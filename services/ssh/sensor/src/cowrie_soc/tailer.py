"""Follow Cowrie's JSON log across restarts, rotation and truncation.

Cowrie (logtype = rotating) writes `cowrie.json` and at midnight renames it to
`cowrie.json.YYYY-MM-DD`, then starts a new `cowrie.json`. A file is identified
by a fingerprint of its first line rather than its name or inode, so after a
rename the follower still finds the file it was reading, drains whatever was
appended before rotation, and only then moves on to the new file.

Only complete (newline-terminated) lines are returned; a partially written
line stays unread until its newline arrives. The follower does not persist
anything itself: `poll()` returns lines plus the checkpoint *after* them, and
the caller stores that checkpoint atomically with the processed records.

Files are opened per poll and closed again, so rotation by rename also works
on Windows during local development.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

from cowrie_soc.parser import RawLine
from cowrie_soc.store import Checkpoint

log = logging.getLogger(__name__)

FINGERPRINT_MAX_BYTES = 4096
READ_CHUNK = 1 << 20


@dataclass
class PollResult:
    lines: list[RawLine]
    checkpoint: Checkpoint | None
    notices: list[str] = field(default_factory=list)


def fingerprint(path: Path) -> str | None:
    """SHA-256 of the file's first line; None until a first full line exists."""
    try:
        with path.open("rb") as fh:
            head = fh.read(FINGERPRINT_MAX_BYTES)
    except FileNotFoundError:
        return None
    nl = head.find(b"\n")
    if nl == -1:
        if len(head) < FINGERPRINT_MAX_BYTES:
            return None
        nl = len(head)
    return hashlib.sha256(head[:nl]).hexdigest()


class LogFollower:
    def __init__(
        self,
        directory: str | Path,
        base_name: str = "cowrie.json",
        start_at_end: bool = False,
        max_line_bytes: int = 1 << 20,
    ) -> None:
        self.directory = Path(directory)
        self.base_name = base_name
        self.start_at_end = start_at_end
        self.max_line_bytes = max_line_bytes

    @property
    def base_path(self) -> Path:
        return self.directory / self.base_name

    def poll(self, checkpoint: Checkpoint | None, max_lines: int = 500) -> PollResult:
        notices: list[str] = []
        if checkpoint is None:
            fp = fingerprint(self.base_path)
            if fp is None:
                return PollResult([], None)
            offset = self._end_offset(self.base_path) if self.start_at_end else 0
            checkpoint = Checkpoint(fp, self.base_name, offset)
            notices.append(f"no checkpoint: starting {self.base_name} at offset {offset}")

        path = self._locate(checkpoint.fingerprint)
        if path is None:
            fp = fingerprint(self.base_path)
            if fp is None:
                return PollResult([], checkpoint, notices)
            notices.append(
                f"POSSIBLE DATA LOSS: file with fingerprint {checkpoint.fingerprint[:12]} "
                f"(last seen as {checkpoint.file} @ {checkpoint.offset}) no longer exists; "
                f"continuing from the start of {self.base_name}"
            )
            checkpoint = Checkpoint(fp, self.base_name, 0)
            path = self.base_path

        size = path.stat().st_size
        if size < checkpoint.offset:
            notices.append(
                f"POSSIBLE DATA LOSS: {path.name} shrank from {checkpoint.offset} to {size} bytes "
                "(truncated); re-reading from offset 0"
            )
            checkpoint = Checkpoint(checkpoint.fingerprint, path.name, 0)

        is_rotated = path.name != self.base_name
        lines, new_offset = self._read_lines(path, checkpoint.offset, max_lines, final=False)
        if lines:
            return PollResult(lines, Checkpoint(checkpoint.fingerprint, path.name, new_offset), notices)

        if is_rotated:
            # The rotated file will not grow again. Flush an unterminated tail, then move on.
            tail, tail_end = self._read_lines(path, checkpoint.offset, 1, final=True)
            if tail:
                return PollResult(tail, Checkpoint(checkpoint.fingerprint, path.name, tail_end), notices)
            fp = fingerprint(self.base_path)
            if fp is not None and fp != checkpoint.fingerprint:
                notices.append(f"finished rotated file {path.name}; switching to new {self.base_name}")
                return PollResult([], Checkpoint(fp, self.base_name, 0), notices)
        return PollResult([], Checkpoint(checkpoint.fingerprint, path.name, checkpoint.offset), notices)

    def _locate(self, fp: str) -> Path | None:
        """Find the file whose first line matches fp: the live file first, then rotated ones."""
        if fingerprint(self.base_path) == fp:
            return self.base_path
        for candidate in sorted(self.directory.glob(self.base_name + ".*")):
            if candidate.is_file() and fingerprint(candidate) == fp:
                return candidate
        return None

    def _end_offset(self, path: Path) -> int:
        """Offset just past the last complete line (used for start_position = end)."""
        size = path.stat().st_size
        with path.open("rb") as fh:
            pos = size
            while pos > 0:
                step = min(READ_CHUNK, pos)
                fh.seek(pos - step)
                chunk = fh.read(step)
                nl = chunk.rfind(b"\n")
                if nl != -1:
                    return pos - step + nl + 1
                pos -= step
        return 0

    def _read_lines(self, path: Path, offset: int, max_lines: int, final: bool) -> tuple[list[RawLine], int]:
        lines: list[RawLine] = []
        with path.open("rb") as fh:
            fh.seek(offset)
            buf = b""
            buf_start = offset
            while len(lines) < max_lines:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                buf += chunk
                while len(lines) < max_lines:
                    nl = buf.find(b"\n")
                    if nl == -1:
                        break
                    line = buf[:nl]
                    lines.append(RawLine(line, path.name, buf_start, oversized=len(line) > self.max_line_bytes))
                    buf = buf[nl + 1 :]
                    buf_start += nl + 1
                if len(buf) > self.max_line_bytes:
                    # Keep reading to find the end of this oversized line, but do not hold it in memory.
                    skipped_start, skipped = buf_start, len(buf)
                    head = buf[:512]
                    while True:
                        chunk = fh.read(READ_CHUNK)
                        if not chunk:
                            if final:
                                # A rotated file will not grow: report the oversized tail, don't skip it.
                                lines.append(RawLine(head, path.name, skipped_start, oversized=True, unterminated=True))
                                return lines, skipped_start + skipped
                            # Unterminated oversized line: leave it unread until it completes.
                            return lines, buf_start
                        nl = chunk.find(b"\n")
                        if nl != -1:
                            skipped += nl
                            lines.append(RawLine(head, path.name, skipped_start, oversized=True))
                            buf = chunk[nl + 1 :]
                            buf_start = skipped_start + skipped + 1
                            break
                        skipped += len(chunk)
            if final and buf and len(lines) < max_lines:
                lines.append(RawLine(buf, path.name, buf_start, unterminated=True))
                buf_start += len(buf)
        return lines, buf_start
