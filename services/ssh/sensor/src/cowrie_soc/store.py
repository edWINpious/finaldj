"""Durable collector state in one SQLite database.

Tables:
  checkpoint   - read position in the Cowrie log (file fingerprint + byte offset)
  outbox       - normalized events and findings awaiting delivery, in order
  sink_cursor  - last outbox seq each sink has delivered
  dead_letter  - records a sink permanently rejected (kept, never silently dropped)
  quarantine   - raw lines that failed parsing/validation, with location

Records and the new checkpoint are committed in ONE transaction, so a crash
can never advance the read position without the records being stored (or
store records twice for the same position). Delivery to sinks is
at-least-once; record ids are deterministic so receivers can de-duplicate.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cowrie_soc.parser import ParseError
from cowrie_soc.schema import record_id

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoint (
    stream TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    file TEXT NOT NULL,
    offset INTEGER NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE,
    record_type TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sink_cursor (
    sink TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS dead_letter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sink TEXT NOT NULL,
    seq INTEGER NOT NULL,
    record_id TEXT NOT NULL,
    body TEXT NOT NULL,
    error TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file TEXT NOT NULL,
    offset INTEGER NOT NULL,
    reason TEXT NOT NULL,
    excerpt TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


@dataclass(frozen=True)
class Checkpoint:
    fingerprint: str
    file: str
    offset: int


@dataclass(frozen=True)
class CommitResult:
    inserted: int
    duplicates: int


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(_SCHEMA)
        # Sinks configured in THIS process. Cursors of sinks from earlier runs stay in the
        # database (so a re-enabled sink resumes) but must not hold back pending/pruning.
        self.active_sinks: set[str] = set()

    def close(self) -> None:
        self.db.close()

    # -- checkpoint -------------------------------------------------------
    def load_checkpoint(self, stream: str) -> Checkpoint | None:
        row = self.db.execute(
            "SELECT fingerprint, file, offset FROM checkpoint WHERE stream = ?", (stream,)
        ).fetchone()
        return Checkpoint(*row) if row else None

    def commit(
        self,
        stream: str,
        checkpoint: Checkpoint | None,
        records: Iterable[dict[str, Any]],
        quarantined: Iterable[ParseError] = (),
    ) -> CommitResult:
        """Atomically store records + quarantined lines and advance the checkpoint."""
        now = time.time()
        inserted = duplicates = 0
        with self._tx():
            for rec in records:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO outbox (record_id, record_type, body, created_at) VALUES (?, ?, ?, ?)",
                    (record_id(rec), rec["record_type"], json.dumps(rec, separators=(",", ":"), ensure_ascii=False), now),
                )
                if cur.rowcount:
                    inserted += 1
                else:
                    duplicates += 1
            for err in quarantined:
                self.db.execute(
                    "INSERT INTO quarantine (file, offset, reason, excerpt, raw_sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (err.source, err.offset, err.reason, err.excerpt, err.raw_sha256, now),
                )
            if checkpoint is not None:
                self.db.execute(
                    "INSERT INTO checkpoint (stream, fingerprint, file, offset, updated_at) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(stream) DO UPDATE SET fingerprint=excluded.fingerprint, file=excluded.file, "
                    "offset=excluded.offset, updated_at=excluded.updated_at",
                    (stream, checkpoint.fingerprint, checkpoint.file, checkpoint.offset, now),
                )
        return CommitResult(inserted, duplicates)

    # -- delivery ---------------------------------------------------------
    def register_sink(self, sink: str) -> None:
        self.active_sinks.add(sink)
        self.db.execute(
            "INSERT OR IGNORE INTO sink_cursor (sink, last_seq, updated_at) VALUES (?, 0, ?)", (sink, time.time())
        )

    def fetch_pending(self, sink: str, limit: int) -> list[tuple[int, dict[str, Any]]]:
        rows = self.db.execute(
            "SELECT seq, body FROM outbox WHERE seq > (SELECT last_seq FROM sink_cursor WHERE sink = ?) "
            "ORDER BY seq LIMIT ?",
            (sink, limit),
        ).fetchall()
        return [(seq, json.loads(body)) for seq, body in rows]

    def mark_delivered(self, sink: str, upto_seq: int, count: int) -> None:
        self.db.execute(
            "UPDATE sink_cursor SET last_seq = ?, delivered = delivered + ?, last_error = NULL, updated_at = ? "
            "WHERE sink = ?",
            (upto_seq, count, time.time(), sink),
        )

    def record_error(self, sink: str, error: str) -> None:
        self.db.execute(
            "UPDATE sink_cursor SET last_error = ?, updated_at = ? WHERE sink = ?", (error[:1000], time.time(), sink)
        )

    def dead_letter(self, sink: str, batch: list[tuple[int, dict[str, Any]]], error: str) -> None:
        now = time.time()
        with self._tx():
            for seq, rec in batch:
                self.db.execute(
                    "INSERT INTO dead_letter (sink, seq, record_id, body, error, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (sink, seq, record_id(rec), json.dumps(rec, separators=(",", ":")), error[:1000], now),
                )
            self.db.execute(
                "UPDATE sink_cursor SET last_seq = ?, last_error = ?, updated_at = ? WHERE sink = ?",
                (batch[-1][0], error[:1000], now, sink),
            )

    def _active_floor(self) -> int | None:
        """Lowest delivered seq across the sinks active in this process (None if no sinks)."""
        if not self.active_sinks:
            return None
        marks = ",".join("?" * len(self.active_sinks))
        row = self.db.execute(
            f"SELECT MIN(last_seq) FROM sink_cursor WHERE sink IN ({marks})", tuple(self.active_sinks)
        ).fetchone()
        return row[0] if row and row[0] is not None else 0

    def pending_count(self, sink: str | None = None) -> int:
        """Undelivered records for one sink, or the maximum over the active sinks."""
        if sink is not None:
            sql = "SELECT COUNT(*) FROM outbox WHERE seq > (SELECT last_seq FROM sink_cursor WHERE sink = ?)"
            return int(self.db.execute(sql, (sink,)).fetchone()[0])
        floor = self._active_floor()
        if floor is None:
            return 0
        return int(self.db.execute("SELECT COUNT(*) FROM outbox WHERE seq > ?", (floor,)).fetchone()[0])

    def prune_delivered(self, retain: int) -> int:
        """Delete records every active sink has delivered, keeping the newest `retain`."""
        floor = self._active_floor()
        if floor is None:
            return 0
        cutoff = min(floor, self._max_seq() - retain)
        if cutoff <= 0:
            return 0
        return self.db.execute("DELETE FROM outbox WHERE seq <= ?", (cutoff,)).rowcount

    def _max_seq(self) -> int:
        return int(self.db.execute("SELECT COALESCE(MAX(seq), 0) FROM outbox").fetchone()[0])

    # -- inspection -------------------------------------------------------
    def status(self) -> dict[str, Any]:
        q = self.db.execute
        return {
            "checkpoints": [
                {"stream": s, "fingerprint": fp[:16], "file": f, "offset": o}
                for s, fp, f, o in q("SELECT stream, fingerprint, file, offset FROM checkpoint")
            ],
            "outbox_rows": q("SELECT COUNT(*) FROM outbox").fetchone()[0],
            "outbox_by_type": dict(q("SELECT record_type, COUNT(*) FROM outbox GROUP BY record_type").fetchall()),
            "sinks": [
                {"sink": s, "last_seq": ls, "delivered": d, "pending": self.pending_count(s), "last_error": e}
                for s, ls, d, e in q("SELECT sink, last_seq, delivered, last_error FROM sink_cursor").fetchall()
            ],
            "quarantined": q("SELECT COUNT(*) FROM quarantine").fetchone()[0],
            "dead_letters": q("SELECT COUNT(*) FROM dead_letter").fetchone()[0],
        }

    def quarantine_rows(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.db.execute(
            "SELECT file, offset, reason, excerpt FROM quarantine ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"file": f, "offset": o, "reason": r, "excerpt": e} for f, o, r, e in rows]

    def _tx(self) -> _Transaction:
        return _Transaction(self.db)


class _Transaction:
    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db

    def __enter__(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.db.execute("ROLLBACK" if exc_type else "COMMIT")
