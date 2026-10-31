"""Build step: stop Cowrie recording tried passwords. Project rule: they reach no log.

Cowrie has no setting for this: core/checkers.py puts the password in the login events that
every output writes. This removes it from those two events only; the password check itself
is untouched. A build fails here if the pinned Cowrie's code is not what this expects.

Usage: strip_password_logging.py <checkers.py> <output path>
"""

from __future__ import annotations

import sys
from pathlib import Path

REPLACEMENTS = {
    '"login attempt [%(username)s/%(password)s] succeeded"': '"login attempt [%(username)s] succeeded"',
    '"login attempt [%(username)s/%(password)s] failed"': '"login attempt [%(username)s] failed"',
}
PASSWORD_LINE = "password=escape_nonprintable(thepassword),"
PASSWORD_LINES = 2


def main() -> int:
    source, output = Path(sys.argv[1]), Path(sys.argv[2])
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [line for line in lines if line.strip() != PASSWORD_LINE]
    if len(lines) - len(kept) != PASSWORD_LINES:
        sys.exit(f"expected {PASSWORD_LINES} password log lines, found {len(lines) - len(kept)}")
    text = "".join(kept)
    for old, new in REPLACEMENTS.items():
        if text.count(old) != 1:
            sys.exit(f"expected exactly one {old}")
        text = text.replace(old, new)
    if "%(password)s" in text:
        sys.exit("a password format string remains")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
