"""Classify one SQL statement.

Uses sqlglot's tokenizer and parser, so string literals and comments cannot fool it the way
they fool a regex: `SELECT 'DROP TABLE x'` is a SELECT. When the parser gives up (SHOW,
DESCRIBE and hostile input often land here), a keyword walk over the tokens still finds the
statement type and table references. The original SQL is always kept by the caller.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, SqlglotError, TokenError

logging.getLogger("sqlglot").setLevel(logging.ERROR)  # hostile SQL would otherwise flood the log

DENIED_CODES = {1044, 1045, 1142, 1143, 1227, 1370}
READ_VERBS = {"SELECT", "WITH", "VALUES", "TABLE"}
ENUM_VERBS = {"SHOW", "DESCRIBE", "DESC", "EXPLAIN", "HELP"}
SESSION_VERBS = {"USE", "SET", "BEGIN", "COMMIT", "ROLLBACK", "START", "KILL", "PING"}
DML_VERBS = {"INSERT", "UPDATE", "DELETE", "REPLACE", "TRUNCATE", "MERGE", "CALL", "DO"}
DDL_VERBS = {"CREATE", "DROP", "ALTER", "RENAME"}
PRIV_VERBS = {"GRANT", "REVOKE", "FLUSH", "INSTALL", "UNINSTALL"}
TABLE_LEAD_INS = {"FROM", "JOIN", "INTO", "UPDATE", "TABLE", "DESCRIBE", "DESC", "EXPLAIN", "COLUMNS", "FIELDS"}
FILE_PATTERN = re.compile(r"\b(load_file\s*\(|into\s+(out|dump)file\b|load\s+(data|xml)\b)", re.I)
CLIENT_NOISE = re.compile(
    r"^\s*(select\s+@@version_comment\s+limit\s+1|select\s+database\(\)|select\s+\$\$|"
    r"set\s+(names|autocommit|character_set_results|sql_mode)\b.*|show\s+warnings|select\s+@@[\w.]+)\s*;?\s*$",
    re.I | re.S,
)
FINGERPRINT = re.compile(r"\b(version|user|current_user|session_user|system_user)\s*\(", re.I)
EXEC_COMMENT = re.compile(r"/\*[!M]")
_WORD = re.compile(r"[A-Za-z_]+")


@dataclass
class Classification:
    query_type: str
    category: str
    tables: list[str] = field(default_factory=list)
    has_join: bool = False
    has_star: bool = False
    unbounded: bool = False
    parsed: bool = False
    tags: list[str] = field(default_factory=list)


def _tokens(sql: str) -> list[Any]:
    try:
        return sqlglot.Dialect.get_or_raise("mysql").tokenize(sql)
    except (TokenError, SqlglotError):
        return []


def _first_keyword(sql: str, tokens: list[Any]) -> str:
    if tokens:
        return tokens[0].text.upper()
    m = _WORD.search(sql)
    return m.group(0).upper() if m else ""


def _name(db: str | None, table: str, default_db: str) -> str:
    table, db = table.lower(), (db or "").lower()
    if not db or db == default_db:
        return table
    return f"{db}.{table}"


def _tables_from_tokens(tokens: list[Any], default_db: str) -> list[str]:
    found: list[str] = []
    i = 0
    while i < len(tokens):
        if tokens[i].text.upper() in TABLE_LEAD_INS and i + 1 < len(tokens):
            j = i + 1
            if tokens[j].text.upper() in ("IF", "EXISTS", "NOT"):  # DROP TABLE IF EXISTS x
                while j < len(tokens) and tokens[j].text.upper() in ("IF", "EXISTS", "NOT"):
                    j += 1
            if j < len(tokens):
                name = tokens[j].text
                db = None
                if j + 2 < len(tokens) and tokens[j + 1].text == ".":
                    db, name = name, tokens[j + 2].text
                if name and name not in ("(", "*", ",") and re.fullmatch(r"[\w$]+", name):
                    found.append(_name(db, name, default_db))
        i += 1
    return list(dict.fromkeys(found))


def classify(sql: str, retcode: int, default_db: str, rules: dict[str, Any]) -> Classification:
    default_db = (default_db or rules["database"]).lower()
    if not sql.strip():
        return Classification("UNKNOWN", "unknown")
    if CLIENT_NOISE.match(sql):
        return Classification("SELECT" if sql.lstrip()[:6].upper() == "SELECT" else "SET", "client_noise", parsed=True)

    tokens = _tokens(sql)
    verb = _first_keyword(sql, tokens)
    c = Classification(query_type=verb or "UNKNOWN", category="unknown")
    if EXEC_COMMENT.search(sql):
        c.tags.append("sql:executable_comment")

    tree = None
    try:
        tree = sqlglot.parse_one(sql, dialect="mysql")
    except (ParseError, TokenError, SqlglotError, RecursionError):
        tree = None
    if tree is not None and not isinstance(tree, exp.Command):
        c.parsed = True
        cte_names = {cte.alias.lower() for cte in tree.find_all(exp.CTE)}
        tables = [_name(t.db, t.name, default_db) for t in tree.find_all(exp.Table)
                  if t.name and t.name.lower() not in cte_names]
        c.tables = list(dict.fromkeys(tables))
        c.has_join = tree.find(exp.Join) is not None
        c.has_star = tree.find(exp.Star) is not None
        if isinstance(tree, exp.Select):
            c.unbounded = tree.args.get("limit") is None and tree.args.get("where") is None and bool(c.tables)
    if not c.tables and verb not in READ_VERBS:
        c.tables = _tables_from_tokens(tokens, default_db)

    if c.has_join:
        c.tags.append("sql:join")
    if c.has_star:
        c.tags.append("sql:select_star")
    if c.unbounded:
        c.tags.append("sql:unbounded_select")
    if retcode == 1064:
        c.tags.append("sql:syntax_error")

    c.category = _category(sql, verb, c, retcode, rules)
    return c


def _category(sql: str, verb: str, c: Classification, retcode: int, rules: dict[str, Any]) -> str:
    denied = retcode in DENIED_CODES
    sensitive = set(rules["sensitive_tables"])
    adaptive = set(rules["adaptive_tables"])
    system = tuple(s + "." for s in rules["system_schemas"])
    tables = set(c.tables)

    if FILE_PATTERN.search(sql):
        return "file_access_attempt"
    if verb in PRIV_VERBS or (verb == "SET" and re.search(r"\bpassword\b", sql, re.I)) \
            or (verb in ("CREATE", "DROP", "ALTER", "RENAME") and re.match(r"\s*\w+\s+(user|role)\b", sql, re.I)):
        return "privilege_attempt"
    if verb in DDL_VERBS:
        return "schema_change_attempt"
    if verb in DML_VERBS:
        return "modification_attempt"
    if verb in SESSION_VERBS:
        return "session_control"
    if verb in READ_VERBS or verb in ENUM_VERBS:
        if denied:
            return "restricted_access"
        if tables & adaptive:
            return "adaptive_decoy_access"
        if tables & sensitive:
            return "sensitive_access"
        if verb in ENUM_VERBS or any(t.startswith(system) for t in tables):
            return "reconnaissance"
        if not tables:
            return "reconnaissance" if FINGERPRINT.search(sql) else "client_noise"
        return "data_exploration"
    return "unknown"


def outcome_for(retcode: int) -> str:
    if retcode == 0:
        return "succeeded"
    return "blocked" if retcode in DENIED_CODES else "failed"


# A literal may be plain SQL ('x') or audit-escaped (\'x\') when applied to a raw log line.
_LITERAL = r"(?:\\'.*?\\'|'(?:[^'\\]|\\.)*')"
_SECRET_PATTERNS = [
    (re.compile(rf"(identified\s+(?:by|via\s+\w+\s+using)\s+(?:password\s+)?){_LITERAL}", re.I), r"\1'[REDACTED]'"),
    (re.compile(rf"(password\s*\(\s*){_LITERAL}", re.I), r"\1'[REDACTED]'"),
    (re.compile(rf"(set\s+password\b[^=]*=\s*){_LITERAL}", re.I), r"\1'[REDACTED]'"),
]


def redact(sql: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        sql = pattern.sub(repl, sql)
    return sql
