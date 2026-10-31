"""SQLite persistence. Documents are stored as JSON, with a few indexed columns for filtering."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class Store:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, ts TEXT NOT NULL, service TEXT NOT NULL,
                source_ip TEXT NOT NULL, session_id TEXT, doc TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip);
            CREATE TABLE IF NOT EXISTS alerts (
                dedupe_key TEXT PRIMARY KEY, alert_id TEXT NOT NULL, last_seen TEXT NOT NULL, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS adaptations (
                adaptation_id TEXT PRIMARY KEY, ts TEXT NOT NULL, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sensors (
                sensor_id TEXT PRIMARY KEY, last_seen TEXT NOT NULL, doc TEXT NOT NULL);
        """)

    def insert_event(self, event: dict[str, Any]) -> bool:
        """False when event_id was already stored: resends are expected (INTEGRATOR_NOTES §1)."""
        with self.lock, self.db:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
                (event["event_id"], event["timestamp"], event["service"], event["source_ip"], event["session_id"],
                 json.dumps(event)))
        return cur.rowcount == 1

    def events(self, limit: int, offset: int = 0, service: str | None = None, source_ip: str | None = None,
               session_id: str | None = None) -> list[dict[str, Any]]:
        where, args = [], []
        for col, val in (("service", service), ("source_ip", source_ip), ("session_id", session_id)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self.lock:
            rows = self.db.execute(f"SELECT doc FROM events {clause} ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?",
                                   (*args, limit, offset)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count_events(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def services_for_source(self, source_ip: str, since: str) -> set[str]:
        with self.lock:
            rows = self.db.execute("SELECT DISTINCT service FROM events WHERE source_ip = ? AND ts >= ?",
                                   (source_ip, since)).fetchall()
        return {r[0] for r in rows}

    def get_alert(self, key: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.db.execute("SELECT doc FROM alerts WHERE dedupe_key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_alert(self, key: str, alert: dict[str, Any]) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?)",
                            (key, alert["alert_id"], alert["last_seen"], json.dumps(alert)))

    def alerts(self, limit: int) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT doc FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def put_adaptation(self, record: dict[str, Any]) -> bool:
        with self.lock, self.db:
            cur = self.db.execute("INSERT OR IGNORE INTO adaptations VALUES (?, ?, ?)",
                                  (record["adaptation_id"], record["timestamp"], json.dumps(record)))
        return cur.rowcount == 1

    def adaptations(self, limit: int) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT doc FROM adaptations ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def put_sensor(self, sensor_id: str, last_seen: str, doc: dict[str, Any]) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO sensors VALUES (?, ?, ?)", (sensor_id, last_seen, json.dumps(doc)))

    def sensors(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.db.execute("SELECT doc FROM sensors ORDER BY sensor_id").fetchall()
        return [json.loads(r[0]) for r in rows]
