"""
SQLite persistence for UNG-HELIOS.
Uses SQLite rather than Postgres on purpose: it's one file, needs no
separate database server to install or configure, and every one of
your other standalone systems (tax filing app, secure vault, etc.)
already uses it — so this fits the same operating pattern instead of
adding a new kind of thing to run.
PersistentRegistry has the exact same method names as the in-memory
Registry in core.py (register, deactivate, reactivate, get,
find_by_capability, all_active), so Relay from core.py works with
either one unchanged.
"""
from __future__ import annotations
import json
import sqlite3
import time
from typing import Optional
from core import Service, DeliveryRecord
SCHEMA = """
CREATE TABLE IF NOT EXISTS services (
    service_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    capabilities TEXT NOT NULL,  -- JSON list
    endpoint TEXT NOT NULL,
    auth_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS delivery_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    message_type TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    success INTEGER NOT NULL,
    error TEXT,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_target ON delivery_log(target_id);
CREATE INDEX IF NOT EXISTS idx_log_sender ON delivery_log(sender_id);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT NOT NULL,
    event_type TEXT NOT NULL,   -- auth_failure | lockout_triggered | auto_quarantine
    detail TEXT,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_service ON security_events(service_id);
"""
class PersistentRegistry:
    def __init__(self, db_path: str = "helios.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
    def register(self, service_id: str, name: str, capabilities: list[str],
                 endpoint: str, auth_key: str) -> Service:
        self._conn.execute(
            "INSERT INTO services (service_id, name, capabilities, endpoint, auth_key, active) "
            "VALUES (?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(service_id) DO UPDATE SET "
            "name=excluded.name, capabilities=excluded.capabilities, "
            "endpoint=excluded.endpoint, auth_key=excluded.auth_key",
            (service_id, name, json.dumps(capabilities), endpoint, auth_key),
        )
        self._conn.commit()
        return self.get(service_id)
    def deactivate(self, service_id: str) -> None:
        self._conn.execute(
            "UPDATE services SET active = 0 WHERE service_id = ?", (service_id,)
        )
        self._conn.commit()
    def reactivate(self, service_id: str) -> None:
        self._conn.execute(
            "UPDATE services SET active = 1 WHERE service_id = ?", (service_id,)
        )
        self._conn.commit()
    def get(self, service_id: str) -> Optional[Service]:
        row = self._conn.execute(
            "SELECT service_id, name, capabilities, endpoint, auth_key, active "
            "FROM services WHERE service_id = ?", (service_id,)
        ).fetchone()
        if row is None:
            return None
        return Service(
            service_id=row[0], name=row[1],
            capabilities=json.loads(row[2]), endpoint=row[3],
            auth_key=row[4], active=bool(row[5]),
        )
    def find_by_capability(self, capability: str) -> list[Service]:
        rows = self._conn.execute(
            "SELECT service_id, name, capabilities, endpoint, auth_key, active "
            "FROM services WHERE active = 1"
        ).fetchall()
        out = []
        for row in rows:
            caps = json.loads(row[2])
            if capability in caps:
                out.append(Service(row[0], row[1], caps, row[3], row[4], bool(row[5])))
        return out
    def all_active(self) -> list[Service]:
        rows = self._conn.execute(
            "SELECT service_id, name, capabilities, endpoint, auth_key, active "
            "FROM services WHERE active = 1"
        ).fetchall()
        return [Service(r[0], r[1], json.loads(r[2]), r[3], r[4], bool(r[5])) for r in rows]
    def log_delivery(self, rec: DeliveryRecord) -> None:
        self._conn.execute(
            "INSERT INTO delivery_log (sender_id, target_id, message_type, "
            "attempts, success, error, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rec.sender_id, rec.target_id, rec.message_type, rec.attempts,
             int(rec.success), rec.error, rec.timestamp),
        )
        self._conn.commit()
    def recent_deliveries(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT sender_id, target_id, message_type, attempts, success, error, timestamp "
            "FROM delivery_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {"sender_id": r[0], "target_id": r[1], "message_type": r[2],
             "attempts": r[3], "success": bool(r[4]), "error": r[5], "timestamp": r[6]}
            for r in rows
        ]
    def log_security_event(self, service_id: str, event_type: str,
                             detail: str, timestamp: float) -> None:
        self._conn.execute(
            "INSERT INTO security_events (service_id, event_type, detail, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (service_id, event_type, detail, timestamp),
        )
        self._conn.commit()
    def recent_security_events(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT service_id, event_type, detail, timestamp FROM security_events "
            "ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {"service_id": r[0], "event_type": r[1], "detail": r[2], "timestamp": r[3]}
            for r in rows
        ]
    def close(self):
        self._conn.close()
