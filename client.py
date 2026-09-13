"""
UNG-HELIOS client — drop this file into each system that needs to
talk through the hub.
Requires security.py to be deployed alongside this file — it's what
signs each request. Your service_key never travels over the network
at all now; only a signature derived from it does (see security.py).
Durability fix: if HELIOS itself can't be reached at all when you try
to send, the message is saved to a local SQLite file (the "outbox")
instead of being lost. Call flush_outbox() later (on a timer, on
startup, whenever) to retry everything that's queued.
This only queues on UNREACHABLE (network/DNS/timeout — HELIOS is
down or you can't reach it). A message HELIOS actively REJECTS (bad
auth, bad request — a real 4xx) is not queued for retry, because
retrying an invalid message forever doesn't fix it; those go to a
small "failed" list you can inspect with failed_messages().
Usage:
    from client import HeliosClient
    helios = HeliosClient(
        helios_url="https://your-helios.up.railway.app",
        service_id="mercury",
        service_key="the-key-you-registered-mercury-with",
        outbox_path="mercury_outbox.db",
    )
    helios.send("ugatu", "shipment_update", {"shipment_id": 42})
    helios.flush_outbox()
"""
import json
import time
import sqlite3
import urllib.request
import urllib.error
import security
class HeliosError(Exception):
    pass
class HeliosUnreachable(HeliosError):
    """HELIOS itself could not be contacted — network/DNS/timeout."""
class HeliosRejected(HeliosError):
    """HELIOS was reached but rejected the message (bad auth/request)."""
OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""
class HeliosClient:
    def __init__(self, helios_url: str, service_id: str, service_key: str,
                 outbox_path: str = "helios_outbox.db", transport_fn=None):
        self.base = helios_url.rstrip("/")
        self.service_id = service_id
        self.service_key = service_key
        self._conn = sqlite3.connect(outbox_path)
        self._conn.executescript(OUTBOX_SCHEMA)
        self._conn.commit()
        self._transport = transport_fn or self._http_transport
    def _http_transport(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        timestamp = str(time.time())
        signature = security.sign(self.service_key, timestamp, data)
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "X-Timestamp": timestamp,
                     "X-Signature": signature},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise HeliosRejected(f"HTTP {e.code} — {e.read().decode(errors='replace')}")
        except urllib.error.URLError as e:
            raise HeliosUnreachable(str(e.reason))
    def send(self, target_id: str, message_type: str, payload: dict) -> dict:
        return self._send_or_queue(f"/send/{self.service_id}", {
            "target_id": target_id,
            "message_type": message_type,
            "payload": payload,
        })
    def broadcast(self, capability: str, message_type: str, payload: dict) -> dict:
        return self._send_or_queue(f"/broadcast/{self.service_id}", {
            "capability": capability,
            "message_type": message_type,
            "payload": payload,
        })
    def _send_or_queue(self, path: str, body: dict) -> dict:
        try:
            result = self._transport(path, body)
            result["status_detail"] = "delivered_immediately"
            return result
        except HeliosUnreachable as e:
            self._enqueue(path, body, str(e))
            return {"status": "queued", "reason": str(e)}
    def _enqueue(self, path: str, body: dict, error: str) -> None:
        now = time.time()
        self._conn.execute(
            "INSERT INTO outbox (path, body, status, attempts, last_error, created_at, updated_at) "
            "VALUES (?, ?, 'pending', 0, ?, ?, ?)",
            (path, json.dumps(body), error, now, now),
        )
        self._conn.commit()
    def pending_count(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM outbox WHERE status = 'pending'"
        ).fetchone()[0]
    def failed_messages(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, path, body, attempts, last_error, created_at "
            "FROM outbox WHERE status = 'failed'"
        ).fetchall()
        return [
            {"id": r[0], "path": r[1], "body": json.loads(r[2]),
             "attempts": r[3], "last_error": r[4], "created_at": r[5]}
            for r in rows
        ]
    def flush_outbox(self) -> dict:
        rows = self._conn.execute(
            "SELECT id, path, body, attempts FROM outbox "
            "WHERE status = 'pending' ORDER BY id ASC"
        ).fetchall()
        delivered, failed, still_pending = 0, 0, 0
        still_down = False
        for row_id, path, body_json, attempts in rows:
            if still_down:
                still_pending += 1
                continue
            body = json.loads(body_json)
            try:
                self._transport(path, body)
                self._conn.execute("DELETE FROM outbox WHERE id = ?", (row_id,))
                self._conn.commit()
                delivered += 1
            except HeliosUnreachable as e:
                self._conn.execute(
                    "UPDATE outbox SET attempts = ?, last_error = ?, updated_at = ? WHERE id = ?",
                    (attempts + 1, str(e), time.time(), row_id),
                )
                self._conn.commit()
                still_down = True
                still_pending += 1
            except HeliosRejected as e:
                self._conn.execute(
                    "UPDATE outbox SET status = 'failed', attempts = ?, last_error = ?, "
                    "updated_at = ? WHERE id = ?",
                    (attempts + 1, str(e), time.time(), row_id),
                )
                self._conn.commit()
                failed += 1
        return {"delivered": delivered, "failed": failed, "still_pending": still_pending}
    def close(self):
        self._conn.close()
