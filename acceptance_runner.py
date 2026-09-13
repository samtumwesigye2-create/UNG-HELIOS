"""One-shot live acceptance probe for UNG-HELIOS.

Uses only environment variables and prints no secret values.
Required: HELIOS_URL, HELIOS_ADMIN_KEY, SENDER_KEY, TARGET_KEY.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ["HELIOS_URL"].rstrip("/")
ADMIN = os.environ["HELIOS_ADMIN_KEY"]
SENDER_KEY = os.environ["SENDER_KEY"]
TARGET_KEY = os.environ["TARGET_KEY"]
SENDER_ID = "helios-acceptance-sender"
TARGET_ID = "helios-acceptance-target"
TARGET_ENDPOINT = "https://httpbin.org/post"


def request(method: str, path: str, *, body: dict | None = None,
            raw: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, str]:
    data = raw if raw is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def admin(method: str, path: str, body: dict | None = None) -> tuple[int, str]:
    return request(method, path, body=body, headers={"X-Admin-Key": ADMIN})


def signed(method_path: str, body: dict, *, timestamp: str | None = None) -> tuple[int, str]:
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    ts = timestamp or str(time.time())
    signature = hmac.new(
        SENDER_KEY.encode("utf-8"), ts.encode("utf-8") + b"." + raw, hashlib.sha256
    ).hexdigest()
    return request(
        "POST", method_path, raw=raw,
        headers={"X-Timestamp": ts, "X-Signature": signature},
    )


def emit(label: str, result: tuple[int, str]) -> tuple[int, str]:
    status, body = result
    print(f"{label}: HTTP {status} {body[:1000]}")
    return result


def main() -> int:
    failures: list[str] = []

    status, body = emit("health", request("GET", "/health"))
    if status != 200:
        failures.append("health")

    registrations = [
        (SENDER_ID, "Acceptance Sender", ["acceptance"], SENDER_KEY),
        (TARGET_ID, "Acceptance Target", ["acceptance-target"], TARGET_KEY),
    ]
    for service_id, name, capabilities, key in registrations:
        status, body = emit(
            f"register:{service_id}",
            admin("POST", "/admin/register", {
                "service_id": service_id,
                "name": name,
                "capabilities": capabilities,
                "endpoint": TARGET_ENDPOINT,
                "auth_key": key,
            }),
        )
        if status != 200:
            failures.append(f"register:{service_id}")
        status, body = emit(
            f"reactivate:{service_id}",
            admin("POST", f"/admin/reactivate/{service_id}"),
        )
        if status != 200:
            failures.append(f"reactivate:{service_id}")

    ping = {
        "target_id": TARGET_ID,
        "message_type": "acceptance_ping",
        "payload": {"probe": "live"},
    }
    status, body = emit("signed_send", signed(f"/send/{SENDER_ID}", ping))
    if status != 200:
        failures.append("signed_send")

    status, deliveries_body = emit("deliveries", admin("GET", "/admin/deliveries?limit=10"))
    delivery_found = False
    if status == 200:
        try:
            deliveries = json.loads(deliveries_body)
            delivery_found = any(
                item.get("message_type") == "acceptance_ping" and item.get("success") is True
                for item in deliveries
            )
        except Exception:
            delivery_found = False
    print(f"delivery_log_match: {delivery_found}")
    if not delivery_found:
        failures.append("delivery_log")

    stale_ts = str(time.time() - 400)
    status, body = emit("stale_request", signed(f"/send/{SENDER_ID}", ping, timestamp=stale_ts))
    if status != 401:
        failures.append("stale_request")

    broadcast = {
        "capability": "acceptance-target",
        "message_type": "acceptance_broadcast",
        "payload": {"probe": "broadcast"},
    }
    status, body = emit("broadcast", signed(f"/broadcast/{SENDER_ID}", broadcast))
    if status != 200:
        failures.append("broadcast")

    for service_id in (SENDER_ID, TARGET_ID):
        status, body = emit(
            f"deactivate:{service_id}",
            admin("POST", f"/admin/deactivate/{service_id}"),
        )
        if status != 200:
            failures.append(f"deactivate:{service_id}")

    print("acceptance_result:", "PASS" if not failures else "FAIL")
    if failures:
        print("failed_checks:", ",".join(failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
