"""One-shot live security acceptance probe for UNG-HELIOS.

Validates failed-auth lockout, per-service rate limiting, and anomaly auto-quarantine.
Prints no secret values.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

BASE = os.environ["HELIOS_URL"].rstrip("/")
ADMIN = os.environ["HELIOS_ADMIN_KEY"]
BASE_KEY = os.environ["SENDER_KEY"]


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


def wait_for_health(attempts: int = 12, delay: float = 2.0) -> bool:
    for _ in range(attempts):
        status, body = request("GET", "/health")
        if status == 200 and '"status":"ok"' in body.replace(" ", ""):
            return True
        time.sleep(delay)
    return False


def register(service_id: str, key: str) -> tuple[int, str]:
    status, body = admin("POST", "/admin/register", {
        "service_id": service_id,
        "name": service_id,
        "capabilities": ["security-acceptance"],
        "endpoint": "https://httpbin.org/post",
        "auth_key": key,
    })
    if status == 200:
        reactivate_status, reactivate_body = admin("POST", f"/admin/reactivate/{service_id}")
        if reactivate_status != 200:
            return reactivate_status, reactivate_body
    return status, body


def signed_broadcast(service_id: str, key: str, capability: str = "no-live-targets") -> tuple[int, str]:
    body = {"capability": capability, "message_type": "security_probe", "payload": {"probe": "live"}}
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    ts = str(time.time())
    sig = hmac.new(key.encode("utf-8"), ts.encode("utf-8") + b"." + raw, hashlib.sha256).hexdigest()
    return request("POST", f"/broadcast/{service_id}", raw=raw,
                   headers={"X-Timestamp": ts, "X-Signature": sig})


def bad_signature_broadcast(service_id: str) -> tuple[int, str]:
    body = {"capability": "no-live-targets", "message_type": "bad_auth_probe", "payload": {}}
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return request("POST", f"/broadcast/{service_id}", raw=raw,
                   headers={"X-Timestamp": str(time.time()), "X-Signature": "0" * 64})


def burst_broadcasts(service_id: str, key: str, *, count: int = 40,
                     workers: int = 20) -> list[tuple[int, str]]:
    """Send a bounded concurrent burst to exercise the live anomaly detector."""
    results: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(signed_broadcast, service_id, key) for _ in range(count)]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def main() -> int:
    failures: list[str] = []

    if not wait_for_health():
        print("health_ready: False")
        print("security_acceptance_result: FAIL")
        print("failed_checks: health")
        return 1
    print("health_ready: True")

    run_suffix = str(int(time.time()))

    # 1) Failed-auth lockout.
    lock_id = f"helios-lockout-{run_suffix}"
    lock_key = BASE_KEY + "-lock"
    status, _ = register(lock_id, lock_key)
    print(f"lockout_register: HTTP {status}")
    if status != 200:
        failures.append("lockout_register")
    bad_statuses = []
    for _ in range(5):
        status, _ = bad_signature_broadcast(lock_id)
        bad_statuses.append(status)
    print("lockout_bad_auth_statuses:", bad_statuses)
    status, body = signed_broadcast(lock_id, lock_key)
    print(f"lockout_valid_after_failures: HTTP {status} {body[:300]}")
    if status != 403 or "locked out" not in body:
        failures.append("lockout")
    admin("POST", f"/admin/unlock/{lock_id}")
    admin("POST", f"/admin/deactivate/{lock_id}")

    # 2) Per-service rate limiting: 120 allowed in a 60s window, 121st rejected.
    rate_id = f"helios-rate-{run_suffix}"
    rate_key = BASE_KEY + "-rate"
    status, _ = register(rate_id, rate_key)
    print(f"rate_register: HTTP {status}")
    allowed = 0
    first_non_200 = None
    for i in range(121):
        status, body = signed_broadcast(rate_id, rate_key)
        if status == 200:
            allowed += 1
        elif first_non_200 is None:
            first_non_200 = (i + 1, status, body[:200])
    print(f"rate_allowed_200_count: {allowed}")
    print(f"rate_first_non_200: {first_non_200}")
    if allowed != 120 or not first_non_200 or first_non_200[0] != 121 or first_non_200[1] != 429:
        failures.append("rate_limit")
    admin("POST", f"/admin/deactivate/{rate_id}")

    # 3) Anomaly auto-quarantine. Establish a low baseline for ~60s, then burst concurrently.
    anomaly_id = f"helios-anomaly-{run_suffix}"
    anomaly_key = BASE_KEY + "-anomaly"
    status, _ = register(anomaly_id, anomaly_key)
    print(f"anomaly_register: HTTP {status}")
    baseline_ok = True
    for i in range(5):
        status, body = signed_broadcast(anomaly_id, anomaly_key)
        print(f"anomaly_baseline_{i+1}: HTTP {status}")
        if status != 200:
            failures.append("anomaly_baseline")
            baseline_ok = False
            break
        if i < 4:
            time.sleep(15)

    quarantine_seen = False
    quarantine_result = None
    if baseline_ok:
        burst_results = burst_broadcasts(anomaly_id, anomaly_key, count=40, workers=20)
        for index, (status, body) in enumerate(burst_results, start=1):
            if status == 403 and "auto-quarantined" in body:
                quarantine_seen = True
                quarantine_result = (index, status, body[:300])
                break
        if quarantine_result is None:
            for index, (status, body) in enumerate(burst_results, start=1):
                if status != 200:
                    quarantine_result = (index, status, body[:300])
                    break
    print(f"anomaly_quarantine_result: {quarantine_result}")
    if not quarantine_seen:
        failures.append("anomaly_quarantine")

    status, events_body = admin("GET", "/admin/security-events?limit=100")
    event_found = False
    if status == 200:
        try:
            events = json.loads(events_body)
            event_found = any(e.get("service_id") == anomaly_id and e.get("event_type") == "auto_quarantine" for e in events)
        except Exception:
            pass
    print(f"anomaly_security_event_found: {event_found}")
    if not event_found:
        failures.append("anomaly_event")
    admin("POST", f"/admin/deactivate/{anomaly_id}")

    print("security_acceptance_result:", "PASS" if not failures else "FAIL")
    if failures:
        print("failed_checks:", ",".join(sorted(set(failures))))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
