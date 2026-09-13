"""
UNG-HELIOS HTTP API — FastAPI layer.
IMPORTANT — same caveat as before: this file could not be run in this
environment (no internet access here to install fastapi/uvicorn).
Every piece of actual logic — signing, rate limiting, lockout timing,
anomaly detection — lives in security.py and core.py, both fully
tested. This file's job is just to: read the request, call the
tested logic, and turn the result into an HTTP response. Run the
checks in test_manually.md once this is deployed, before pointing
real systems at it.
Security model, in order, for every /send and /broadcast request:
 1. Is this service currently locked out (too many recent auth
    failures)? If so, reject immediately, no further checks.
 2. Is the signature valid and the timestamp fresh (not a replay of
    an old captured request)? If not, record a failure — enough
    failures in a row triggers a lockout automatically.
 3. Is this service under its rate limit? If not, reject (temporary —
    doesn't lock them out, just says "slow down").
 4. Does this burst of activity look anomalous compared to this
    service's own normal history? If so, auto-quarantine it (the same
    "deactivated" state as a manual admin deactivation) and fire an
    alert — a compromised service can't be used to attack the other
    24 through the hub.
None of this reaches out toward whatever might be attacking HELIOS —
it only ever controls access TO helios and visibility INTO what's
happening. See security.py's module docstring.
"""
import os
import time
import json as jsonlib
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from core import Registry, Relay, DeliveryError, TargetUnreachable, TargetErrored
from storage import PersistentRegistry
import security
ADMIN_KEY = os.environ.get("HELIOS_ADMIN_KEY", "change-me-before-deploying")
DB_PATH = os.environ.get("HELIOS_DB_PATH", "helios.db")
ALERT_WEBHOOK_URL = os.environ.get("HELIOS_ALERT_WEBHOOK_URL", "")
MAX_CLOCK_SKEW_SECONDS = float(os.environ.get("HELIOS_MAX_CLOCK_SKEW", "300"))
RATE_LIMIT_MAX = int(os.environ.get("HELIOS_RATE_LIMIT_MAX", "120"))
RATE_LIMIT_WINDOW = float(os.environ.get("HELIOS_RATE_LIMIT_WINDOW", "60"))
LOCKOUT_MAX_FAILURES = int(os.environ.get("HELIOS_LOCKOUT_MAX_FAILURES", "5"))
LOCKOUT_WINDOW = float(os.environ.get("HELIOS_LOCKOUT_WINDOW", "300"))
LOCKOUT_SECONDS = float(os.environ.get("HELIOS_LOCKOUT_SECONDS", "900"))
ANOMALY_SPIKE_MULTIPLIER = float(os.environ.get("HELIOS_ANOMALY_MULTIPLIER", "5"))
app = FastAPI(title="UNG-HELIOS")
registry = PersistentRegistry(DB_PATH)
rate_limiter = security.RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW)
lockout = security.LockoutTracker(LOCKOUT_MAX_FAILURES, LOCKOUT_WINDOW, LOCKOUT_SECONDS)
anomaly = security.AnomalyDetector(spike_multiplier=ANOMALY_SPIKE_MULTIPLIER)
def http_sender(endpoint: str, auth_key: str, payload: dict) -> None:
    body = jsonlib.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {auth_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status >= 400:
                raise TargetErrored(f"HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        raise TargetErrored(f"HTTP {e.code}")
    except urllib.error.URLError as e:
        raise TargetUnreachable(str(e.reason))
relay = Relay(registry, http_sender)
def send_alert(event: dict) -> None:
    if not ALERT_WEBHOOK_URL:
        return
    try:
        body = jsonlib.dumps(event).encode("utf-8")
        req = urllib.request.Request(ALERT_WEBHOOK_URL, data=body, method="POST", headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass
class RegisterRequest(BaseModel):
    service_id: str
    name: str
    capabilities: list[str]
    endpoint: str
    auth_key: str
class SendRequest(BaseModel):
    target_id: str
    message_type: str
    payload: dict
class BroadcastRequest(BaseModel):
    capability: str
    message_type: str
    payload: dict
def require_admin(x_admin_key: str = Header(default="")) -> None:
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="invalid admin key")
def _record_auth_failure(service_id: str, now: float, reason: str) -> None:
    just_locked = lockout.record_failure(service_id, now)
    registry.log_security_event(service_id, "auth_failure", reason, now)
    if just_locked:
        registry.log_security_event(service_id, "lockout_triggered", reason, now)
        send_alert({"type": "lockout", "service_id": service_id, "reason": reason})
async def verify_signed_request(request: Request, service_id: str) -> dict:
    now = time.time()
    if lockout.is_locked_out(service_id, now):
        raise HTTPException(status_code=403, detail="service is temporarily locked out due to repeated auth failures")
    svc = registry.get(service_id)
    if svc is None:
        raise HTTPException(status_code=401, detail="authentication failed")
    if not svc.active:
        raise HTTPException(status_code=403, detail="service is deactivated")
    body_bytes = await request.body()
    timestamp = request.headers.get("x-timestamp", "")
    signature = request.headers.get("x-signature", "")
    try:
        ts_val = float(timestamp)
    except ValueError:
        _record_auth_failure(service_id, now, "missing or malformed timestamp")
        raise HTTPException(status_code=401, detail="authentication failed")
    if abs(now - ts_val) > MAX_CLOCK_SKEW_SECONDS:
        _record_auth_failure(service_id, now, "stale timestamp (possible replay)")
        raise HTTPException(status_code=401, detail="authentication failed")
    if not signature or not security.verify(svc.auth_key, timestamp, body_bytes, signature):
        _record_auth_failure(service_id, now, "invalid signature")
        raise HTTPException(status_code=401, detail="authentication failed")
    if not rate_limiter.allow(service_id, now):
        raise HTTPException(status_code=429, detail="rate limit exceeded — slow down")
    anomaly_reason = anomaly.record_and_check(service_id, now)
    if anomaly_reason:
        registry.deactivate(service_id)
        registry.log_security_event(service_id, "auto_quarantine", anomaly_reason, now)
        send_alert({"type": "auto_quarantine", "service_id": service_id, "reason": anomaly_reason})
        raise HTTPException(status_code=403, detail=f"service auto-quarantined: {anomaly_reason}")
    try:
        return jsonlib.loads(body_bytes)
    except jsonlib.JSONDecodeError:
        raise HTTPException(status_code=400, detail="malformed JSON body")
@app.post("/admin/register")
def register_service(req: RegisterRequest, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    svc = registry.register(req.service_id, req.name, req.capabilities, req.endpoint, req.auth_key)
    return {"status": "registered", "service_id": svc.service_id}
@app.post("/admin/deactivate/{service_id}")
def deactivate_service(service_id: str, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    registry.deactivate(service_id)
    return {"status": "deactivated", "service_id": service_id}
@app.post("/admin/reactivate/{service_id}")
def reactivate_service(service_id: str, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    registry.reactivate(service_id)
    lockout.reset(service_id)
    return {"status": "reactivated", "service_id": service_id}
@app.get("/admin/services")
def list_services(x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    return [{"service_id": s.service_id, "name": s.name, "capabilities": s.capabilities, "active": s.active} for s in registry.all_active()]
@app.get("/admin/deliveries")
def list_deliveries(limit: int = 50, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    return registry.recent_deliveries(limit)
@app.get("/admin/security-events")
def list_security_events(limit: int = 50, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    return registry.recent_security_events(limit)
@app.post("/admin/unlock/{service_id}")
def unlock_service(service_id: str, x_admin_key: str = Header(default="")):
    require_admin(x_admin_key)
    lockout.reset(service_id)
    return {"status": "unlocked", "service_id": service_id}
@app.post("/send/{sender_id}")
async def send_message(sender_id: str, request: Request):
    body = await verify_signed_request(request, sender_id)
    try:
        req = SendRequest(**body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"malformed request: {e}")
    try:
        rec = relay.send(sender_id, req.target_id, req.message_type, req.payload)
    except DeliveryError as e:
        registry.log_delivery(relay.log[-1])
        raise HTTPException(status_code=502, detail=str(e))
    registry.log_delivery(rec)
    return {"status": "delivered", "attempts": rec.attempts}
@app.post("/broadcast/{sender_id}")
async def broadcast_message(sender_id: str, request: Request):
    body = await verify_signed_request(request, sender_id)
    try:
        req = BroadcastRequest(**body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"malformed request: {e}")
    records = relay.broadcast(sender_id, req.capability, req.message_type, req.payload)
    for rec in records:
        registry.log_delivery(rec)
    return {"sent_to": len(records), "succeeded": sum(1 for r in records if r.success), "failed": sum(1 for r in records if not r.success)}
@app.get("/health")
def health():
    return {"status": "ok", "active_services": len(registry.all_active())}
