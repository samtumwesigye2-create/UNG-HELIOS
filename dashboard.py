from pathlib import Path
import base64
import hashlib
import hmac
import os
import time

from fastapi import HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api import (
    ADMIN_KEY,
    RegisterRequest,
    app,
    deactivate_service,
    reactivate_service,
    register_service,
    registry,
    unlock_service,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

SESSION_COOKIE = "helios_operator"
SESSION_MAX_AGE = int(os.environ.get("HELIOS_UI_SESSION_MAX_AGE", str(60 * 60 * 8)))
SESSION_SECRET = os.environ.get("HELIOS_UI_SESSION_SECRET", ADMIN_KEY)
OPERATOR_KEY = os.environ.get("HELIOS_OPERATOR_KEY", "")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class OperatorLoginRequest(BaseModel):
    operator_key: str


class UIRegisterRequest(BaseModel):
    service_id: str
    name: str
    capabilities: list[str]
    endpoint: str
    auth_key: str


def _safe_service(service):
    return {
        "service_id": service.service_id,
        "name": service.name,
        "capabilities": list(service.capabilities),
        "endpoint": service.endpoint,
        "active": bool(service.active),
    }


def _make_session_token(now: int | None = None) -> str:
    issued = int(time.time() if now is None else now)
    payload = f"operator|{issued}"
    signature = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{signature}".encode()).decode()


def _verify_session_token(token: str | None, now: int | None = None) -> bool:
    if not token:
        return False
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        role, issued_raw, signature = raw.split("|", 2)
        issued = int(issued_raw)
    except (ValueError, UnicodeDecodeError):
        return False
    if role != "operator":
        return False
    current = int(time.time() if now is None else now)
    if issued > current + 60 or current - issued > SESSION_MAX_AGE:
        return False
    payload = f"{role}|{issued}"
    expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def _require_operator(request: Request) -> None:
    if not _verify_session_token(request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(status_code=401, detail="operator session required")


@app.get("/", response_class=HTMLResponse)
def helios_dashboard():
    return (TEMPLATE_DIR / "helios-dashboard.html").read_text(encoding="utf-8")


@app.post("/ui-api/operator/login")
def operator_login(req: OperatorLoginRequest, response: Response):
    if not OPERATOR_KEY:
        raise HTTPException(status_code=503, detail="operator login is not configured")
    if not hmac.compare_digest(req.operator_key, OPERATOR_KEY):
        raise HTTPException(status_code=401, detail="invalid operator credential")
    response.set_cookie(
        SESSION_COOKIE,
        _make_session_token(),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return {"status": "authenticated", "expires_in": SESSION_MAX_AGE}


@app.post("/ui-api/operator/logout")
def operator_logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"status": "signed_out"}


@app.get("/ui-api/operator/session")
def operator_session(request: Request):
    return {"authenticated": _verify_session_token(request.cookies.get(SESSION_COOKIE))}


@app.get("/dashboard/state")
def dashboard_state(request: Request, delivery_limit: int = 50, security_limit: int = 50):
    _require_operator(request)
    services = registry.all_active()
    return {
        "health": {
            "status": "ok",
            "active_services": len(services),
        },
        "services": [_safe_service(service) for service in services],
        "deliveries": registry.recent_deliveries(max(1, min(delivery_limit, 200))),
        "security_events": registry.recent_security_events(max(1, min(security_limit, 200))),
        "generated_at": time.time(),
    }


@app.post("/ui-api/services/register")
def ui_register_service(req: UIRegisterRequest, request: Request):
    _require_operator(request)
    return register_service(
        RegisterRequest(
            service_id=req.service_id,
            name=req.name,
            capabilities=req.capabilities,
            endpoint=req.endpoint,
            auth_key=req.auth_key,
        ),
        x_admin_key=ADMIN_KEY,
    )


@app.post("/ui-api/services/{service_id}/deactivate")
def ui_deactivate_service(service_id: str, request: Request):
    _require_operator(request)
    return deactivate_service(service_id, x_admin_key=ADMIN_KEY)


@app.post("/ui-api/services/{service_id}/reactivate")
def ui_reactivate_service(service_id: str, request: Request):
    _require_operator(request)
    return reactivate_service(service_id, x_admin_key=ADMIN_KEY)


@app.post("/ui-api/services/{service_id}/unlock")
def ui_unlock_service(service_id: str, request: Request):
    _require_operator(request)
    return unlock_service(service_id, x_admin_key=ADMIN_KEY)
