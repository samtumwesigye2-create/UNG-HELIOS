from pathlib import Path
import time

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from api import app, registry

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _safe_service(service):
    return {
        "service_id": service.service_id,
        "name": service.name,
        "capabilities": list(service.capabilities),
        "active": bool(service.active),
    }


@app.get("/", response_class=HTMLResponse)
def helios_dashboard():
    return (TEMPLATE_DIR / "helios-dashboard.html").read_text(encoding="utf-8")


@app.get("/dashboard/state")
def dashboard_state(delivery_limit: int = 50, security_limit: int = 50):
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
