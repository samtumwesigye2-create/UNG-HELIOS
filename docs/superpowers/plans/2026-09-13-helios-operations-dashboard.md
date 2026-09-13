# UNG-HELIOS Operations Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a staff-facing dark operations dashboard to the existing UNG-HELIOS FastAPI service so the production root URL becomes a live operational console without changing HELIOS relay/security behavior.

**Architecture:** Keep `api.py`, `core.py`, `storage.py`, and `security.py` authoritative. Serve a thin HTML/CSS/JavaScript dashboard from the same FastAPI service, add narrowly scoped dashboard read endpoints that do not expose secrets, and reuse the existing protected admin operations for register/deactivate/reactivate/unlock actions. No routing or security logic moves into the browser.

**Tech Stack:** Python 3, FastAPI, existing HELIOS registry/security modules, HTML5, CSS3, vanilla JavaScript, Python `unittest` / FastAPI TestClient where available.

**Spec:** `docs/superpowers/specs/2026-09-13-helios-operations-dashboard-design.md`

## Global Constraints

- Preserve all existing HELIOS authentication, HMAC, rate-limit, lockout, quarantine, relay, persistence, and alert behavior.
- Never expose `HELIOS_ADMIN_KEY` or service `auth_key` values in HTML, JavaScript, browser storage, API responses, logs, or error messages.
- Existing HELIOS API modules remain the source of truth.
- The frontend must not persist HELIOS operational state independently.
- Failed admin operations must show their actual failure state; the UI must not optimistically report success.
- The existing `/health` endpoint must continue to work after the dashboard is deployed.
- The production root `/` must render the dashboard instead of returning 404.

---

## File Structure

- Modify `api.py` — mount dashboard assets, serve `/`, expose safe dashboard read models, and add server-side admin action wrappers only where required to keep secrets out of the browser.
- Create `static/helios-dashboard.css` — dark UNG operations-console presentation, responsive layout, topology styling, status badges, tables, and empty/error states.
- Create `static/helios-dashboard.js` — polling, rendering, filtering, topology drawing, section-level errors, and protected admin form submission without persistent credential storage.
- Create `templates/helios-dashboard.html` — dashboard shell, topology panel, systems/message/security panels, and administration controls.
- Create `test_dashboard.py` — route, asset, sanitization, and admin-control regression tests.
- Modify `README.md` — document the dashboard URL and operational behavior after tests pass.

---

### Task 1: Dashboard Route and Static Assets

**Files:**
- Modify: `api.py`
- Create: `templates/helios-dashboard.html`
- Create: `static/helios-dashboard.css`
- Create: `static/helios-dashboard.js`
- Test: `test_dashboard.py`

**Interfaces:**
- Consumes: existing FastAPI `app` in `api.py`
- Produces: `GET /` HTML dashboard, `/static/helios-dashboard.css`, `/static/helios-dashboard.js`

- [ ] **Step 1: Write the failing route test**

```python
import unittest
from fastapi.testclient import TestClient
import api

class DashboardRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(api.app)

    def test_root_returns_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("UNG-HELIOS", response.text)
        self.assertIn("Operations Dashboard", response.text)

    def test_dashboard_assets_load(self):
        self.assertEqual(self.client.get("/static/helios-dashboard.css").status_code, 200)
        self.assertEqual(self.client.get("/static/helios-dashboard.js").status_code, 200)
```

- [ ] **Step 2: Run the test and verify it fails before implementation**

Run: `python -m unittest test_dashboard.DashboardRouteTests -v`

Expected: root returns 404 and/or static assets are unavailable.

- [ ] **Step 3: Add FastAPI template/static serving**

Add imports and mounts in `api.py`:

```python
from pathlib import Path
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE_DIR / "templates" / "helios-dashboard.html").read_text(encoding="utf-8")
```

- [ ] **Step 4: Create the dashboard shell**

`templates/helios-dashboard.html` must contain these stable element IDs for later tasks:

```html
<header id="topbar"></header>
<section id="health-summary"></section>
<section id="topology"></section>
<section id="systems-panel"></section>
<section id="deliveries-panel"></section>
<section id="security-panel"></section>
<section id="admin-panel"></section>
<div id="global-banner" role="status"></div>
<script src="/static/helios-dashboard.js" defer></script>
```

Include the stylesheet with:

```html
<link rel="stylesheet" href="/static/helios-dashboard.css">
```

- [ ] **Step 5: Create the initial dark console styling**

Use CSS variables and responsive grid structure; status semantics must be conveyed by text/badges as well as visual styling. Required classes:

```css
:root { color-scheme: dark; }
.dashboard-grid { display: grid; grid-template-columns: minmax(0,2fr) minmax(320px,1fr); gap: 1rem; }
.status-badge { border: 1px solid currentColor; border-radius: 999px; padding: .2rem .55rem; }
@media (max-width: 900px) { .dashboard-grid { grid-template-columns: 1fr; } }
```

- [ ] **Step 6: Add a JavaScript boot marker**

`static/helios-dashboard.js`:

```javascript
window.HELIOS_DASHBOARD = { version: "1" };
```

- [ ] **Step 7: Run route tests**

Run: `python -m unittest test_dashboard.DashboardRouteTests -v`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add api.py templates/helios-dashboard.html static/helios-dashboard.css static/helios-dashboard.js test_dashboard.py
git commit -m "feat: serve HELIOS operations dashboard"
```

---

### Task 2: Safe Dashboard Data API

**Files:**
- Modify: `api.py`
- Modify: `test_dashboard.py`

**Interfaces:**
- Consumes: `registry.all_active()`, `registry.recent_deliveries(limit)`, `registry.recent_security_events(limit)`, current HELIOS health state
- Produces: `GET /dashboard/state?delivery_limit=50&security_limit=50` returning only safe operational metadata

- [ ] **Step 1: Write failing safe-state tests**

```python
class DashboardStateTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(api.app)

    def test_dashboard_state_does_not_expose_auth_keys(self):
        response = self.client.get("/dashboard/state")
        self.assertEqual(response.status_code, 200)
        body = response.text.lower()
        self.assertNotIn("auth_key", body)
        self.assertNotIn("helios_admin_key", body)

    def test_dashboard_state_has_required_sections(self):
        data = self.client.get("/dashboard/state").json()
        self.assertIn("health", data)
        self.assertIn("services", data)
        self.assertIn("deliveries", data)
        self.assertIn("security_events", data)
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python -m unittest test_dashboard.DashboardStateTests -v`

Expected: 404 for `/dashboard/state`.

- [ ] **Step 3: Implement safe state serialization**

Add to `api.py`:

```python
def _safe_service(s):
    return {
        "service_id": s.service_id,
        "name": s.name,
        "capabilities": list(s.capabilities),
        "active": bool(s.active),
    }

@app.get("/dashboard/state")
def dashboard_state(delivery_limit: int = 50, security_limit: int = 50):
    services = registry.all_active()
    return {
        "health": {"status": "ok", "active_services": len(services)},
        "services": [_safe_service(s) for s in services],
        "deliveries": registry.recent_deliveries(max(1, min(delivery_limit, 200))),
        "security_events": registry.recent_security_events(max(1, min(security_limit, 200))),
        "generated_at": time.time(),
    }
```

If existing storage objects are dataclasses or named tuples, normalize deliveries/security events to JSON-safe dictionaries in a helper before returning them; do not return any service secret field.

- [ ] **Step 4: Run safe-state tests**

Run: `python -m unittest test_dashboard.DashboardStateTests -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api.py test_dashboard.py
git commit -m "feat: expose safe HELIOS dashboard state"
```

---

### Task 3: Live Overview, Topology, Systems, Deliveries, and Security Panels

**Files:**
- Modify: `templates/helios-dashboard.html`
- Modify: `static/helios-dashboard.css`
- Modify: `static/helios-dashboard.js`
- Modify: `test_dashboard.py`

**Interfaces:**
- Consumes: `GET /dashboard/state`
- Produces: `loadDashboardState()`, `renderHealth(state)`, `renderTopology(services)`, `renderSystems(services)`, `renderDeliveries(deliveries)`, `renderSecurity(events)`

- [ ] **Step 1: Write failing content-contract test**

```python
def test_dashboard_contains_operational_sections(self):
    html = self.client.get("/").text
    for marker in ["health-summary", "topology", "systems-panel", "deliveries-panel", "security-panel", "admin-panel"]:
        self.assertIn(marker, html)
```

- [ ] **Step 2: Run test and confirm the first missing marker fails**

Run: `python -m unittest test_dashboard -v`

Expected: FAIL until all required markers exist.

- [ ] **Step 3: Implement polling without browser persistence**

```javascript
const REFRESH_MS = 5000;

async function loadDashboardState() {
  const response = await fetch("/dashboard/state", { cache: "no-store" });
  if (!response.ok) throw new Error(`Dashboard state HTTP ${response.status}`);
  return response.json();
}

async function refreshDashboard() {
  try {
    const state = await loadDashboardState();
    renderHealth(state.health);
    renderTopology(state.services || []);
    renderSystems(state.services || []);
    renderDeliveries(state.deliveries || []);
    renderSecurity(state.security_events || []);
    setBanner("");
  } catch (error) {
    setBanner(`HELIOS dashboard degraded: ${error.message}`);
  }
}

refreshDashboard();
setInterval(refreshDashboard, REFRESH_MS);
```

Do not use `localStorage`, `sessionStorage`, IndexedDB, or cookies for HELIOS state.

- [ ] **Step 4: Implement topology rendering**

Render HELIOS as the central hub and service cards/nodes around it. Each service node must show `name`, `service_id`, capabilities, and an explicit ACTIVE/INACTIVE-style text badge. Never inject raw metadata with `innerHTML`; create text nodes or assign `textContent`.

- [ ] **Step 5: Implement systems and event tables**

Systems table columns: System, Service ID, Capabilities, State.

Deliveries table columns: Time, Sender, Target, Message Type, Attempts, Result.

Security table columns: Time, Service, Event, Detail.

Each panel must show an explicit empty-state row when no records exist.

- [ ] **Step 6: Add filters**

Add text filters for systems and delivery sender/target. Filters operate on the last in-memory response only and do not store data beyond the page lifetime.

- [ ] **Step 7: Run dashboard and existing tests**

Run:

```bash
python -m unittest test_dashboard -v
python -m unittest discover -v
```

Expected: all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add templates/helios-dashboard.html static/helios-dashboard.css static/helios-dashboard.js test_dashboard.py
git commit -m "feat: render HELIOS live operations panels"
```

---

### Task 4: Protected Administration Controls

**Files:**
- Modify: `api.py`
- Modify: `templates/helios-dashboard.html`
- Modify: `static/helios-dashboard.js`
- Modify: `test_dashboard.py`

**Interfaces:**
- Consumes: current server-side `ADMIN_KEY`, existing `register_service`, `deactivate_service`, `reactivate_service`, `unlock_service`
- Produces: `POST /dashboard/admin/register`, `POST /dashboard/admin/deactivate/{service_id}`, `POST /dashboard/admin/reactivate/{service_id}`, `POST /dashboard/admin/unlock/{service_id}`

- [ ] **Step 1: Write failing admin wrapper tests**

```python
class DashboardAdminTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(api.app)

    def test_dashboard_admin_endpoint_does_not_require_admin_key_in_browser(self):
        response = self.client.post("/dashboard/admin/unlock/nonexistent")
        self.assertNotEqual(response.status_code, 404)

    def test_dashboard_html_never_contains_admin_key(self):
        html = self.client.get("/").text
        self.assertNotIn(api.ADMIN_KEY, html)
```

- [ ] **Step 2: Run tests and confirm wrappers are absent**

Run: `python -m unittest test_dashboard.DashboardAdminTests -v`

Expected: 404 for wrapper route before implementation.

- [ ] **Step 3: Implement server-side wrappers that call existing admin functions**

```python
@app.post("/dashboard/admin/deactivate/{service_id}")
def dashboard_deactivate(service_id: str):
    return deactivate_service(service_id, ADMIN_KEY)

@app.post("/dashboard/admin/reactivate/{service_id}")
def dashboard_reactivate(service_id: str):
    return reactivate_service(service_id, ADMIN_KEY)

@app.post("/dashboard/admin/unlock/{service_id}")
def dashboard_unlock(service_id: str):
    return unlock_service(service_id, ADMIN_KEY)
```

For registration, define a browser-safe request model with the same fields as `RegisterRequest`, forward it internally to `register_service(req, ADMIN_KEY)`, and never echo `auth_key` in the response.

If dashboard access is public at this stage, do **not** ship these wrappers enabled without an operator authentication gate. In that case, expose only read-only dashboard controls first and keep admin buttons disabled with the label `Operator authentication required` until an authenticated staff session mechanism is available.

- [ ] **Step 4: Implement UI controls**

Add forms/buttons for register, deactivate/reactivate, and unlock. After a successful response, call `refreshDashboard()`. On failure, display the exact HTTP status/detail in the admin result area and leave the rendered service state unchanged until the next confirmed refresh.

- [ ] **Step 5: Verify secret non-exposure**

Run:

```bash
python -m unittest test_dashboard.DashboardAdminTests -v
grep -R "HELIOS_ADMIN_KEY\|change-me-before-deploying" templates static || true
```

Expected: tests PASS; grep returns no dashboard secret references.

- [ ] **Step 6: Commit**

```bash
git add api.py templates/helios-dashboard.html static/helios-dashboard.js test_dashboard.py
git commit -m "feat: add protected HELIOS dashboard controls"
```

---

### Task 5: Regression, Production Deployment, and Visual Acceptance

**Files:**
- Modify: `README.md`
- Modify: `test_dashboard.py` only if deployment-specific regression coverage is required

**Interfaces:**
- Consumes: full dashboard implementation and existing Railway deployment
- Produces: verified production root dashboard and unchanged `/health`

- [ ] **Step 1: Run full local regression suite**

Run:

```bash
python -m unittest discover -v
```

Expected: all existing HELIOS tests plus dashboard tests PASS; no regressions.

- [ ] **Step 2: Start local FastAPI server and smoke test**

Run:

```bash
uvicorn api:app --host 127.0.0.1 --port 8080
```

Then verify:

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/dashboard/state
```

Expected: `/` 200 HTML, `/health` 200 JSON, `/dashboard/state` 200 JSON with no secret fields.

- [ ] **Step 3: Update README**

Document:
- production root opens the HELIOS Operations Dashboard
- `/health` remains the machine health endpoint
- dashboard polls operational state every 5 seconds
- administrative controls are available only behind the implemented operator-auth gate; otherwise the first release is read-only

- [ ] **Step 4: Deploy through Railway from the approved branch/commit**

Confirm the deployment reaches `SUCCESS` and Uvicorn starts on Railway's assigned port.

- [ ] **Step 5: Verify production HTTP behavior**

Verify on the existing production domain:
- `GET /` -> 200 and contains `UNG-HELIOS`
- `GET /health` -> 200
- `GET /dashboard/state` -> 200
- dashboard JS/CSS assets -> 200

- [ ] **Step 6: Perform visual acceptance**

Check desktop and narrow/mobile widths. Confirm:
- HELIOS is visually central
- system state is readable without relying only on color
- no horizontal page overflow at narrow widths
- empty/error states are readable
- security and delivery tables remain usable
- admin actions are disabled or protected when operator authentication is unavailable

- [ ] **Step 7: Final secret scan**

Run:

```bash
grep -R "HELIOS_ADMIN_KEY\|change-me-before-deploying" templates static README.md || true
```

Expected: no secret values/references in browser assets.

- [ ] **Step 8: Commit documentation/acceptance updates**

```bash
git add README.md test_dashboard.py
git commit -m "docs: document HELIOS operations dashboard"
```

---

## Self-Review Results

- Spec coverage: root dashboard, topology, health, systems, delivery activity, security events, failure states, secret handling, protected admin operations, tests, and Railway verification are all mapped to tasks.
- Placeholder scan: no TBD/TODO/future-fill instructions are present.
- Interface consistency: the plan consistently uses `/dashboard/state`, `refreshDashboard()`, and the four `/dashboard/admin/...` action routes.
- Security caveat resolved explicitly: server-side admin wrappers must not be exposed on a public dashboard without operator authentication; if no staff-session mechanism exists, V1 ships read-only rather than creating an admin bypass.
