# UNG-HELIOS Operations Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a real responsive operations console on top of the existing HELIOS FastAPI engine while keeping privileged credentials server-side.

**Architecture:** Extend the existing FastAPI application with same-origin static UI assets and server-protected UI/session routes. Existing HELIOS endpoints remain the source of truth. The browser polls safe UI-facing endpoints; privileged actions are proxied server-side so HELIOS_ADMIN_KEY is never delivered to browser code.

**Tech Stack:** Python/FastAPI, existing HELIOS registry/storage/security modules, HTML/CSS/vanilla JavaScript for a dependency-light console, unittest/FastAPI TestClient.

**Spec:** `docs/superpowers/specs/2026-09-13-helios-operations-console-design.md`

## Global Constraints
- Preserve all existing HELIOS API endpoint behavior.
- Preserve the 46-test backend baseline and add UI/security tests.
- Never expose HELIOS_ADMIN_KEY in HTML, JavaScript, localStorage, or public environment variables.
- Render only real HELIOS state; no fabricated demo traffic.
- Root `/` becomes the console while `/health` remains unchanged.
- Responsive for desktop, iPad, and iPhone.
- UI completion does not mark HELIOS operationally cleared.

---

### Task 1: Secure UI boundary and root shell

**Files:**
- Modify: `api.py`
- Create: `ui/index.html`
- Create: `ui/styles.css`
- Create: `ui/app.js`
- Test: `test_ui.py`

**Interfaces:**
- Produces: `GET /` HTML console, `GET /ui/styles.css`, `GET /ui/app.js`.
- Preserves: existing `GET /health` response contract.

- [ ] **Step 1: Write failing tests**

```python
class TestConsoleShell(unittest.TestCase):
    def test_root_serves_helios_console(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("UNG-HELIOS", response.text)
        self.assertNotIn(os.environ.get("HELIOS_ADMIN_KEY", "__never__"), response.text)

    def test_health_contract_is_unchanged(self):
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertIn("active_services", response.json())
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest test_ui.TestConsoleShell -v`
Expected: root-shell test FAIL because `/` currently returns 404.

- [ ] **Step 3: Implement minimal same-origin shell**

Mount a static `/ui` directory in `api.py`, return `ui/index.html` from `/`, and create a semantic shell containing header, metrics, topology, security, delivery, and services regions. Do not add any admin key to templates or JS.

- [ ] **Step 4: Verify**

Run: `python -m unittest test_ui.TestConsoleShell -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api.py ui test_ui.py
git commit -m "feat: add HELIOS operations console shell"
```

### Task 2: Real read-only operational data

**Files:**
- Modify: `api.py`
- Modify: `ui/app.js`
- Modify: `ui/index.html`
- Test: `test_ui.py`

**Interfaces:**
- Produces: `GET /ui-api/overview` returning `{health, services, deliveries, security_events}` with no auth keys.
- Consumes: existing registry/storage methods already used by HELIOS admin endpoints.

- [ ] **Step 1: Write failing redaction/data test**

```python
def test_overview_contains_real_state_and_redacts_auth_key(self):
    response = client.get("/ui-api/overview")
    self.assertEqual(response.status_code, 200)
    payload = response.json()
    self.assertIn("services", payload)
    self.assertIn("deliveries", payload)
    self.assertIn("security_events", payload)
    self.assertNotIn("auth_key", json.dumps(payload))
```

- [ ] **Step 2: Run test and verify 404 failure**

Run: `python -m unittest test_ui.TestConsoleData -v`
Expected: FAIL with 404 for `/ui-api/overview`.

- [ ] **Step 3: Implement overview endpoint and polling renderer**

Build the overview payload from the same registry/delivery/security sources used by the existing admin API, explicitly serialize service-safe fields only (`service_id`, `name`, `capabilities`, `endpoint`, `active`). In `ui/app.js`, poll every 5 seconds, render actual counts and records, and show API OFFLINE when fetch fails.

- [ ] **Step 4: Verify tests and browser-independent API behavior**

Run: `python -m unittest test_ui.TestConsoleData -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api.py ui test_ui.py
git commit -m "feat: connect HELIOS console to live operational data"
```

### Task 3: Topology and activity visualization

**Files:**
- Modify: `ui/index.html`
- Modify: `ui/styles.css`
- Modify: `ui/app.js`
- Test: `test_ui.py`

**Interfaces:**
- Consumes: `/ui-api/overview` service and delivery arrays.
- Produces: responsive HELIOS-centered topology and recent sender→target flow rows.

- [ ] **Step 1: Write failing shell-contract test**

```python
def test_console_contains_topology_and_activity_regions(self):
    response = client.get("/")
    self.assertIn('id="topology"', response.text)
    self.assertIn('id="delivery-activity"', response.text)
    self.assertIn('id="security-watch"', response.text)
```

- [ ] **Step 2: Run and verify failure**

Run: `python -m unittest test_ui.TestConsoleShell.test_console_contains_topology_and_activity_regions -v`
Expected: FAIL until regions exist.

- [ ] **Step 3: Implement topology renderer**

Render a central HELIOS node with service nodes positioned around it using CSS/JS geometry. Status classes are derived only from API state. Render capabilities under service names and animate only fresh delivery-flow indicators. On narrow screens switch to a scrollable/stacked topology representation.

- [ ] **Step 4: Verify**

Run: `python -m unittest test_ui -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui test_ui.py
git commit -m "feat: visualize HELIOS topology and message activity"
```

### Task 4: Server-protected operator controls

**Files:**
- Modify: `api.py`
- Modify: `ui/index.html`
- Modify: `ui/app.js`
- Modify: `ui/styles.css`
- Test: `test_ui.py`

**Interfaces:**
- Produces: server-side operator session gate plus UI action routes for register/deactivate/reactivate/unlock.
- Consumes: HELIOS_ADMIN_KEY only inside Python server process.

- [ ] **Step 1: Write failing secret-boundary and unauthorized-action tests**

```python
def test_admin_secret_never_appears_in_browser_assets(self):
    secret = os.environ["HELIOS_ADMIN_KEY"]
    for path in ("/", "/ui/app.js", "/ui/styles.css"):
        self.assertNotIn(secret, client.get(path).text)

def test_privileged_ui_action_requires_operator_session(self):
    response = client.post("/ui-api/services/example/deactivate")
    self.assertIn(response.status_code, (401, 403))
```

- [ ] **Step 2: Run and verify failure**

Run: `python -m unittest test_ui.TestConsoleSecurity -v`
Expected: action-route test FAIL until the protected route exists.

- [ ] **Step 3: Implement server-side session gate**

Add a server-held operator session mechanism. A successful operator login creates an HttpOnly, Secure, SameSite=Strict session cookie; privileged UI routes validate that session, then invoke the existing HELIOS admin operations server-side using the environment-held admin credential. Never return the credential to the browser. Add explicit logout/session expiry.

- [ ] **Step 4: Implement controls**

Add register, deactivate/reactivate, and unlock controls. UI changes only after a successful server response or subsequent overview refresh. Display failures without assuming state changed.

- [ ] **Step 5: Verify**

Run: `python -m unittest test_ui.TestConsoleSecurity -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api.py ui test_ui.py
git commit -m "feat: protect HELIOS operator controls server-side"
```

### Task 5: Responsive command-center styling

**Files:**
- Modify: `ui/styles.css`
- Modify: `ui/index.html`
- Modify: `ui/app.js`

**Interfaces:**
- Consumes: existing semantic console regions.
- Produces: desktop/tablet/phone layouts with accessible touch controls and explicit status styling.

- [ ] **Step 1: Add viewport and accessibility assertions**

```python
def test_console_is_mobile_ready(self):
    html = client.get("/").text
    self.assertIn('name="viewport"', html)
    self.assertIn('aria-live="polite"', html)
```

- [ ] **Step 2: Run test and verify failure if attributes are missing**

Run: `python -m unittest test_ui.TestConsoleShell.test_console_is_mobile_ready -v`
Expected: FAIL until required markup exists.

- [ ] **Step 3: Implement visual system**

Use CSS custom properties for the dark command surface, telemetry grid, status accents, spacing, typography, and breakpoints. Desktop is topology-first; <=1024px condenses side panels; <=640px becomes a vertical operational stack with >=44px touch targets.

- [ ] **Step 4: Verify automated tests**

Run: `python -m unittest discover -v`
Expected: all existing 46 tests plus new UI tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ui test_ui.py
git commit -m "style: finish responsive HELIOS command console"
```

### Task 6: Deployment and live verification

**Files:**
- Modify only if required by deployment: `railway.toml`, `README.md`

**Interfaces:**
- Consumes: Railway deployment from `main`.
- Produces: live root console while retaining `/health` and existing API endpoints.

- [ ] **Step 1: Run complete local verification**

Run: `python -m unittest discover -v`
Expected: zero failures.

- [ ] **Step 2: Push/deploy main and inspect startup**

Verify Uvicorn reaches application startup complete and Railway deployment status is successful.

- [ ] **Step 3: Live smoke test**

Check `GET /` = 200 HTML console and `GET /health` = 200 JSON. Confirm browser assets load and overview endpoint returns real state without `auth_key` or admin secret.

- [ ] **Step 4: Security smoke test**

Verify an unauthenticated privileged UI action is rejected and browser source/assets contain no `HELIOS_ADMIN_KEY` value.

- [ ] **Step 5: Responsive smoke test**

Check desktop and iPhone-width render: no horizontal control overflow, topology remains understandable, and all operator controls are touch-usable.

- [ ] **Step 6: Final regression statement**

Record exact test count and deployment evidence. State separately that the UI is deployed and that HELIOS remains LIVE / NOT YET OPERATIONALLY CLEARED until the previously outstanding authenticated relay/security/persistence acceptance gates pass.
