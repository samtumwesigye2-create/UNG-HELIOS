# UNG-HELIOS Operations Dashboard Design

Date: 2026-09-13
Status: Approved design, pending implementation plan

## Goal

Add a staff-facing operations dashboard to the existing UNG-HELIOS service without replacing or weakening the deployed communications API. The dashboard gives authorized operators a clear, live view of HELIOS health, connected UNG systems, message delivery, retries, security events, lockouts, quarantines, and administrative actions.

## Design Direction

Use a dark UNG operations-console visual language. The main screen centers HELIOS as the hub, with connected systems arranged around it. Status must be understandable at a glance and optimized for desktop/tablet operations use.

## Architecture

The existing FastAPI HELIOS API remains the source of truth and relay engine. The dashboard is a thin frontend served by the same application so the current Railway service and domain can remain authoritative.

The dashboard reads existing HELIOS endpoints for health, services, deliveries, and security events. Administrative actions call existing protected admin endpoints. No message-routing logic moves into the frontend.

Initial implementation should avoid introducing a separate frontend deployment unless later scale or UX requirements justify it.

## Main Screens

### 1. Operations Overview
- HELIOS hub visualization in the center
- Connected service nodes around HELIOS
- Overall health state
- Active service count
- Recent delivery success/failure activity
- Recent security alerts
- Status badges: online, inactive, locked, quarantined, degraded

### 2. Systems
- Registered system list
- Name, service ID, capabilities, endpoint status, active state
- Search/filter by system or capability
- Detail panel for one selected system
- Protected actions: deactivate, reactivate, unlock

### 3. Message Flow
- Recent HELIOS delivery records
- Sender, target, message type, time, attempts, result
- Filters for sender, target, failure state, and time range
- Retry/failure visibility without exposing authentication secrets

### 4. Security
- Recent security events
- Authentication failures
- Lockout events
- Auto-quarantine events
- Rate-limit/anomaly events when present
- Protected recovery controls where supported by current API

### 5. Administration
- Register a service using the existing admin API
- Deactivate/reactivate services
- Unlock services
- Never display stored auth keys after submission

## Data Flow

Browser -> HELIOS dashboard routes -> existing HELIOS API/registry -> SQLite persistence.

Read operations use health/services/deliveries/security-event endpoints. Write operations use existing admin endpoints and retain current server-side authorization checks.

The frontend must not become a second source of truth and must not persist HELIOS state independently.

## Security

- Preserve all existing HELIOS authentication and authorization behavior.
- Never expose HELIOS_ADMIN_KEY or service auth keys in page source, client storage, logs, or responses.
- Admin credentials are supplied only for protected administrative actions and should be handled server-side where practical.
- Escape/render untrusted service metadata safely.
- Do not add any bypass around existing HMAC, rate limiting, lockout, or quarantine controls.
- Dashboard is an operational visibility/control surface, not an intrusion or counterattack tool.

## Error Handling

- API unavailable: show degraded/offline banner, retain last rendered view only in memory, and disable dangerous admin actions.
- Individual endpoint failure: show section-level error rather than blanking the whole dashboard.
- Failed admin action: show the actual HTTP failure result and do not optimistically mark success.
- Empty datasets: show an explicit empty state rather than an error.

## Implementation Shape

Recommended first version:
- FastAPI-served HTML/CSS/JavaScript dashboard
- New dashboard route for `/`
- Static assets under a dedicated static directory
- Small server-side dashboard/admin helper only where needed to keep secrets off the browser
- Existing API modules remain authoritative

This is intentionally simpler than introducing React/Vite or a second service. A separate frontend can be considered later if HELIOS UI complexity grows materially.

## Testing

Implementation must preserve the existing HELIOS automated suite and add dashboard-specific tests covering:
- `/` returns the dashboard instead of 404
- dashboard assets load
- health/services/deliveries/security data render correctly
- admin actions map to the correct existing HELIOS operations
- failed admin actions are surfaced accurately
- auth keys/admin secrets are never rendered back to the browser
- current relay/security API behavior remains unchanged

Before completion, run the full existing test suite plus the new dashboard tests, then verify the deployed Railway root page and API health endpoint.

## Acceptance Criteria

The dashboard is accepted when:
1. Opening the existing HELIOS Railway domain shows the operations dashboard instead of a 404.
2. HELIOS health and active-system information appear correctly.
3. Registered systems and recent message/security activity can be inspected.
4. Authorized staff can register, deactivate/reactivate, and unlock systems through the UI.
5. Secrets are not exposed to the browser.
6. Existing HELIOS messaging/security tests still pass.
7. `/health` continues to return successfully after deployment.
