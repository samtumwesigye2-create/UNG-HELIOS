# UNG-HELIOS Operations Console Design

## Purpose
Add a production operations UI to the existing UNG-HELIOS communications engine without replacing or weakening its current FastAPI relay/security architecture.

## Design direction
The console is a dark, high-density UNG operations interface rather than a generic admin page. The primary visual is a live HELIOS topology centered on the relay, with connected UNG systems arranged around it and status encoded as ONLINE, OFFLINE, LOCKED, or QUARANTINED. The interface must remain readable on iPhone/iPad as well as desktop.

## Existing API contract
The console consumes the existing HELIOS endpoints:
- GET /health
- GET /admin/services
- GET /admin/deliveries
- GET /admin/security-events
- POST /admin/register
- POST /admin/deactivate/{service_id}
- POST /admin/reactivate/{service_id}
- POST /admin/unlock/{service_id}

The communications engine, signing model, relay behavior, registry, delivery log, and security-event log remain authoritative.

## Console information architecture
1. Command header: HELIOS identity, API health, active-service count, current time, operator/session state.
2. Topology: HELIOS core node, registered systems, connection/status visualization, capability labels, recent message-flow indication.
3. Operations metrics: deliveries, successful/failed attempts, retries, active services, security-event count.
4. Delivery activity: recent sender → target traffic, message type, attempts, success/failure, timestamp/error.
5. Security watch: authentication failures, lockouts, rate-limit/anomaly/quarantine events with severity and affected service.
6. Service registry: service ID/name, capabilities, endpoint, active state, operator actions.
7. Protected controls: register service, deactivate/reactivate service, unlock service.

## Security architecture
The HELIOS_ADMIN_KEY must never be embedded in browser JavaScript, HTML, localStorage, or a public frontend environment variable. Privileged browser actions must terminate at a server-side HELIOS UI/session boundary that holds the admin credential server-side and calls the existing admin API internally. Operator authentication/session state gates every privileged read or mutation. Read-only health may remain public only where the existing API already permits it.

No UI feature may bypass HELIOS HMAC service authentication or create an alternate relay path.

## Data behavior
The first release uses short polling against the existing API rather than introducing a new messaging protocol. Health/topology/activity should refresh without a full page reload. A disconnected API produces an explicit degraded/offline state; it must not fabricate healthy services or traffic. Empty registries/logs render as empty operational states rather than demo data.

## Responsive behavior
Desktop uses a topology-first command-center layout. Tablet keeps topology plus condensed side panels. Phone switches to a vertical operational stack: health/metrics, topology, security, deliveries, services. Touch targets must be large enough for iPhone/iPad operation.

## Visual system
Near-black command surface, restrained high-contrast status accents, fine grid/telemetry texture, compact technical typography, clear hierarchy, and deliberate motion only for live status/message-flow changes. Avoid decorative gradients or generic SaaS cards that reduce operational readability.

## Failure handling
- HELIOS unreachable: show API OFFLINE/DEGRADED and retain no false live claims.
- Unauthorized session: hide/disable privileged data/actions and require operator authentication.
- Admin action failure: show the server response and preserve current known state until refresh confirms a change.
- Empty data: show zero/empty states, never invented traffic.

## Acceptance criteria
- Root UI renders instead of the current bare 404 once deployed.
- /health remains compatible and continues returning the existing API response.
- Existing 46-test backend baseline is not regressed.
- No admin secret is shipped to the browser bundle.
- Services, deliveries, security events, and health are rendered from real HELIOS data.
- Register/deactivate/reactivate/unlock controls are server-protected.
- Desktop and iPhone layouts are usable.
- UI clearly distinguishes HELIOS UI completion from HELIOS operational acceptance; building the UI does not itself clear the outstanding live acceptance gates.
