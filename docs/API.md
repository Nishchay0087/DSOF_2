# FastAPI API

The normal server is `dsof.api`, started by `python -m dsof run`. Browse
`/api/docs` for offline endpoint documentation and `/api/openapi.json` for
request/response schemas. The former Flask/Socket.IO API remains as a legacy
compatibility module, not the running server.

Read endpoints: `/api/health`, `/api/ready`, `/api/state`, `/api/config`,
`/api/collector`, `/api/flows`, `/api/alerts`, `/api/attacks/latest`,
`/api/honeypots`, `/api/sessions`, `/api/sessions/{id}`, `/api/strategies`,
`/api/errors`, `/api/export` and `/api/auth`.

Collection endpoints accept `limit=1..500` and provenance/link filters such as
`origin`, `test_id`, `runtime_id`, `flow_id`, `deployment_id`, `session_id` and
`alert_id`. Snapshot/export is bounded recent history, not a full backup.
Counts include retained history. WebSocket `/ws` sends a complete snapshot
every second. Cross-origin WebSockets are rejected.

Mutation endpoints require `Authorization: Bearer <data/control.token>` or
a logged-in operator cookie. Cross-origin mutations are rejected. Login is
`POST /api/auth/login` with `{ "token": "..." }`; it creates a one-hour
HTTP-only SameSite=Strict cookie. Logout is `POST /api/auth/logout`.

- `POST /api/collector/control`: `{ "action": "start" | "stop" }`.
- `POST /api/honeypots`: `{ "service": "web" | "ssh" | "database" }` for
  a manual listener test. This does not create an alert.
- `POST /api/honeypots/stop`: `{}` closes the current listeners.
- `POST /api/predict`: `{ "features": {...} }` performs labeled manual
  inference only; callers cannot provide provenance or create detector alerts.
- `POST /api/tests/register`: `{ "test_id": "UUID", "target_port": 19090 }`
  registers a short-lived localhost traffic correlation. It does not create
  packets, alerts or interactions.

Invalid input returns 400/422, unauthenticated mutations 401, forbidden origins
403, missing resources 404, disabled capture starts 409, oversized bodies 413,
rate-limited login 429, and unavailable model/failed listener/readiness 503.
The request body limit is 64 KiB. The control token is never returned to the
browser by the server. Remote exposure remains outside the local demonstration
configuration and requires separate authentication/transport deployment work.
