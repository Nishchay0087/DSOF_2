# DSOF — AI-driven Adaptive Honeypot Framework

A working **local research project for macOS**, with a FastAPI backend,
React/TypeScript dashboard, the selected 78-feature XGBoost classifier with recovered StandardScaler, measured network
flows, HTTP indicator detection, attacker behavior profiles, adaptive strategy
selection, real honeypot interactions, SQLite history, and reproducible DSI.

Database hosting is deferred by agreement; no external database account is
required. Original model and dataset artifacts remain unchanged.

## Run on this Mac

The Python environment and compiled frontend are already installed.

Terminal 1:

```sh
cd /Users/nishchay/Documents/dsop_re
sh tools/run_local.sh run
```

Terminal 2:

```sh
cd /Users/nishchay/Documents/dsop_re
sh tools/capture_macos.sh
```

Enter your Mac administrator password in Terminal when `sudo` requests it.
Only Apple's `tcpdump` runs privileged; the server and honeypots run as your
normal account. The private FIFO holds packets in memory and applies
backpressure. No system permissions, routing, or security settings change.
The helper captures `lo0` TCP/UDP traffic only. Stop each terminal with Ctrl+C.
If the backend is restarted, restart the capture helper as well.

Open **http://127.0.0.1:5050**. Wait for **Traffic capture: Ready**. A running
web server alone does not mean capture is working.

The dashboard includes overview metrics, traffic and detection tables,
listener controls, session evidence, DSI component breakdowns, strategy
history, model details, operator controls and JSON snapshot export. Snapshots
refresh over WebSockets and reconnect automatically. Tables contain recent
records; counters include retained history. API documentation is available
locally at `/api/docs`, with the full schema at `/api/openapi.json`.

To unlock controls, copy the contents of `data/control.token` into the
**System → Operator access** field. The token is never returned by an API or
embedded in frontend code. The browser receives a one-hour HTTP-only cookie.

## Verify the entire pipeline

With both terminals running:

```sh
.venv-mac/bin/python tools/verify_live.py
```

This sends harmless SQL/XSS/traversal indicator requests and a benign control
**to a temporary localhost HTTP server only**. It checks actual packet
capture, flow creation, classification, rule attribution, deployment readiness,
new honeypot connections, durable evidence and both DSI formulas. It does not
inject alerts or fabricate engagement. Reports are written to
`validation/macos-live-verification.json` and tagged `manual_test`, excluded
from learning on live attacks.

A model can classify a request as benign while an HTTP indicator matches;
both outputs remain visible. This is expected and is not relabeled as a
successful ML detection. The provided model's training feature parity is
unverified; no new accuracy claim is made.

Additional checks:

```sh
sh tools/run_local.sh validate
sh tools/run_local.sh check
sh tools/test_local.sh
sh tools/build_frontend.sh
```

Run regression tests with capture stopped when you want to avoid collecting
their real localhost socket traffic. Tests use disposable databases and
explicitly labeled fixtures. On this Mac the direct-BPF test is skipped when
OS permissions prevent direct access; the configured FIFO backend is tested
separately and the live acceptance run verifies real capture.

## Deception services

| Service | Local endpoint | Behavior |
|---|---|---|
| Web | `127.0.0.1:8081` | HTTP pages, login forms, restricted paths and query endpoints; observed request categories |
| SSH | `127.0.0.1:2222` | Actual encrypted SSH, password attempts, exec requests and interactive virtual shell |
| Database | `127.0.0.1:3307` | Bounded documented line protocol: `HELP`, `AUTH`, `TABLES`, `SELECT`, `QUIT` |

The SSH shell answers a fixed vocabulary such as `whoami`, `id`, `pwd`, `ls`
and `cat /etc/passwd` from fictional in-memory content. It does not execute
commands, access real files, provide forwarding, or expose SFTP. Passwords are
not stored; authentication records contain a deployment-keyed fingerprint.
The database service is a low-interaction emulator, not a MySQL/PostgreSQL
wire-protocol server. Health checks never count as attacker sessions.

Deception begins when a subsequent client connects to a listening service.
This project does not transparently redirect an existing connection. Sources
are associated with the most recent matching live alert within five minutes;
this is a source-address heuristic, not proof of actor identity.

## DSI and learning

`evaluation` implements:

**DSI = 0.35 E + 0.30 I + 0.20 D + 0.15 P**, bounded 0–100.

- E: equally weighted normalized session duration (120 seconds) and
  interaction count (20).
- I: 60% distinct meaningful actions (5) and 40% interaction depth (4).
- D: this observed honeypot connection divided by it plus observed connections
  to configured protected service ports during the session. This is a scoped
  connection-share proxy, not proof that compromise was prevented.
- P: earlier observed sessions from that source and origin within 24 hours,
  normalized to three returns (at most 10,000 recent session records).

The overall score is **unknown** when D cannot be measured. D requires
protected ports, continuous collector readiness since session start, no known
queue loss and no pending processing backlog. Kernel loss is unknown and
remains stated in the evidence. The local configuration monitors port `9090`
as the example protected service; set `DSOF_PROTECTED_PORTS` to the actual
services in your authorized lab. Setting an empty list deliberately makes D
unavailable. Source IPs may represent multiple users.

The earlier engagement-only score remains in `dsi` for audit compatibility.
Learning prefers complete four-component scores when a comparable baseline
exists; otherwise it can compare legacy engagement scores separately. It
never mixes metric versions, normalization policies or monitoring scopes.
Only completed, attributed **live** sessions train selection. Three samples
per strategy and an improvement of five points are required to switch.
Without enough evidence the configured strategy is retained. Alternatives
need prior qualifying observations; there is no random exploration.

## Configuration and installation

`.env` contains this Mac's local configuration; `.env.example` documents
available settings. Environment variables take precedence. Restart after
changing ports or policies. `config.policy.json` maps attack classes to default
services. `config.dsi.json` retains the legacy scoring policy. Storage and
rotating logs are under `data/`; the token and SSH host key are private files.
Retention defaults to seven days with linked-evidence preservation.

For a fresh Mac checkout: create `.venv-mac` with Python 3.12, install
`requirements.macos.lock.txt`, run `sh tools/prepare_capture.sh`, install
frontend packages using `pnpm install` inside `frontend/`, then run
`sh tools/build_frontend.sh`. The launcher locates the OpenMP library bundled
with the pinned scikit-learn wheel. The original Windows `.venv` is retained
but cannot run on macOS. Direct capture remains available with
`DSOF_CAPTURE_MODE=direct` and the appropriate interface/OS permissions.

## Scope

This is a local, bounded research system, not a production perimeter appliance.
The working deployment uses SQLite as requested. PostgreSQL/Supabase can be
connected in a later deployment. Cowrie/container infrastructure, full database
wire protocols, FTP/IoT/enterprise-network emulation and automatic traffic
redirection are outside this local three-service implementation. HTTPS payload
inspection and a reconstructed original ML training pipeline are not claimed.

See [validation report](docs/VALIDATION_REPORT.md),
[feature contract](docs/FEATURE_CONTRACT.md) and
[HTTP inspection limits](docs/HTTP_DETECTION.md).

The additional `traindata` model has a reproduced offline evaluation and recovered
preprocessing. See [training package validation](docs/TRAINDATA_VALIDATION.md)
for results and its differences from the active model.

The active bundle is `artifacts/traindata/`. Its 10 class labels and 97.13%
reconstructed offline test accuracy are described in the
[active model contract](docs/NEW_MODEL_CONTRACT.md). Live accuracy remains
unverified. Original artifacts remain available for historical comparison.

## HTTP-content ML

A separate learned HTTP classifier now detects SQL-injection and XSS content,
alongside the 78-feature flow classifier and HTTP rules. Its training data is
explicitly synthetic. See [data, evaluation and limits](docs/HTTP_CONTENT_ML.md).
Run `.venv-mac/bin/python tools/verify_http_ml.py` for a live test that requires
correct HTTP ML predictions, rather than accepting a rule-only detection.
