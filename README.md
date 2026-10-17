# DSOF — Adaptive Honeypot Framework

DSOF is a local cybersecurity research application. It captures loopback traffic,
keeps flow-model predictions separate from HTTP-content predictions and rules,
and records interactions with web, SSH and database-style decoys.

The application uses FastAPI, React/TypeScript and SQLite. A separate research
package compares six configuration-selection policies using recorded localhost
protocol outcomes. It does not control the dashboard's deployed selector.

## What is implemented

- XGBoost classification of 78 flow features and a separate HTTP classifier for
  SQL-injection, XSS and benign content.
- Independent HTTP rules, with each alert retaining its detection source.
- Web decoy, encrypted SSH with a virtual shell, and a database-style line protocol.
- Session history, behaviour profiles, versioned DSI components and JSON exports.
- Operator authentication for service controls.
- Isolated policy-replay, browser usability and AHP study tools.

Services bind to localhost by default. A detection can start a decoy, but a client
must connect to it to create a session. Automatic gateway redirection is not
implemented. Virtual-shell commands never execute in the host shell.

## Quick start on macOS

Requirements: Python 3.12, Node.js 22 or newer, pnpm, and Git. Run commands from
this repository's root unless a command explicitly changes directory.

```sh
git clone https://github.com/Nishchay0087/DSOP.git
cd DSOP
python3.12 -m venv .venv-mac
.venv-mac/bin/python -m pip install -r requirements.macos.lock.txt
cp .env.example .env
sh tools/prepare_capture.sh
(cd frontend && pnpm install --frozen-lockfile)
sh tools/build_frontend.sh
sh tools/run_local.sh validate
```

The tracked model bundles are in `artifacts/traindata/` and
`artifacts/http_content/`. Raw training datasets are not included. Load model
files only from a trusted source; joblib/pickle files can execute code.

Start the application in one Terminal window:

```sh
sh tools/run_local.sh run
```

In a second Terminal window, change to the same checkout and start capture:

```sh
sh tools/capture_macos.sh
```

The capture helper asks for your administrator password through `sudo`. Only
Apple's `tcpdump` runs with elevated privileges; it writes loopback packets to a
private FIFO read by the application. Stop either process with Ctrl+C. Restart
the capture helper after restarting the backend.

Open **http://127.0.0.1:5050** and check that capture reports **Ready**. The API
schema is at `/api/openapi.json` and interactive documentation at `/api/docs`.
The supplied configuration uses port 5050 to avoid common macOS port 5000 conflicts.

### Operator controls

The server creates `data/control.token` on first start. Copy its contents into
**System → Operator access** to unlock service controls. Treat this token as a
password. Never commit it, include it in a screenshot or share it with participants.
The browser receives a one-hour HTTP-only cookie.

### Local services

| Service | Default address | Interaction |
|---|---|---|
| Dashboard/API | `127.0.0.1:5050` | Monitoring and authenticated controls |
| Web | `127.0.0.1:8081` | HTTP pages and recorded requests |
| SSH | `127.0.0.1:2222` | Encrypted connection with a bounded virtual shell |
| Database-style | `127.0.0.1:3307` | `HELP`, `AUTH`, `TABLES`, `SELECT`, `QUIT` |

The database emulator is not wire-compatible with MySQL or PostgreSQL. The SSH
service has no host-shell execution, forwarding or SFTP. See
[service behaviour](docs/HONEYPOTS.md) for details.

## Test and demonstrate

With the backend and capture helper running:

```sh
.venv-mac/bin/python tools/verify_live.py
.venv-mac/bin/python tools/verify_http_ml.py
sh tools/run_local.sh check
```

These checks send controlled localhost requests and inspect the resulting
records. Controlled-test records are labelled separately from live observations.
The HTTP check requires HTTP-model predictions; a rule match alone is insufficient.
A BENIGN flow prediction may coexist with an HTTP attack prediction because the
models use different features and labels.

For the regression suite, stop capture first to avoid collecting test traffic:

```sh
sh tools/test_local.sh
sh tools/build_frontend.sh
```

Some integration tests open localhost listeners. Direct packet-capture tests
require OS permissions. Report skips and permission failures separately from
successful capture verification. See the [demonstration guide](RUN_AND_TEST_GUIDE.txt)
and [troubleshooting](docs/TROUBLESHOOTING.md).

## Research results and limits

| Evaluation | Recorded result | Scope |
|---|---|---|
| Flow model | 97.13% accuracy; macro-F1 0.729 | Reconstructed split, 388,394 records; live feature parity unverified |
| HTTP model | 95.45% accuracy; macro-F1 0.941 | 176 synthetic test examples; eight SQL-injection misses |
| Policy replay | UCB1 close to fixed A2 | Five seeds; scripted localhost clients; no established superiority |
| Web usability pilot | Six sessions; median rating 3.5/5 | Small, unequal groups; no human DSI validation |
| AHP | Three evaluators; group CR 0.0070 | Criterion judgments, not evidence of deception effectiveness |

The final protocol benchmark contains 11,340 measured episodes and 22,500 replay
choices. These are not independent human sessions. The research score and its
AHP weights are separate from the dashboard score. Participant answers and
completed evaluator forms are private and excluded from this repository.

Start with [research instructions](research/README.md), the
[final benchmark report](validation/research-comparison-final-20261016/REPORT.md),
and [aggregate study results](docs/STUDY_RESULTS.md). Detector details are in
[the flow-model contract](docs/NEW_MODEL_CONTRACT.md) and
[HTTP-content evaluation](docs/HTTP_CONTENT_ML.md).

## Configuration

Copy `.env.example` to `.env` for local settings. Environment variables take
precedence. Restart after changing configuration. `config.policy.json` defines
default service mappings; `config.dsi.json` preserves the legacy scoring policy.
Runtime data, logs, tokens and SSH host keys belong under `data/` and are ignored
by Git. SQLite retention defaults to seven days.

The dashboard uses weights E=0.35, I=0.30, D=0.20 and P=0.15. Diversion is a
scoped connection-share proxy. It remains unknown without adequate monitoring
of the configured protected ports. The example uses port 9090; change
`DSOF_PROTECTED_PORTS` for your authorised lab. See [DSI definitions](docs/DSI.md).

The deployed selector compares eligible historical live sessions. It requires
three samples per alternative and a five-point improvement before switching;
it does not use UCB1 or random exploration. See [architecture](docs/ARCHITECTURE.md).

## Repository map

| Directory | Contents |
|---|---|
| `dsof/` | Backend, capture, detection, services and storage |
| `frontend/` | React dashboard source and dependency lockfile |
| `artifacts/` | Runtime model bundles and feature contracts |
| `tools/` | Launch, build, validation and training commands |
| `research/`, `tools/research/` | Separate policy experiments and study tools |
| `tests/` | Unit and integration tests |
| `validation/` | Saved evaluation evidence; reports identify their scope |
| `docs/` | Architecture, detector contracts and usage documentation |

Local environments, raw datasets, runtime databases, completed study forms,
paper drafts and temporary exports are excluded. Research provenance and
synthetic-data labels are retained so results can be assessed correctly.

## Scope and reuse

This is a local research prototype, not a production perimeter defence system.
HTTPS payload inspection, Cowrie deployment, external database hosting and
contained gateway routing are not implemented. Use it only with systems and
traffic you are authorised to test.

See [third-party notices](docs/THIRD_PARTY.md) for dependencies. No project-wide
open-source licence has been selected; obtain the authors' permission before
redistributing project code or supplied model/data assets.
