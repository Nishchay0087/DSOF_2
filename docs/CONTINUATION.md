# Historical continuation notes

This records the first continuation only. The current implementation and setup are documented in [README](../README.md) and [validation report](VALIDATION_REPORT.md). Several gaps below have since been completed.

# Continuation: 13 October 2026

The existing Flask/Socket.IO application and SQLite evidence database have been
extended in place. Original model and dataset files are unchanged.

## Added

- An explainable ten-minute attacker behavior profile, persisted on every new
  alert. It uses up to 1,000 recent flows from the same source and origin.
  Twenty destination ports across three destinations yields Advanced; five
  ports or ten flows yields Intermediate; otherwise Beginner. These labels
  describe observed behavior, not verified expertise or identity.
- A DSOF feedback selector and `/api/strategies` endpoint. Only completed live
  sessions linked to profiled alerts contribute. Active, interrupted,
  unattributed and manual-test sessions do not train the selector.
- Comparisons are separated by attack category, profile tier and exact DSI
  version, weights and normalizers. Both the configured strategy and an
  alternative need three samples; switching requires five points improvement.
  Without this evidence, the configured strategy remains selected. Rankings
  are rebuilt from retained records, so restarts do not lose feedback and
  retention removes expired evidence. This is observational learning, not a
  causal experiment or model retraining. There is no automatic exploration;
  an alternative needs separately collected qualifying history.
- Dashboard panels for profile evidence, decision reasons and historical DSI.
- Platform-specific loopback defaults, macOS capture diagnostics and a launcher
  using the OpenMP runtime already bundled with the pinned scikit-learn wheel.

## macOS

The local `.venv-mac` is installed. From the project directory:

```sh
sh tools/run_local.sh validate
sh tools/run_local.sh check
DSOF_PORT=5050 sh tools/run_local.sh run
```

Visit `http://127.0.0.1:5050`. Port 5050 avoids common macOS port 5000 conflicts.
Ctrl+C stops the process. Capture errors are displayed while the dashboard
remains available. No fake traffic is generated to fill an empty dashboard.
For a fresh environment, use Python 3.12 to create `.venv-mac`, then install
`requirements.txt` using that environment's pip. The copied Windows `.venv`
is not executable on macOS.

On this Mac, interface discovery succeeds but opening `/dev/bpf0` fails with
permission denied, including outside the Codex sandbox. Live capture requires
administrator-configured BPF access; the application does not modify device
permissions. Do not interpret a running dashboard as capture readiness.

## Remaining differences from the supplied proposal

The current application uses Flask, plain JavaScript and SQLite. It has not
been migrated to FastAPI, React/TypeScript or PostgreSQL/Supabase. Available
services are a web emulator and plaintext SSH/database-style emulators; full
SSH/Cowrie, FTP, IoT, enterprise networks and isolated container deployment
are not implemented. Traffic is not redirected.

The existing versioned DSI measures observed duration, interaction count,
distinct actions and depth. It is not the proposed 0.35E + 0.30I + 0.20D +
0.15P metric. Measuring diversion needs legitimate-asset telemetry, and
persistence needs a defined longitudinal session window and attribution
policy. Neither factor is fabricated. Model feature parity remains unverified
because the original training/preprocessing pipeline was not supplied.

## Validation

The original XGBoost model loads on macOS with SHA-256
`86e5dd0e6afe353e3ee1b7488271e390a047ec8483cc540b526c1f74ca65e8f6`.
The full suite initially reported 88 passed and one failed: the real capture
integration test cannot open `/dev/bpf0`. That test remains a failure rather
than being hidden or reported as live verification. All socket honeypot and
API integration tests passed outside the sandbox. Dashboard JavaScript passes
Node's syntax check. Synthetic tests are not evidence of detection accuracy.
