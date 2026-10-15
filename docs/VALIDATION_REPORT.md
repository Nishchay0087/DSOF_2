# Latest validation — new model integration, 14 October 2026

The selected 78-feature/10-class model is active with reconstructed StandardScaler.
Fresh loopback SQL/XSS/traversal requests passed capture, inference, HTTP-rule
attribution, automatic web deployment, session persistence and score reproduction.
All three EIDP scores were 42.4752. The benign control produced no alert.
The new classifier returned BENIGN for these short requests; web detection came
from HTTP rules. SSH and database protocol checks also passed.

Current evidence: [live checks](../validation/macos-live-verification.json),
[service checks](../validation/macos-services.json),
[regression tests](../validation/pytest-new-model.xml),
[dashboard](../validation/new-model-dashboard.png).
See [active feature contract](NEW_MODEL_CONTRACT.md) for measurement conventions
and the distinction between reproduced offline accuracy and unverified live parity.
The earlier results below describe the previous model.

# Validation report — 13 October 2026

## Tested implementation

macOS / Python 3.12, FastAPI and Uvicorn, React/TypeScript compiled with Vite,
SQLite, Scapy PCAP decoding, Apple's tcpdump loopback helper and Paramiko SSH.
The backend and services run as the normal user; only tcpdump needs sudo.

## Automated regression results

**95 passed, 1 skipped**. See
[`validation/pytest-macos.xml`](../validation/pytest-macos.xml).

Coverage includes original model integrity and inference validation, flow
accounting, bounded HTTP reassembly, API authorization and provenance,
SQLite relationships and retention, listener lifecycle and limits, real SSH
transport, FIFO framing/disconnect handling, EIDP reproduction and feedback
selection with metric/scope separation. Test databases are disposable and
synthetic fixtures are not represented as real attack evidence.

The one skipped test requires direct `/dev/bpf` access, denied to the normal
macOS account. The actual configured backend uses a privileged tcpdump helper
and an unprivileged FIFO reader. That backend passed its own test and the
fresh live acceptance run below. This is not an assertion that direct BPF
capture works without OS permission.

Two upstream deprecation warnings are present: Starlette's httpx test-client
compatibility and Scapy's finite-field Diffie-Hellman import. Neither produced
a test failure. `pip check` reported no broken requirements. TypeScript checking
and the production frontend build completed successfully.

## Actual live acceptance results

The user started the loopback capture helper in Terminal. The test program
sent new network requests to a temporary localhost HTTP server, waited for
capture-derived detections, made new connections to the automatically deployed
honeypot, fetched persisted session evidence and reproduced both score formats.

| Case | Observed result | Four-component DSI |
|---|---|---:|
| Segmented SQL indicator | Captured flow → HTTP rule → verified web listener → completed session | 32.4752 |
| XSS indicator | Captured flow → HTTP rule → verified web listener → completed session | 37.4752 |
| Traversal indicator | Captured flow → HTTP rule → verified web listener → completed session | 42.4752 |
| Benign control | Captured flow, no HTTP rule match | Not applicable |

Source evidence, correlation IDs, model outputs, rules, decisions, inputs,
coverage and timestamps are stored in
[`validation/legacy-model-live-verification.json`](../validation/legacy-model-live-verification.json).
The scores describe these short controlled interactions; they are not
benchmarks of real adversary deception success. The increasing persistence
component reflects actual successive test connections. All four traffic cases
are marked `manual_test` and excluded from live strategy learning.

For these indicator requests, the original XGBoost model predicted **Normal
Traffic**. The detections came from the independent HTTP rules. Reports and
the interface preserve this distinction; these are not successful ML attack
classification claims. Recovering original training/preprocessing provenance
is still required before claiming live feature parity or calibrated accuracy.

## Actual service protocol results

[`validation/macos-services.json`](../validation/macos-services.json) records
successful checks of the running application:

- **SSH:** encrypted SSH handshake, authentication, fixed virtual-shell
  `whoami` response, two recorded interactions and a completed persisted
  session. The expected local host key was checked. No real shell was invoked.
- **Database:** actual TCP connection using the documented line protocol,
  `TABLES`, `SELECT example`, `QUIT`, three interactions and a completed session.
  This is an emulator, not the PostgreSQL/MySQL wire protocol.

The protocol checks were manually initiated acceptance procedures, not
external attacks. Their sessions are unattributed and cannot train the live
optimizer because there is no linked detection alert.

## Model integrity

The supplied artifact loads successfully and retains SHA-256:

`86e5dd0e6afe353e3ee1b7488271e390a047ec8483cc540b526c1f74ca65e8f6`

See [`validation/model-macos.json`](../validation/model-macos.json).
Neither the original model nor dataset was retrained, overwritten or relabeled.
The supplied accuracy metric has no independently reproduced split provenance
and is displayed only as supplied model metadata.

## Operational limits

This acceptance establishes a working **local research implementation** with
three service types. It does not establish production security, universal
attack detection, unseen-data model accuracy, external-network capture,
causal attack diversion, container isolation, or automatic traffic forwarding.
D is a declared observation-scope connection-share proxy, with unknown kernel
loss; missing coverage produces unknown total DSI. Database hosting is deferred
at the user's request. The local setup and exact startup commands are in
[README](../README.md).

## Final dashboard verification

The browser showed authoritative live snapshots, all four pipeline stages ready,
and three verified listening honeypots. Opening the SSH session displayed its
persisted authentication/command interactions and four EIDP components. No
browser console errors were reported. The final overview screenshot is saved as
[`validation/dashboard.png`](../validation/dashboard.png).
