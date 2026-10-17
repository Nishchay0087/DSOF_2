# Reproducible policy experiments

This package is independent of the running dashboard. It does not replace `dsof/strategy.py`, update production learning records, or claim that routing and human validation are complete.

## Run the automatic localhost benchmark

```sh
# From the repository root
.venv-mac/bin/python tools/research/run_comparison.py \
  --output validation/research-new-run \
  --train 200 --heldout 50 --pilot 10 \
  --seeds 11 23 37 53 71 --workers 6
```

Use a new output folder for every run. No sudo, dashboard auth key or packet-capture restart is needed. Temporary listeners bind only to 127.0.0.1 and are closed on exit. Dependencies come from the existing Mac environment (NumPy, SciPy, Paramiko); install the pinned project requirements before running.

The run records 90 pilot and 11,250 main real protocol episodes. Three arms are measured under matching random stimuli in each episode panel, then six policies are replayed against those outcomes. The decision ledger contains 22,500 choices (3 classes × 5 seeds × 6 policies × 250 episodes). These are policy replay choices, not 22,500 independent network sessions or participants. All policies receive only selected-arm rewards.

Policies: fixed A2; uniform random; an explicitly new rate-bucket rule (low=A1, medium=A2, high=A3); terminal tabular Q update with alpha=.1 and epsilon=.1; sample-mean epsilon-greedy with epsilon=.1; UCB1. Q sees class and rate bucket, other learners class only. This unequal information set is disclosed, not presented as identical-context comparison. Agent rate buckets use 2/4/6ms pauses, not calibrated human skill. Frozen learners use greedy actions, no updates/exploration. Static/random/rule retain their definitions. Random tie-breaking uses fixed seeds.

UCB1 uses mean reward + sqrt(2 log(total pulls)/arm pulls), with each arm tried once. Reference: https://doi.org/10.1023/A:1013689704352. Policy state and outcomes are in a separate SQLite ledger for audit, not an integrated restartable production routing service.

## Actual arm definitions

- Web A1: always rejects. A2: common synthetic admin login yields fixed dashboard. A3: adds fixed SQL-like response records and a breadcrumb to a records page. No actual vulnerable SQL engine or XSS execution exists.
- SSH A1: authentication succeeds but commands are unavailable. A2: a small populated virtual persona. A3: adds a history breadcrumb. All use real encrypted Paramiko SSH with pinned temporary host keys and fixed command responses. None is Cowrie; no OS command is executed.
- Scan A1: one responding endpoint and two bound non-listening probe targets. A2: three generic endpoint banners. A3: three detailed banners. The agent currently responds to service success/failure, not banner realism, so A2/A3 are not expected to differ systematically except timing noise. Closed-target refusal/50ms timeout is a probe result, not an infrastructure failure.
- Reference: a local HTTP stub. A 0.35 probability of a reference visit after agent stopping provides a measured surrogate action share. It is not a real asset, gateway redirection, or a causal reduction in damage.

Agent continuation probabilities are .90 after success and .25 after an empty/failed action. Breadcrumb following is .65; maximum 12 scripted steps. These are declared assumptions, not fitted human behavior. SSH authentication is an additional action. The agent never reads the arm ID to decide whether to continue. No download, OS command, external host or real credential is used.

Pilot 95th-percentile action/time caps are fixed before the main run. Equal weights were fixed before AHP collection; original-weight and ±.05/±.10 perturbations are secondary descriptive analyses. Hardware load and protocol overhead affect real-time persistence. Class labels come from the runner, not ML predictions. The original detector is not evaluated here.

The hindsight fixed-arm gap can be negative in finite samples. It is an empirical replay comparator, not theoretical regret against an independently known optimal arm. Five seeds give weak inference: the smallest attainable exact paired two-sided sign-flip p-value is .0625. All 15 held-out UCB1 contrasts receive Holm correction. No statistical superiority is guaranteed. Failed episodes receive zero reward and remain counted.

## Human study

Read [study/PROTOCOL.md](study/PROTOCOL.md). Blank forms and a balanced 18-session schedule are in `study/collection`. Arrange actual consented volunteers and independent evaluators. Do not use generated/synthetic answers. Signed consent and completed human records must remain private. The script can record actual sessions and analyze completed forms; it cannot substitute for participants.

## Checks

```sh
.venv-mac/bin/python -m pytest -q tests/test_research.py
DSOF_RESEARCH_PROTOCOL_TESTS=1 .venv-mac/bin/python -m pytest -q tests/test_research_protocols.py
```

AHP collection is complete (three evaluators); see [aggregate results](../docs/STUDY_RESULTS.md). This does not complete human DSI validation.

Final evidence: `validation/research-comparison-final-20261016/REPORT.md`. Earlier `research-smoke*` directories are engineering checks; `research-comparison-20261016` was interrupted after a macOS closed-port handling defect and must not be reported as final research data.

## Human pilot redesign after participant feedback

The v1 volunteer sessions exposed confusing interactions. New browser-based web usability pilot: [study/WEB_PILOT_V2.md](study/WEB_PILOT_V2.md). It is independently versioned and stores results separately. It does not alter the recorded protocol benchmark or establish DSI/deception validity. SSH/scan human trials are paused.
