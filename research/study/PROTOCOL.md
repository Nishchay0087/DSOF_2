# Notice: human trials paused for redesign

The initial assisted sessions revealed usability problems. For new **web usability** sessions use `WEB_PILOT_V2.md` and `tools/research/web_pilot.py`. Do not continue this v1 protocol as if it were validated. SSH and scan human trials remain paused. Preserve existing recordings. The original protocol follows for traceability.

# Human validation pilot — facilitator guide

Status: prepared, not conducted. No volunteers, judgments, approval or results are claimed. This evaluates local fixed-response decoys, not a production network or the full routed Cowrie testbed. The researcher must arrange participants and obtain the department's decision on any required ethics/permission process before recruitment. Do not describe that process as already approved.

## What to arrange

- At least six adult volunteers with basic security-testing experience for 18 main sessions: three sessions per person, one per class, about 20 minutes each. This is about six hours of participant testing, plus breaks and questionnaires. The supplied schedule balances each arm twice within each class and randomizes class order. Six participants are a small exploratory sample, not 18 independent people.
- A separate pilot with at least three recorded sessions per class to set normalization caps before the main study. Prefer separate pilot volunteers. Never use the fast agent's millisecond caps for human sessions.
- Three to five evaluators to judge the importance of the DSI components, independently of participant answers. `ahp.csv` has three blank evaluator rows; add up to two genuine evaluators if available.
- Faculty review of the task instructions, permitted targets, observation fields, consent and debrief. Keep identifiers/contact/consent records separately from pseudonymous analysis files. Agree an actual retention/deletion date.

Do not recruit or message anyone automatically. All testing is voluntary. Compensation or marks must not depend on participation, being fooled, or giving favorable ratings.

## Consent information — complete before signing

Study title: Local evaluation of adaptive honeypot service responses.
Research contact: Nishchay Aggarwal, nishchay.aggarwal2024@vitstudent.ac.in.
Faculty contact: N. Harini, harini.n@vit.ac.in.

You will interact with an isolated local security lab. Some services may be simulated. We do not reveal each service's exact configuration until after your final session so we can study perceptions. Activity timestamps, bounded requests/commands, responses and questionnaire answers will be recorded under a participant code. Use only supplied synthetic credentials; do not type personal passwords, tokens or personal information. No command you submit to these emulators executes on the operating system. You may stop or skip any task without penalty. The facilitator will explain how to withdraw your identifiable data before aggregation.

Expected time: three 20-minute sessions, short questionnaires and breaks. Risks include minor frustration and logging of material you enter; avoid personal data. These sessions do not establish real-world intrusion protection. Records are accessible only to the authorized research team until the agreed deletion date. Any public evidence must be anonymized and reviewed for accidental personal information.

Participant code: ______  Date: ______  Retention/deletion date: ______
I have had the chance to ask questions; I understand the recording, partial disclosure and withdrawal arrangements; I voluntarily agree: ______
Facilitator signature: ______  Department permission reference, if required: ______

Do not store signatures in the results CSV or commit them to Git.

## Participant task briefing

Use only the localhost ports provided by the facilitator. Explore the assigned service using browser requests, SSH exec commands, or individual TCP probes, according to its class. Try to identify service contents and obtain access to synthetic information. You may also explore the second target supplied for that session. Use a maximum of one request per second for manual probes. Do not target other ports, outside hosts, the dashboard or real files. No DoS, credential harvesting or external downloads. The lab provides fixed virtual responses. Do not reveal arm identities or scores, and do not coach participants toward responses expected to increase DSI.

The deliberately restricted protocol support itself can reveal the decoy. Record this as a limitation, not as participant error. Giving consent that some services may be simulated can reduce belief scores; report this disclosure rather than concealing it.

## Exact operator steps on this Mac

Open Terminal; keep the normal dashboard/capture helper as they are. This study creates independent temporary loopback listeners, with no sudo and no dashboard token.

```sh
# From the repository root
```

Main forms already exist in `research/study/collection`. To create a separate pilot folder:

```sh
.venv-mac/bin/python tools/research/human_study.py prepare --output research/study/pilot-collection
```

Use that folder's schedule to run at least three completed sessions per class. Pilot sessions use the same task and observation window. For each actual participant, obtain consent first, then run:

```sh
.venv-mac/bin/python tools/research/human_study.py capture \
  --study research/study/pilot-collection --session S01 --consent --minutes 20
```

Replace S01 with the assigned session ID. `--consent` is an operator confirmation of actual signed consent; the program cannot obtain consent for you. The command prints the specific ports, URL or SSH example for that session. Keep this facilitator Terminal private because it identifies the service class. Give the participant only the permitted target information. The SSH password is a disposable synthetic value such as `demo`; each SSH invocation uses one fixed command, not an interactive shell. Example additional commands: `pwd`, `ls`, `cat welcome.txt`, `id`. Do not introduce commands selectively for a particular arm.

The collector runs for 20 minutes and saves actual server events. Ctrl+C ends early and marks the session interrupted; retain it in missing/attrition reporting. The normal timeout must finish for a main completed session. An empty recording is not evidence of deception.

After the pilot, lock the 95th-percentile action/time caps before starting any main sessions:

```sh
.venv-mac/bin/python tools/research/human_study.py calibrate \
  --pilot-study research/study/pilot-collection \
  --output research/study/human-pilot-caps.json
```

Then run each main session according to `research/study/collection/schedule.csv`:

```sh
.venv-mac/bin/python tools/research/human_study.py capture \
  --study research/study/collection --session S01 --consent --minutes 20
```

Record the actual completion time and consent in the schedule. Do not change assignments after seeing outcomes. Provide breaks. Do not tell participants which configuration they saw before they finish all three sessions.

## Questionnaire immediately after each session

Enter only the participant's own responses in `research/study/collection/responses.csv`:

1. Belief that the target behaved like a genuine operational service: 1 definitely simulated, 2 probably simulated, 3 uncertain, 4 probably genuine, 5 definitely genuine.
2. Did you suspect a honeypot? yes/no.
3. If yes, approximately how many minutes from the start did you first suspect it?
4. What specific response or behavior raised suspicion? Free text.
5. Optional usability/context notes.

Set `consent_confirmed` to `yes` only where actual consent exists. Never fill beliefs with guessed, model-generated, or facilitator-suggested values. Debrief after the final session: show the decoy nature, explain omitted arm details and provide the withdrawal contact.

## AHP evaluator sheet

E = interaction volume; I = observed credential/tool/payload/post-access artefact diversity; D = action share toward the decoy rather than the local reference target; P = elapsed time between observed events. D is a surrogate in this local pilot, not measured protection of real assets.

Ask each evaluator independently: “For judging deception success, how much more important is the row component than the column component?” Enter six judgments in `ahp.csv`: E/I, E/D, E/P, I/D, I/P, D/P. Use 1 equal, 3 moderate, 5 strong, 7 very strong, 9 extreme; 2/4/6/8 intermediate. If the second component is more important, use a reciprocal such as `1/3`.

No judgments are prefilled. The analyzer builds reciprocal matrices, computes individual and geometric-mean group consistency ratios and accepts only ratios below 0.10. If inconsistent, ask evaluators to reconsider their own judgments; never adjust entries to get desired weights.

## Analysis after real collection

```sh
.venv-mac/bin/python tools/research/human_study.py analyze \
  --study research/study/collection \
  --caps research/study/human-pilot-caps.json
```

The tool refuses blank AHP sheets, missing consent, duplicate responses, mismatched IDs and main sessions predating locked pilot caps. It reports exclusions and refuses to estimate correlations with fewer than three completed participants. Three is a software floor, not adequate statistical power; use the planned six or more.

Outputs include AHP consistency, Spearman correlations against actual belief scores, and 5,000 participant-cluster bootstrap replicates for AHP DSI, equal/original weight scores, dwell time and action count. It also estimates paired differences in correlations. Constant outcomes have undefined correlations, not invented zeros. Review class/order confounding and small-sample uncertainty. Do not claim significance by choosing a favorable result after inspecting the data.

This initial analyzer does not implement validated Roy/Aradi reproductions, causal routing evaluation, or a full known-groups/fingerprinting analysis. The necessary compatible measurements and literature-specific definitions still need to be agreed. Server logs do not count failed connection attempts; any gateway-level claim requires additional telemetry. Report these boundaries in the paper.
