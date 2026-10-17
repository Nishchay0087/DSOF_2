# Revised web usability pilot

This replaces the confusing human web exercise, not the existing automated benchmark. Do not continue the old S01/S02 commands for new volunteers. Their records and answers are preserved in `pilot-collection`. Do not mix these with v2 results or apply v1 DSI caps to v2.

## Start one session

The new schedule is already prepared. In Terminal:

```sh
# From the repository root
.venv-mac/bin/python tools/research/web_pilot.py run --session V2W01
```

Open the exact `http://127.0.0.1:PORT/study` address printed by Terminal in Chrome on this Mac. The number changes each time. Keep Terminal open. There is only one browser target; no reference surrogate, SSH commands or scan probes are needed.

Before handing over the browser, explain the study and your agreed data-retention/withdrawal arrangements. Obtain your professor's guidance on the participant process. The browser consent form does not replace any institutional requirements. The participant decides whether to consent. The ten-minute maximum begins only when they choose Agree and start, not when you run the command.

## What the participant does

They read the on-screen task: find invoice INV-1042, identify its client/status, and save a short review note if they can access it. They sign in using the displayed demonstration account (`demo` / `demo`). Working configurations support navigation, search, invoice details and persistent session notes. The task involves fictional invoices only.

They can click Finish task whenever they finish, cannot proceed, or wish to stop. They do not have to wait for the timer. They then answer the browser questionnaire and click Save my answers. Look for “Your answers have been saved.” Return to Terminal and press Ctrl+C to close that session's server. The saved completed record is retained.

If the timer expires, the next page request leads to the questionnaire. The browser does not automatically refresh an idle screen. Click any link to continue. An operator Ctrl+C before questionnaire completion retains the available evidence but is not a completed response. No program invents a missing answer.

Do not coach a participant into saying the page is genuine or identifying a honeypot. The questionnaire separates “broken website” from “deliberate decoy.” It does not preselect scores. The first-suspicion field accepts ordinary descriptions, such as “after the first login,” without converting them to invented minute values.

## Conditions and assignments — facilitator only

The prepared schedule has 18 assignments, balanced six per condition, randomized with fixed seed 162026. Each participant should take one session. `V2P01` is a pseudonymous ID, not a claim that a participant already exists. Keep the mapping to actual volunteers privately. Never assign the same person a second ID and count them twice as independent participants.

- Arm 0: a designed sign-in rejection condition with a proper form, help page and finish route. The task can be impossible; inability to proceed is an outcome, not a technical failure. Participants should not retry repeatedly just to fill time.
- Arm 1: working sign-in, dashboard, report search, details and saved review notes.
- Arm 2: the same working task plus a linked purchasing archive with account context.

These are new human-facing configurations, not the v1 benchmark's arms. Login success differs by arm; this can dominate ratings and task completion. This pilot diagnoses usability and perceived plausibility; it does not isolate a causal “deception gain.” There is no real-asset observation, diversion estimate or DSI output. The on-screen research disclosure also affects belief scores. SSH and scan human trials remain paused until meaningful service-specific tasks are built and reviewed.

After the first session, use `--session V2W02` for the next different volunteer, then V2W03 and so on. Do not choose an assignment after seeing a rating. An earlier lab volunteer may participate, but they must answer Yes to the prior-exposure question; analyze them separately from first-time volunteers. A small initial usability round is preferable to running everyone before checking the task.

## Where results are saved

`research/study/web-pilot-v2/sessions/V2W01.json` contains the assigned version and arm, consent, prior exposure, timing, observed interactions, finish reason and original questionnaire responses. Subsequent sessions have their own files. An existing ID cannot be overwritten. Browser assets and health checks do not count as actions. Password values are not stored; search strings and review notes are recorded, so use fictional content only. Session files are excluded from Git by default.

`status=completed` means the participant submitted the questionnaire, even when they finished early. `stop_reason` preserves whether they completed the task, could not proceed, chose to stop or reached the time limit. It is not evidence that the task succeeded or that deception worked. Task completion in the questionnaire is explicitly self-reported; note-save events can provide a separate observed measure.

There is no new human validation result until actual participants use this version. Existing paper numbers still refer to the old automatic protocol replay and remain unchanged. A revised research protocol, compatible telemetry and independent validation are required before using these sessions to support scientific effectiveness claims.

## Verification

The separate QA folder `tmp/web-pilot-v2-qa` contains developer checks, never participant evidence. Unit/integration checks use Flask's test client and do not claim human consent or responses. Run:

```sh
.venv-mac/bin/python -m pytest -q tests/test_human_web.py tests/test_research.py
```
