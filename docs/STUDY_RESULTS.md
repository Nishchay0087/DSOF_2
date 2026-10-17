# Aggregate study results

The browser usability pilot and AHP exercise were separate from the scripted
protocol benchmark. Completed forms and participant recordings remain private.

## Web usability pilot

Six volunteers completed one session each. Assignment counts were one rejecting
login, three working-report interfaces and two reports-plus-archive interfaces.
One volunteer reported prior exposure. Earlier assisted sessions used another
procedure and are not pooled with this group.

The median plausibility rating was 3.5/5. Four participants reported completing
the task, one partly completed it and one did not. Five sessions contained a
saved-note event. Two selected broken website, two neither broken nor honeypot,
and two unsure. These observations do not establish that all six were deceived.

The small, unequal groups support usability feedback only. Missing protected-asset
and compatible intelligence telemetry prevented calculation of research DSI.

## AHP priorities

Three evaluators supplied reciprocal comparison matrices: one self-identified
faculty member and two experienced students. The latest individual consistency
ratios were 0.0489, 0.0933 and 0.0694 for R01, R02 and R03. They made five, three
and one submissions respectively; revisions remain retained privately.

| Criterion | Group weight |
|---|---:|
| Engagement | 0.225107 |
| Intelligence | 0.326472 |
| Diversion | 0.370090 |
| Persistence | 0.078331 |

Matrices were combined using the elementwise geometric mean and principal
eigenvector. Group CR was 0.006995. Two evaluators prioritised diversion and one
engagement. Internal consistency does not establish agreement or score validity.

## Post-hoc sensitivity

Rescoring the same 4,500 held-out choices with AHP weights gave UCB1/fixed-A2 means
of 86.14/86.13 for web, 82.07/82.06 for SSH and 62.08/62.09 for scan. Choices and
learner states were unchanged; these are not policies retrained with AHP rewards.
The scan rate-rule ranking changed. No UCB1 superiority is established.

`tools/research/ahp_posthoc.py` reproduces the calculation when the private local
AHP analysis is available at its documented input path. It is not part of the
public quick start. Public policy replay can be rerun independently with equal
weights using the research guide.
