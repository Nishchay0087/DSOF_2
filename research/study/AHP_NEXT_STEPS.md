# Collect evaluator judgments

The six web sessions provide preliminary usability observations, not complete DSI measurements. This next step collects expert judgments about the relative importance of Engagement, Intelligence, Diversion and Persistence. Consistent AHP weights do not themselves validate DSI.

Arrange 3–5 distinct evaluators: faculty, security practitioners or experienced security students. Explain data retention and withdrawal arrangements. They should answer independently, without viewing participant ratings or other evaluators' answers. Do not suggest values. Keep the code-to-person mapping privately so one person is not counted twice.

For the first evaluator, run:

```sh
# From the repository root
.venv-mac/bin/python tools/research/ahp_evaluators.py run --evaluator R01
```

Open the printed URL on this Mac. Give the browser to the evaluator. The form explains the criteria and asks six pair comparisons. They choose their background, enter their own judgments, confirm voluntary use and click Save my judgments. No answers are prefilled.

The confirmation shows the evaluator's consistency ratio. The predeclared criterion is CR < 0.10. If higher, they can review their own reasoning and submit a revision; all previous submissions are preserved. Do not instruct them to choose values simply to produce a desired weight or pass the threshold.

After submission, press Ctrl+C in Terminal. Repeat with R02 and R03 for two different evaluators. R04 and R05 support additional evaluators. A returning evaluator must retain the original code.

After at least three genuine submissions, run:

```sh
.venv-mac/bin/python tools/research/ahp_evaluators.py analyze
```

Results go to `output/research/AHP_Results.json`. The analysis uses the latest revision per evaluator, the element-wise geometric mean of reciprocal matrices and the principal eigenvector. Accepted weights require every individual and the group to meet the consistency criterion. Inconsistent evaluators are not silently removed. Fewer than three submissions produce an awaiting-evaluators status with no weights. For a later analysis, specify a new `--output` filename to preserve earlier reports.

Judgments are stored locally in `research/study/ahp-evaluators/` and excluded from Git by default. Automated test fixtures are not evaluator evidence.

## Remaining research limits

The invoice pilot did not measure protected-asset actions or compatible intelligence evidence. Do not compute a complete DSI or a DSI-belief correlation from it. The next full validation requires an agreed instrumented task, separate pilot calibration, fixed score definitions and actual consented main sessions with compatible measurements. Preserve early voluntary endings, missing telemetry and failures honestly. Do not count repeated volunteers as independent new people.

The routed multi-service testbed, benign-redirection measurements and live policy evaluation remain incomplete. Existing automatic results are a protocol-replay pilot and did not demonstrate UCB1 superiority. Review the paper's achievable scope with the professor; do not turn the usability average or consistent AHP judgments into stronger effectiveness claims.
