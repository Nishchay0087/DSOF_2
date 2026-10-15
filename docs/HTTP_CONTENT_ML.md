# HTTP-content ML experiment

The system now has two independent learned models: the supplied XGBoost model
classifies 78 numerical flow statistics, and a character n-gram TF-IDF plus
logistic-regression classifier classifies parsed HTTP field content into BENIGN,
SQL_INJECTION or XSS. The existing HTTP rules also operate independently.
The HTTP model takes no rule-match indicators as input. Unit tests disable all
rules and verify that its prediction can independently create an alert.

## Data and reproducibility

`tools/train_http_model.py` authors a synthetic corpus of inert labeled strings.
It writes `datasets/http_content_synthetic.jsonl` and the model/manifest under
`artifacts/http_content/`. Each record carries its label, template family,
split and synthetic source. No live user content is used for training.
Template families are assigned to train/validation/test BEFORE expanding case,
numeric and word variants. Case-normalized text and family overlap are checked.
These families share attack syntax; this is not independent-source evaluation.
Repeated constant templates are retained within their own split, so expanded
row counts should not be interpreted as independent attack campaigns.

Run `.venv-mac/bin/python tools/train_http_model.py` to reproduce training.
The fitted vectorizer is trained only on the training partition. A threshold is
selected using validation to minimize benign false alarms, then maximize correct
attack labels, then prefer the higher threshold. The test partition is evaluated
once after that choice and never used to select the threshold.

Threshold: 0.85. Synthetic held-out test: 176 expanded examples; accuracy 95.45%,
SQL-injection recall 75%, XSS recall 100%, 0/112 benign false alarms. Eight SQL
examples were missed. Scores are saved in `validation/http-content-evaluation.json`.
These results do not establish real-world detection rates or calibrated probability.
Live smoke requests use familiar syntax and are not an accuracy benchmark.

## Runtime

Parsed path, query keys/values, supported form/JSON/text body fields are decoded
with at most two URL-decoding passes, then classified separately. Cookies and
authorization headers are not model inputs. Processing is capped at 128 fields,
4,096 characters per field and 32,768 total characters. Partial coverage is
reported. Raw content is transient: only class probabilities, field location,
threshold, coverage and model identity are persisted. The selected malicious
prediction must exceed the frozen threshold. A model failure is represented as
unavailable; it never becomes a fabricated BENIGN prediction.

The flow model remains under `ml`; HTTP content results use `http_ml`.
Alerts record `detection_components` and a display string such as
`HTTP ML + HTTP rule`. Historical records have no HTTP-model prediction.
SQL/XSS content detections select the existing Web Attacks strategy, preserving
specific SQL_INJECTION/XSS labels in the HTTP model result. This does not add new
classes to the original XGBoost artifact. Cleartext parsed HTTP only is supported;
TLS interception and encrypted HTTPS inspection are not implemented.

## Tests

Keep the backend and capture helper running, then execute:

```sh
cd /Users/nishchay/Documents/dsop_re
.venv-mac/bin/python tools/verify_http_ml.py
```

Unlike `verify_live.py`, this test fails unless captured SQL and XSS requests
produce the correct HTTP ML label above threshold, and the benign control
produces BENIGN without an alert. It also checks the actual honeypot/session/DSI
pipeline using the existing controlled-test registration. Results are written
to `validation/http-ml-live.json`. These tests execute no payload content.

The Traffic table uses `http_ml` as its primary prediction column. Flows with
no stored HTTP result show Not inspected; inference failures show Unavailable.
Click a row for full evidence, including the separate original flow prediction.
Historical flow-only records are not relabeled.
