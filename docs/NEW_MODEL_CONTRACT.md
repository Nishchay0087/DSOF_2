# Active 78-feature model — 14 October 2026

The user selected `traindata/xgboost_cicids2017_model.pkl`. The active runtime
bundle lives in `artifacts/traindata/`: `model.ubj`, `preprocessing.joblib`,
and `manifest.json`. The source model remains unchanged. UBJ stores the loaded
booster without depending on obsolete sklearn wrapper attributes. Startup
checks both bundle hashes, exact feature order, scaler dimensions/statistics,
label mapping, classifier objective and class count before permitting inference.

## Input and prediction

The exact 78 names/order and ten original labels are in `manifest.json`.
Runtime input is measured raw numeric data in that order, converted to float64,
transformed by the reconstructed fitted StandardScaler, and passed to the
booster. Class selection is argmax of the original multiclass probabilities.
Probabilities are not calibrated or replaced by HTTP rule results.
`BENIGN` is the benign class. The eight additional policy entries cover the
new named attack classes; DDoS already existed. HTTP web indicators continue
to generate separately attributed Web Attacks alerts because the model lacks
that class. No missing feature is padded with invented values.

## Added measurements

Shared measurements follow the legacy conventions in FEATURE_CONTRACT.md.
All features are computed from bounded online state; packets are not retained.

- Reverse packet count and payload-byte total come from reverse observations.
- SYN, RST, URG, CWR (CSV spelling `CWE`) and ECE count observed flags. Forward
  and backward PSH/URG counts use the first-packet direction convention.
- Down/Up Ratio is reverse count / forward count (zero if unavailable).
- Average directional segment size is mean observed transport payload size.
- `Fwd Header Length.1` is the duplicate forward transport-header sum.
- Subflow directional packet/byte averages divide measured totals by the
  observed burst count, using the existing gap greater than one second rule.
- Active/Idle Std use sample standard deviations of measured intervals.
- A bulk is a directional run of at least four nonempty payload packets,
  separated by gaps no greater than one second and interrupted by opposite
  payload after the run began. Average bytes and packets divide qualifying
  totals by qualifying runs. Bulk rate divides bytes by accumulated within-run
  duration in seconds. No qualifying run or zero duration returns zero.

These are explicit measurement conventions, not a claim of exact equivalence
to an unidentified CICFlowMeter build. Original packet captures and extractor
version/settings are still required to establish that equivalence.

## Evidence and limits

Offline preprocessing/split reconstruction produced 97.1297% accuracy on
388,394 test rows, with an exact confusion-matrix match to the supplied image.
Macro F1 is 0.7287. This is a reproduced random-row split, not measured live
accuracy. The source script retains Destination Port because it removes
columns before trimming whitespace; runtime faithfully preserves that input.
Changing the feature requires separately training and evaluating a new model.

Regression tests compare runtime scaled predictions with the supplied booster,
verify tampered-preprocessing rejection, calculate flags/directions/bulks from
known packets, and retain legacy artifact integrity checks. The test report is
`validation/pytest-new-model.xml`. Real network acceptance is recorded separately
and labels controlled tests explicitly. Old persisted records retain their
original model hash and class output; they are historical evidence.

Reproduction: run `tools/validate_traindata.py` with the project Python/OpenMP
environment, then `tools/package_traindata.py`. Both scripts preserve the
supplied source files. Dataset replay defaults to `traindata/combine.csv`,
strips CSV header whitespace and records `Label` as ground truth; strict input
validation rejects malformed rows rather than silently repairing them.
