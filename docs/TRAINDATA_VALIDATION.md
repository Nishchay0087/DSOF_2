# Supplied training package validation — 14 October 2026

The new `traindata` package was evaluated using `tools/validate_traindata.py`.
The script reconstructs preprocessing and the exact stratified random split
from the supplied `train.py`; it does not retrain or replace either model.

## Reproduced result

- CSV: 2,214,469 rows; 2,212,030 after removing missing/infinite rows;
  1,941,970 after duplicate removal.
- Training split: 1,553,576 rows. Test split: 388,394 rows.
- Accuracy: **97.1297187907%**.
- Macro F1: **0.728701126**. Overall accuracy alone masks substantial differences
  between classes, including low Bot precision.
- Every cell of the reconstructed confusion matrix matches the supplied
  `traindata/confusion_matrix.png` on visual comparison.

The reconstructed StandardScaler and LabelEncoder are saved in
`validation/traindata/reconstructed_preprocessing.joblib`. Feature order,
class order, source hashes, library versions, per-class metrics, and confusion
matrix are in `validation/traindata/evaluation.json`.

## Compatibility and remaining evidence

This package is for a **different model** from the running application's model:

| Property | Running model | New training package |
|---|---|---|
| File | artifacts/xgb_model.joblib | traindata/xgboost_cicids2017_model.pkl |
| Feature count | 52 | 78 |
| Class count | 7 grouped classes | 10 classes |
| Preprocessing | Original provenance unavailable | Reconstructed StandardScaler |
| Web Attacks / Brute Force | Both present | Both absent |

The new classes are BENIGN, Bot, DDoS, DoS GoldenEye, DoS Hulk,
DoS Slowhttptest, DoS slowloris, Heartbleed, Infiltration and PortScan.
These files cannot establish the training procedure of the active 52-feature
artifact. The user subsequently selected this new model. The application now uses a separate 78-feature bundle; see [active model contract](NEW_MODEL_CONTRACT.md).

The supplied training script attempts to drop Destination Port before stripping
column whitespace. The CSV uses ` Destination Port`, so that feature remains.
Reconstruction intentionally preserves this behavior to match the saved model;
changing it would require training a new model and evaluating it separately.

The original script saves only the estimator, losing fitted preprocessing.
The reconstructed bundle restores this package's reproducible offline inference.
Its saved estimator also triggers an upstream XGBoost serialization-version
warning; inference through the booster succeeds and reproduces the supplied
matrix. Original training dependency versions remain unknown.

These results validate the supplied random row split, not temporal or live
network generalization. The source packet-to-feature extraction code/version
and settings are still absent. The live extractor has now been extended to all 78 named measurements with analytic regression tests; training-extractor equivalence remains unverified. Zero-filling the missing features would invalidate its input contract.

To resolve provenance for the currently active model, supply the training and
preprocessing code that produced `artifacts/xgb_model.joblib` (52 features,
7 grouped labels). The new package is sufficient to reproduce its own offline
result and does not require a separately saved original scaler for that purpose.
