"""Read-only original-artifact loader and strict inference boundary."""
from __future__ import annotations

import hashlib
import json
import math
from numbers import Real
from pathlib import Path
import threading
import time

from .flows import FEATURE_NAMES, NEW_FEATURE_NAMES


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Model:
    def __init__(self, artifact_dir):
        self.artifact_dir = Path(artifact_dir)
        self._lock = threading.RLock()
        self._model = None
        self._scaler = None
        self.benign_labels = {"Normal Traffic", "BENIGN"}
        self.schema = []
        self.labels = []
        self._status = {"ready": False, "sha256": None, "hash": None, "error": None,
                        "feature_contract": "experimental_unverified", "preprocessing": "raw_numeric_unverified",
                        "probability_calibrated": False, "warnings": [
                            "Training script, fitted preprocessing, extractor version and original timeout conventions were not supplied. Raw numeric inference has unverified training parity.",
                            "Label indices follow supplied label_classes.json array; original label encoder was not supplied.",
                            "Model probability calibration is not established. Stored metrics have no reproducible evaluation split provenance.",
                        ]}
        try:
            self._load()
        except Exception as exc:
            self._status["error"] = f"Model unavailable: {type(exc).__name__}: {exc}. Check artifacts and pinned dependencies; do not retrain or overwrite originals."

    def _load(self):
        import joblib
        import numpy as np
        import sklearn
        import xgboost
        if (self.artifact_dir / "manifest.json").exists():
            self._load_bundle()
            return
        model_path = self.artifact_dir / "xgb_model.joblib"
        required = [model_path, self.artifact_dir / "feature_schema.json", self.artifact_dir / "label_classes.json"]
        missing = [str(p) for p in required if not p.is_file()]
        if missing:
            raise ValueError("Missing required files: " + ", ".join(missing))
        digest = sha256_file(model_path)
        self._status.update(sha256=digest, hash=digest)
        baseline_path = self.artifact_dir.parent / "validation" / "model_baseline.json"
        if baseline_path.is_file():
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            if baseline.get("sha256") != digest:
                raise ValueError("Original model SHA-256 differs from validation/model_baseline.json")
            self._status["original_hash_unchanged"] = True
        else:
            self._status["original_hash_unchanged"] = None
            self._status["warnings"].append("No prior SHA-256 baseline is available for this artifact directory.")
        schema = json.loads(required[1].read_text(encoding="utf-8-sig"))
        if not isinstance(schema, list) or schema != FEATURE_NAMES:
            raise ValueError("feature_schema.json must exactly match the documented 52 feature names and order")
        labels = json.loads(required[2].read_text(encoding="utf-8-sig"))
        if not isinstance(labels, list) or len(labels) != 7 or len(set(labels)) != 7 or not all(isinstance(x, str) and x for x in labels):
            raise ValueError("label_classes.json must be the seven unique class labels in encoded index order")
        loaded = joblib.load(model_path)  # Trusted local serialized artifact only.
        if int(getattr(loaded, "n_features_in_", -1)) != len(schema):
            raise ValueError("Model feature count does not match schema")
        if list(getattr(loaded, "classes_", [])) != list(range(len(labels))):
            raise ValueError("Encoded model classes must match label array indices 0..6")
        booster_names = loaded.get_booster().feature_names
        if booster_names is not None and booster_names != schema:
            raise ValueError("Booster feature names disagree with schema")
        self._model, self.schema, self.labels = loaded, schema, labels
        self._status.update(ready=True, feature_count=len(schema), feature_names=list(schema), labels=list(labels),
                            versions={"joblib": joblib.__version__, "numpy": np.__version__, "sklearn": sklearn.__version__, "xgboost": xgboost.__version__})
        metrics_path = self.artifact_dir / "model_metrics.json"
        if metrics_path.is_file():
            try:
                self._status["supplied_metrics"] = {"source": "artifacts/model_metrics.json", "dataset": "unspecified original training/evaluation split; not verified", "values": json.loads(metrics_path.read_text(encoding="utf-8-sig"))}
            except (OSError, ValueError) as exc:
                self._status["warnings"].append(f"Optional stored metrics could not be read: {exc}")

    def _load_bundle(self):
        import joblib
        import numpy as np
        import xgboost as xgb
        manifest = json.loads((self.artifact_dir / "manifest.json").read_text())
        if set(manifest['sha256']) != {'model.ubj', 'preprocessing.joblib'}:
            raise ValueError('Bundle must declare model and preprocessing hashes')
        for name, digest in manifest['sha256'].items():
            if Path(name).name != name or sha256_file(self.artifact_dir / name) != digest:
                raise ValueError(f"Bundle integrity mismatch: {name}")
        schema, labels = manifest['features'], manifest['labels']
        if schema != NEW_FEATURE_NAMES or len(labels) != 10 or len(set(labels)) != 10:
            raise ValueError("New model schema or label contract mismatch")
        bundle = joblib.load(self.artifact_dir / 'preprocessing.joblib')
        scaler = bundle['scaler']
        if (bundle['features'] != schema or list(bundle['label_encoder'].classes_) != labels
                or scaler.n_features_in_ != len(schema)
                or list(scaler.feature_names_in_) != schema
                or not np.isfinite(scaler.mean_).all() or not np.isfinite(scaler.scale_).all()
                or (scaler.scale_ <= 0).any()):
            raise ValueError("Preprocessing does not match model contract")
        booster = xgb.Booster()
        booster.load_model(self.artifact_dir / 'model.ubj')
        booster.set_param({'nthread': 2})
        config = json.loads(booster.save_config())['learner']
        if (booster.num_features() != len(schema)
                or int(config['learner_model_param']['num_class']) != len(labels)
                or config['objective']['name'] != 'multi:softprob'):
            raise ValueError("Booster dimensions/objective do not match contract")
        self._model, self._scaler, self.schema, self.labels = booster, scaler, schema, labels
        self._status.update(ready=True, sha256=manifest['source_model_sha256'], hash=manifest['source_model_sha256'],
            feature_count=len(schema), feature_names=schema, labels=labels,
            preprocessing='reconstructed_standard_scaler', feature_contract='experimental_unverified',
            original_hash_unchanged=True, bundle_hashes=manifest['sha256'],
            warnings=['Preprocessing and offline split reproduced; live extractor parity remains unverified.',
                      'Destination Port was retained by the supplied training script.',
                      'Probability calibration and temporal generalization are unverified.'],
            supplied_metrics={'source':'reconstructed supplied random test split', 'values':manifest['evaluation']})

    def status(self):
        with self._lock:
            return json.loads(json.dumps(self._status))

    def validate(self, features):
        if not self._status["ready"]:
            raise ValueError(self._status["error"] or "Model is not ready")
        if not isinstance(features, dict):
            raise ValueError("features must be a JSON object keyed by all exact model feature names")
        missing = sorted(set(self.schema) - set(features))
        extra = sorted(set(features) - set(self.schema), key=str)
        if missing or extra:
            raise ValueError(f"Feature contract mismatch: missing={missing}; unexpected={extra}")
        values = []
        for name in self.schema:
            value = features[name]
            try:
                finite_number = not isinstance(value, bool) and isinstance(value, Real) and math.isfinite(float(value))
            except (OverflowError, TypeError, ValueError):
                finite_number = False
            if not finite_number:
                raise ValueError(f"{name}: expected a finite real number; strings, booleans, missing values, NaN and infinity are rejected")
            if abs(value) > 3.4028234e38:
                raise ValueError(f"{name}: value exceeds finite float32 model input range")
            if name == "Destination Port" and (value != int(value) or not 0 <= value <= 65535):
                raise ValueError("Destination Port: expected integer 0..65535")
            if name in {"Total Fwd Packets", "Total Backward Packets", "FIN Flag Count", "PSH Flag Count", "ACK Flag Count", "SYN Flag Count", "RST Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "act_data_pkt_fwd"} and value != int(value):
                raise ValueError(f"{name}: expected an integer packet count")
            if name.startswith("Init_Win_bytes_") and (value != int(value) or not -1 <= value <= 65535):
                raise ValueError(f"{name}: expected raw unscaled TCP window 0..65535 or documented unavailable sentinel -1")
            if not name.startswith("Init_Win_bytes_") and value < 0:
                raise ValueError(f"{name}: negative values are unsupported by the documented live feature contract")
            values.append(float(value))
        return values

    def predict(self, features):
        import numpy as np
        with self._lock:
            values = self.validate(features)
            started = time.perf_counter()
            array = np.asarray([values], dtype=np.float64 if self._scaler is not None else np.float32)
            try:
                if self._scaler is not None:
                    import pandas as pd
                    import xgboost as xgb
                    array = self._scaler.transform(pd.DataFrame(array, columns=self.schema))
                    if not np.isfinite(array).all():
                        raise ValueError("Preprocessing produced nonfinite input")
                    probabilities = self._model.predict(xgb.DMatrix(array))[0]
                    encoded = int(np.argmax(probabilities))
                else:
                    probabilities = self._model.predict_proba(array)[0]
                    encoded = int(self._model.predict(array)[0])
                if len(probabilities) != len(self.labels) or not np.isfinite(probabilities).all() or encoded not in range(len(self.labels)):
                    raise ValueError("Model produced invalid probabilities or class index")
            except Exception as exc:
                message = f"Model inference failed: {type(exc).__name__}: {exc}. Inspect original artifacts and dependency compatibility; restart after fixing the cause."
                self._status.update(ready=False, error=message)
                raise ValueError(message) from exc
            result = {"prediction": self.labels[encoded], "encoded_prediction": encoded,
                      "probability": float(probabilities[encoded]),
                      "probabilities": {label: float(probabilities[index]) for index, label in enumerate(self.labels)},
                      "feature_contract": "experimental_unverified", "probability_calibrated": False,
                      "duration_ms": (time.perf_counter() - started) * 1000,
                      "preprocessing": self._status["preprocessing"],
                      "model_sha256": self._status["sha256"]}
            return result
