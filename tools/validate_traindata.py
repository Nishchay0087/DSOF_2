"""Reconstruct the supplied training split and audit its saved model, without retraining."""
from pathlib import Path
import hashlib
import json
import platform
import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'traindata'
OUT = ROOT / 'validation' / 'traindata'

def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print('Reading source CSV', flush=True)
    df = pd.read_csv(SOURCE / 'combine.csv')
    original_rows = len(df)
    # Preserve the exact supplied script order, including its whitespace/drop bug.
    leaky = ['Destination Port', 'Source IP', 'Destination IP', 'Source Port', 'Timestamp']
    dropped = [c for c in leaky if c in df.columns]
    df.drop(columns=dropped, inplace=True)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    finite_rows = len(df)
    df.drop_duplicates(inplace=True)
    labels = LabelEncoder()
    y = labels.fit_transform(df['Label'])
    features = list(df.drop(columns=['Label']).columns)
    X = df[features]
    print(f'Reconstructing split: {len(df)} rows, {len(features)} features', flush=True)
    train_idx, test_idx = train_test_split(np.arange(len(df)), test_size=.2, random_state=42, stratify=y)
    scaler = StandardScaler().fit(X.iloc[train_idx])
    scaled = scaler.transform(X.iloc[test_idx])
    model = joblib.load(SOURCE / 'xgboost_cicids2017_model.pkl')
    booster = model.get_booster()
    if booster.num_features() != len(features):
        raise ValueError('Model feature count does not match reconstructed training inputs')
    # Booster inference avoids incompatible sklearn wrapper attributes in older pickles.
    booster.set_param({'nthread': 4})
    predictions = np.argmax(booster.predict(xgb.DMatrix(scaled)), axis=1)
    report = {
        'kind': 'Reconstructed supplied random split; not independent live accuracy',
        'original_rows': original_rows, 'rows_after_dropna': finite_rows,
        'rows_after_deduplication': len(df), 'train_rows': len(train_idx), 'test_rows': len(test_idx),
        'feature_count': len(features), 'features': features, 'classes': labels.classes_.tolist(),
        'dropped_columns_before_stripping': dropped,
        'leakage_columns_retained_after_stripping': [c for c in leaky if c in features],
        'accuracy': accuracy_score(y[test_idx], predictions),
        'classification_report': classification_report(y[test_idx], predictions, target_names=labels.classes_, output_dict=True, zero_division=0),
        'confusion_matrix': confusion_matrix(y[test_idx], predictions).tolist(),
        'source_sha256': {name: sha256(SOURCE / name) for name in ['train.py', 'combine.csv', 'xgboost_cicids2017_model.pkl']},
        'versions': {'python': platform.python_version(), 'numpy': np.__version__, 'pandas': pd.__version__, 'sklearn': sklearn.__version__, 'xgboost': xgb.__version__},
        'limits': ['Scaler and encoder reconstructed, not original saved preprocessing artifacts.',
                   'Same input order and split assumed; original training environment unavailable.',
                   'Destination Port drop happens before whitespace stripping in supplied script.',
                   'Random row split does not establish temporal or external-network generalization.',
                   '78-feature model requires its own scaler and full feature contract; legacy 52-feature inputs are incompatible.',
                   'Original packet-to-feature extractor provenance remains unavailable.'],
    }
    (OUT / 'evaluation.json').write_text(json.dumps(report, indent=2))
    joblib.dump({'scaler': scaler, 'label_encoder': labels, 'features': features, 'provenance': report['source_sha256']}, OUT / 'reconstructed_preprocessing.joblib')
    print(json.dumps({k: report[k] for k in ['original_rows','rows_after_deduplication','feature_count','classes','accuracy','leakage_columns_retained_after_stripping']}, indent=2), flush=True)

if __name__ == '__main__':
    main()
