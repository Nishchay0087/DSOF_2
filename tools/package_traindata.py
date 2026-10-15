"""Package the user-selected model and reconstructed preprocessing for runtime."""
from pathlib import Path
import hashlib
import json
import shutil
import joblib
import numpy as np
import xgboost as xgb
ROOT = Path(__file__).resolve().parents[1]
def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    report = json.loads((ROOT/'validation/traindata/evaluation.json').read_text())
    source = ROOT/'traindata/xgboost_cicids2017_model.pkl'
    if digest(source) != report['source_sha256'][source.name]:
        raise ValueError('Source model changed since evaluation')
    bundle = joblib.load(ROOT/'validation/traindata/reconstructed_preprocessing.joblib')
    if bundle['provenance'] != report['source_sha256']:
        raise ValueError('Preprocessing provenance differs from evaluation')
    target = ROOT/'artifacts/traindata'
    target.mkdir(exist_ok=True)
    booster = joblib.load(source).get_booster()
    booster.save_model(target/'model.ubj')
    check = xgb.Booster(); check.load_model(target/'model.ubj')
    sample = xgb.DMatrix(np.zeros((1, len(report['features'])), dtype=np.float32))
    np.testing.assert_array_equal(booster.predict(sample), check.predict(sample))
    shutil.copyfile(ROOT/'validation/traindata/reconstructed_preprocessing.joblib', target/'preprocessing.joblib')
    manifest = {'features':report['features'], 'labels':report['classes'],
                'source_model_sha256':digest(source),
                'sha256':{name:digest(target/name) for name in ['model.ubj','preprocessing.joblib']},
                'evaluation':{key:report[key] for key in ['accuracy','test_rows','classification_report','confusion_matrix']}}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Packaged verified 78-feature model and reconstructed scaler')
if __name__ == '__main__': main()
