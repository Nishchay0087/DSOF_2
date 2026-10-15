"""Selected model preprocessing parity and measured additional feature semantics."""
from pathlib import Path
import json
import shutil
import joblib
import numpy as np
import pandas as pd
import pytest
import xgboost as xgb
from dsof.flows import Flow, Packet, NEW_FEATURE_NAMES
from dsof.model import Model

ROOT = Path(__file__).resolve().parents[1]

def test_selected_model_scaled_inference_matches_supplied_booster():
    model = Model(ROOT/'artifacts/traindata')
    assert model.status()['ready'], model.status()
    assert model.status()['feature_count'] == 78
    rows = pd.read_csv(ROOT/'traindata/combine.csv', nrows=20)
    rows.columns = rows.columns.str.strip()
    scaler = joblib.load(ROOT/'artifacts/traindata/preprocessing.joblib')['scaler']
    source = joblib.load(ROOT/'traindata/xgboost_cicids2017_model.pkl').get_booster()
    expected = source.predict(xgb.DMatrix(scaler.transform(rows[model.schema])))
    for i, row in rows.iterrows():
        result = model.predict({name: float(row[name]) for name in model.schema})
        np.testing.assert_array_equal(list(result['probabilities'].values()), expected[i])
        assert result['prediction'] == model.labels[int(expected[i].argmax())]
        assert result['preprocessing'] == 'reconstructed_standard_scaler'


def test_new_bundle_rejects_tampered_scaler(tmp_path):
    for p in (ROOT/'artifacts/traindata').iterdir():
        shutil.copyfile(p, tmp_path/p.name)
    (tmp_path/'preprocessing.joblib').write_bytes(b'invalid')
    status = Model(tmp_path).status()
    assert not status['ready']
    assert 'integrity mismatch' in status['error']


def test_measured_full_features_bulk_flags_and_directions():
    flow = Flow(Packet(1, 'a', 'b', 1234, 80, 'TCP', b'ab', flags=2|8|32|128, header_length=24))
    for ts in (1.1, 1.2, 1.3):
        flow.add(Packet(ts, 'a', 'b', 1234, 80, 'TCP', b'ab', flags=16))
    flow.add(Packet(1.4, 'b', 'a', 80, 1234, 'TCP', b'123456', flags=8|4|64, header_length=20))
    values = flow.features(NEW_FEATURE_NAMES)
    assert list(values) == NEW_FEATURE_NAMES
    assert values['Total Backward Packets'] == 1
    assert values['Total Length of Bwd Packets'] == 6
    assert values['Down/Up Ratio'] == .25
    assert values['Fwd Header Length.1'] == 84
    for name in ('SYN Flag Count','RST Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags'):
        assert values[name] == 1
    assert values['Bwd URG Flags'] == 0
    assert values['Fwd Avg Bytes/Bulk'] == 8
    assert values['Fwd Avg Packets/Bulk'] == 4
    assert values['Fwd Avg Bulk Rate'] == pytest.approx(8/.3)
    assert values['Bwd Avg Bytes/Bulk'] == 0
    assert values['Subflow Bwd Bytes'] == 6
    assert values['Subflow Fwd Packets'] == 4
    assert values['Avg Bwd Segment Size'] == 6
    assert all(np.isfinite(list(values.values())))


def test_opposite_payload_breaks_bulk_run():
    flow = Flow(Packet(1,'a','b',1,2,'TCP',b'x'))
    flow.add(Packet(1.1,'a','b',1,2,'TCP',b'x'))
    flow.add(Packet(1.2,'b','a',2,1,'TCP',b'x'))
    for ts in (1.3,1.4,1.5):
        flow.add(Packet(ts,'a','b',1,2,'TCP',b'x'))
    assert flow.features(NEW_FEATURE_NAMES)['Fwd Avg Bytes/Bulk'] == 0


def test_benign_label_never_triggers_ml_deployment(tmp_path):
    from dsof.config import Config
    from dsof.store import Store
    from dsof.engine import Engine
    store = Store(tmp_path/'app.db')
    engine = Engine(Config(capture=False, db_path=tmp_path/'app.db'), store)
    try:
        engine.model.predict = lambda features: {'prediction':'BENIGN', 'probability':1.0}
        flow = Flow(Packet(1,'127.0.0.1','127.0.0.1',40000,9090,'TCP',b'ordinary'))
        engine._finish(flow,'test')
        assert store.get('flows',flow.id)['ml']['prediction'] == 'BENIGN'
        assert store.list('alerts') == []
    finally:
        engine.stop()
        store.close()
