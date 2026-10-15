from pathlib import Path
import json,shutil
from urllib.parse import quote
from dsof.http_model import HTTPContentModel
from dsof.http_detect import HTTPStream

ROOT=Path(__file__).resolve().parents[1]

def test_classifier_independent_of_rules_and_does_not_return_payload():
    model=HTTPContentModel()
    assert model.status()['ready']
    for value,label in [("' OR 1=1 --",'SQL_INJECTION'),('<script>alert(1)</script>','XSS'),('ordinary books','BENIGN')]:
        result=model.predict_fields([(value,'query.value[0]')])
        assert result['prediction']==label
        assert result['attack']==(label!='BENIGN')
        assert value not in json.dumps(result)


def test_parser_runs_content_model_without_rule_features(monkeypatch):
    import dsof.http_detect as http
    monkeypatch.setattr(http,'_RULES',())
    stream=HTTPStream(classifier=HTTPContentModel().predict_fields)
    payload=('GET /?q='+quote('<img src=x onerror=alert(1)>')+' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode()
    result=stream.feed(1,payload)[0]
    assert result['rules']==[]
    assert result['http_ml']['prediction']=='XSS' and result['http_ml']['attack']


def test_http_model_limits_and_integrity(tmp_path):
    model=HTTPContentModel()
    result=model.predict_fields([('hello'*1000,'field')]*200)
    assert result['coverage']=='partial' and result['inspected_fields']<=128
    for name in ('manifest.json','model.joblib'):
        shutil.copyfile(ROOT/'artifacts/http_content'/name,tmp_path/name)
    (tmp_path/'model.joblib').write_bytes(b'broken')
    assert not HTTPContentModel(tmp_path).status()['ready']


def test_training_family_and_normalized_text_splits_are_disjoint():
    data=[json.loads(line) for line in (ROOT/'datasets/http_content_synthetic.jsonl').read_text().splitlines()]
    for key in ('family','text'):
        sets=[{r[key].lower() for r in data if r['split']==split} for split in ('train','validation','test')]
        assert not sets[0]&sets[1] and not sets[0]&sets[2] and not sets[1]&sets[2]


def test_http_ml_alone_can_create_alert(tmp_path,monkeypatch):
    from dsof.config import Config
    from dsof.engine import Engine
    from dsof.store import Store
    from dsof.flows import Flow,Packet
    store=Store(tmp_path/'test.db');engine=Engine(Config(capture=False,db_path=tmp_path/'test.db'),store)
    try:
        monkeypatch.setattr(engine.model,'predict',lambda _: {'prediction':'BENIGN','probability':1.0})
        monkeypatch.setattr(engine.pots,'ensure',lambda *args,**kwargs: {'id':'fixture','state':'listening'})
        flow=Flow(Packet(1,'127.0.0.1','127.0.0.1',40000,9090,'TCP',b'test fixture'))
        result=engine.http_model.predict_fields([("' OR 1=1 --",'query.value[0]')])
        engine.requests[flow.id]=[{'rules':[],'http_ml':result}]
        engine._finish(flow,'unit_fixture')
        alert=store.list('alerts')[0]
        assert alert['detection_components']==['HTTP ML']
        assert alert['http_ml']['prediction']=='SQL_INJECTION'
        assert alert['ml']['prediction']=='BENIGN'
    finally:
        engine.stop();store.close()
