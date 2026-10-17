import copy
import pytest
from research.policies import Policy, NAMES
from research.metrics import score, ahp, EQUAL, exact_paired_p

def record(**kw):
    return dict({'status':'completed','actions':10,'duration':10.,'reference_actions':2,'artefacts':[True,True,False,False]},**kw)

def test_unknown_coverage_not_perfect_diversion():
    r=record(); r['reference_actions']=None
    assert score(r,{'actions':10,'seconds':10})['score'] is None
    r['status']='failed'
    assert score(r,{'actions':10,'seconds':10})['score']==0

def test_components_and_bounds():
    s=score(record(),{'actions':10,'seconds':10})
    assert s['components']['intelligence']==50
    assert s['components']['diversion']==pytest.approx(100*10/12)
    assert s['score']==pytest.approx((100+50+100*10/12+100)/4)
    with pytest.raises(ValueError): score(record(),{'actions':0,'seconds':10})
    with pytest.raises(ValueError): score(record(),{'actions':10,'seconds':10},{k:.5 for k in EQUAL})

def test_ucb_explores_then_learns_without_test_updates():
    p=Policy('ucb1',42)
    first=[]
    for _ in range(300):
        a=p.choose(0); first.append(a); p.update(a,[.1,.5,.9][a],0)
    assert first[:3]==[0,1,2]
    assert p.counts[2]>p.counts[1]>p.counts[0]
    state=copy.deepcopy(p.snapshot())
    assert all(p.choose(0,True)==2 for _ in range(20))
    assert p.snapshot()==state

def test_q_is_terminal_contextual_update():
    p=Policy('q_learning',1); p.update(2,1,1)
    assert p.q[1][2]==.1 and p.q[0]==[0.,0.,0.]
    p.update(2,1,1); assert p.q[1][2]==pytest.approx(.19)

def test_all_policies_frozen_do_not_mutate_learned_state():
    for name in NAMES:
        p=Policy(name,9); p.update(0,.3,0); before=copy.deepcopy(p.snapshot())
        for i in range(30): assert p.choose(i%3,True) in (0,1,2)
        assert p.snapshot()==before

def test_ahp_rejects_missing_and_inconsistent_evidence():
    equal=[[[1.]*4 for _ in range(4)] for _ in range(3)]
    r=ahp(equal); assert r['accepted'] and r['group']['weights']==pytest.approx(EQUAL)
    bad=copy.deepcopy(equal); bad[0][0][1]=9; bad[0][1][0]=1/9
    assert not ahp(bad)['accepted']
    with pytest.raises(ValueError): ahp(equal[:1])

def test_five_seed_exact_test_cannot_claim_significance():
    assert exact_paired_p([1,2,3,4,5])==.0625
    assert exact_paired_p([0,0,0,0,0])==1

def test_human_forms_are_blank_balanced_and_analysis_refuses_fabrication(tmp_path):
    import csv
    from argparse import Namespace
    from tools.research.human_study import prepare, analyze
    folder=tmp_path/'study'; prepare(folder)
    with (folder/'schedule.csv').open() as f: rows=list(csv.DictReader(f))
    assert len(rows)==18
    for kind in ('web','ssh','scan'):
        assert [sum(r['class']==kind and r['arm']==str(a) for r in rows) for a in range(3)]==[2,2,2]
    with (folder/'responses.csv').open() as f: responses=list(csv.DictReader(f))
    assert all(not r['belief_real_1_to_5'] for r in responses)
    with pytest.raises(ValueError,match='incomplete'):
        analyze(Namespace(study=folder,caps=folder/'nonexistent.json'))
    assert not (folder/'human_results.json').exists()


def test_recorded_benchmark_integrity():
    """Audit the actual committed-workspace run without opening network listeners."""
    import hashlib
    import json
    import sqlite3
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    out=root/'validation/research-comparison-final-20261016'
    if not out.exists(): pytest.skip('Run the local benchmark to produce evidence')
    manifest=json.loads((out/'manifest.json').read_text())
    for filename,digest in manifest['evidence_hashes'].items():
        assert hashlib.sha256((out/filename).read_bytes()).hexdigest()==digest
    rows=[json.loads(s) for s in (out/'outcomes.jsonl').read_text().splitlines()]
    assert len(rows)==11340 and len({r['id'] for r in rows})==len(rows)
    train={r['seed'] for r in rows if r['phase']=='train'}
    held={r['seed'] for r in rows if r['phase']=='heldout'}
    assert not train & held
    db=sqlite3.connect(out/'decisions.sqlite3')
    assert db.execute('select count(*) from decisions').fetchone()[0]==22500
    lookup={r['id']:r for r in rows}
    caps=json.loads((out/'pilot_caps.json').read_text())
    for kind,phase,arm,reward,outcome_id in db.execute('select class,phase,arm,reward,outcome_id from decisions'):
        r=lookup[outcome_id]
        assert r['class']==kind and r['phase']==phase and r['arm']==arm
        assert reward==pytest.approx(score(r,caps[kind])['score']/100)
    for kind,seed,policy in db.execute('select distinct class,seed,policy from decisions'):
        states=[json.loads(r[0]) for r in db.execute("select state from decisions where class=? and seed=? and policy=? and phase='heldout' order by episode",(kind,seed,policy))]
        assert all(s==states[0] for s in states)
    db.close()
