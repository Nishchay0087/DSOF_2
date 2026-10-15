"""Synthetic feedback fixtures; never evidence of live detection accuracy."""
import pytest

from dsof.dsi import calculate_dsi, DEFAULT_WEIGHTS, DEFAULT_NORMALIZERS
from dsof.store import Store
from dsof.strategy import StrategyOptimizer


@pytest.fixture
def optimizer(tmp_path):
    store = Store(tmp_path / 'strategy.sqlite3')
    yield StrategyOptimizer(store)
    store.close()


def evidence(opt, service, score, *, origin='live', state='completed', level='Beginner', provisional=False):
    alert = opt.store.put('alerts', {'origin': origin, 'classification': 'Port Scanning',
                                   'attacker_profile': {'version': 'behavior-v1', 'level': level}})
    dsi = calculate_dsi(dict(duration_seconds=120, interaction_count=20, distinct_actions=5, max_depth=4))
    dsi.update(score=score, provisional=provisional)
    return opt.store.put('sessions', {'origin': origin, 'alert_id': alert['id'], 'service': service,
                                     'state': state, 'dsi': dsi})


def choose(opt, origin='live'):
    return opt.choose('Port Scanning', {'level': 'Beginner'}, 'web', origin,
                      DEFAULT_WEIGHTS, DEFAULT_NORMALIZERS)


def test_no_history_and_insufficient_samples_preserve_policy(optimizer):
    assert choose(optimizer)['selected'] == 'web'
    for _ in range(2):
        evidence(optimizer, 'ssh', 90)
    assert choose(optimizer)['reason'] == 'configured_policy'


def test_completed_comparable_feedback_changes_future_selection(optimizer):
    for _ in range(3):
        evidence(optimizer, 'web', 40)
        evidence(optimizer, 'ssh', 80)
    decision = choose(optimizer)
    assert decision['selected'] == 'ssh'
    assert decision['reason'] == 'historical_dsi'
    assert choose(optimizer, 'manual_test')['selected'] == 'web'
    assert len(optimizer.rankings()) == 2


def test_ineligible_sessions_cannot_influence_selection(optimizer):
    for options in ({'origin':'manual_test'}, {'state':'active'}, {'state':'interrupted'},
                    {'provisional':True}):
        for _ in range(3):
            evidence(optimizer, 'ssh', 99, **options)
    assert optimizer.rankings() == []
    assert choose(optimizer)['selected'] == 'web'


def test_profile_and_score_policy_are_not_mixed(optimizer):
    for _ in range(3):
        evidence(optimizer, 'web', 40)
        evidence(optimizer, 'ssh', 99, level='Advanced')
        session = evidence(optimizer, 'database', 99)
        session['dsi']['normalizers']['duration_seconds'] = 1
        optimizer.store.put('sessions', session)
    assert choose(optimizer)['selected'] == 'web'


def test_small_improvements_do_not_switch_and_updates_do_not_duplicate(optimizer):
    for _ in range(3):
        evidence(optimizer, 'web', 40)
        session = evidence(optimizer, 'ssh', 44)
        optimizer.store.put('sessions', session)
    assert choose(optimizer)['selected'] == 'web'
    assert all(r['samples'] == 3 for r in optimizer.rankings())


def test_profile_uses_only_recent_same_origin_source_evidence(optimizer):
    for port in range(20):
        optimizer.store.put('flows', {'origin':'live', 'src':'192.0.2.1',
                                     'dst':f'192.0.2.{port % 3 + 2}', 'dport':port})
    assert optimizer.profile('192.0.2.1', 'live')['level'] == 'Advanced'
    assert optimizer.profile('192.0.2.1', 'manual_test')['observed_flows'] == 0
    optimizer.store.put('flows', {'origin':'live', 'src':'192.0.2.9', 'dst':'192.0.2.2',
                                 'dport':80, 'timestamp':'2000-01-01T00:00:00.000+00:00'})
    assert optimizer.profile('192.0.2.9', 'live')['observed_flows'] == 0


@pytest.mark.parametrize('system, expected', [('Darwin','lo0'), ('Linux','lo'), ('Windows',r'\Device\NPF_Loopback')])
def test_platform_capture_defaults(monkeypatch, system, expected):
    from dsof.config import Config
    from dsof.capture import is_loopback_interface
    monkeypatch.setattr('dsof.config.platform.system', lambda: system)
    assert Config().interfaces == [expected]
    assert is_loopback_interface(expected)

def test_four_component_feedback_requires_matching_monitoring_scope(optimizer):
    from dsof.evaluation import calculate_eidp
    scope={'protected_ports':[9090],'interfaces':['lo0']}
    for _ in range(3):
        for service,score in [('web',30),('ssh',70)]:
            session=evidence(optimizer,service,score)
            session['evaluation']=calculate_eidp({'duration_seconds':120,'interaction_count':20,
                'distinct_actions':5,'max_depth':4,'state':'completed'},prior_sessions=0,
                protected_connections=0,coverage=scope)
            session['evaluation']['score']=score  # Explicit synthetic policy fixture.
            optimizer.store.put('sessions',session)
    result=optimizer.choose('Port Scanning',{'level':'Beginner'},'web','live',
                            DEFAULT_WEIGHTS,DEFAULT_NORMALIZERS,scope)
    assert result['selected']=='ssh' and result['score_basis']=='dsof-eidp-v1'
    different={**scope,'protected_ports':[8080]}
    assert optimizer.choose('Port Scanning',{'level':'Beginner'},'web','live',
                            DEFAULT_WEIGHTS,DEFAULT_NORMALIZERS,different)['selected']=='web'
