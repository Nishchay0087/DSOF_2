"""Four-component DSI, with unavailable telemetry represented as unknown."""
import math
from datetime import datetime
from .store import utcnow

WEIGHTS = {'engagement':.35,'intelligence':.30,'diversion':.20,'persistence':.15}
VERSION = 'dsof-eidp-v1'

def calculate_eidp(session, *, prior_sessions, protected_connections=None, coverage=None):
    def norm(key, denominator):
        value = session.get(key)
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f'Invalid measured input: {key}')
        return min(value/denominator,1)
    if type(prior_sessions) is not int or prior_sessions < 0:
        raise ValueError('prior_sessions must be a nonnegative integer')
    if protected_connections is not None and (type(protected_connections) is not int or protected_connections < 0):
        raise ValueError('protected_connections must be a nonnegative integer or unknown')
    components = {
        'engagement':round(100*(.5*norm('duration_seconds',120)+.5*norm('interaction_count',20)),4),
        'intelligence':round(100*(.6*norm('distinct_actions',5)+.4*norm('max_depth',4)),4),
        'diversion':None if protected_connections is None else round(100/(1+protected_connections),4),
        'persistence':round(100*min(prior_sessions/3,1),4),
    }
    complete = all(v is not None for v in components.values())
    return {'version':VERSION,'score':round(sum(WEIGHTS[k]*v for k,v in components.items()),4) if complete else None,
            'components':components,'weights':WEIGHTS,'provisional':session['state']=='active',
            'inputs':{k:session[k] for k in ('duration_seconds','interaction_count','distinct_actions','max_depth')},
            'prior_sessions_24h':prior_sessions,'protected_connections_during_session':protected_connections,
            'coverage':coverage,'evaluated_at':utcnow(),
            'meaning':'Diversion is this observed honeypot connection divided by it plus protected-service connections during this session; not causal proof of prevention',
            'reason':None if complete else 'Diversion unavailable: configure protected ports and continuous capture without known queue loss'}


def evaluate_session(store, session, protected_connections=None, coverage=None):
    start = datetime.fromisoformat(session['started_at']).timestamp()
    prior = 0
    for row in store.list('sessions',10000,remote_address=session['remote_address'],origin=session['origin']):
        if row['id'] == session['id']:
            continue
        timestamp = datetime.fromisoformat(row['started_at']).timestamp()
        if start-86400 <= timestamp < start:
            prior += 1
    result = calculate_eidp(session,prior_sessions=prior,protected_connections=protected_connections,coverage=coverage)
    result['persistence_sample_limit'] = 10000
    return result
