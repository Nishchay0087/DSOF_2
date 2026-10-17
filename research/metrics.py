"""Proposed DSI v2, deliberately separate from dashboard DSI v1."""
import math
import numpy as np
from scipy import stats

COMPONENTS = ('engagement', 'intelligence', 'diversion', 'persistence')
EQUAL = dict.fromkeys(COMPONENTS, .25)
ORIGINAL = dict(zip(COMPONENTS, (.35, .30, .20, .15)))


def score(record, caps, weights=EQUAL):
    if set(weights) != set(COMPONENTS) or any(not math.isfinite(v) or v < 0 for v in weights.values()) or not math.isclose(sum(weights.values()), 1):
        raise ValueError('Weights must be finite, nonnegative and sum to one')
    if any(not math.isfinite(caps[k]) or caps[k] <= 0 for k in ('actions', 'seconds')):
        raise ValueError('Positive pilot caps required')
    if record['status'] != 'completed':
        return {'score': 0., 'components': None, 'failure_penalty': True}
    m, d, real = record['actions'], record['duration'], record['reference_actions']
    if any(not math.isfinite(x) or x < 0 for x in (m, d)) or (real is not None and (not math.isfinite(real) or real < 0)):
        raise ValueError('Invalid telemetry')
    artefacts = record['artefacts']
    if len(artefacts) != 4 or any(type(x) is not bool for x in artefacts):
        raise ValueError('Four observed artefact flags required')
    parts = dict(zip(COMPONENTS, (
        100*min(1, math.log1p(m)/math.log1p(caps['actions'])),
        25*sum(artefacts),
        None if real is None or m+real == 0 else 100*m/(m+real),
        100*min(1, d/caps['seconds']))))
    return {'score': None if None in parts.values() else sum(weights[k]*parts[k] for k in COMPONENTS),
            'components': parts, 'failure_penalty': False}


def ahp(matrices):
    matrices = np.asarray(matrices, dtype=float)
    if matrices.ndim != 3 or matrices.shape[1:] != (4,4) or not 3 <= len(matrices) <= 5:
        raise ValueError('Supply 3–5 actual evaluator matrices, each 4x4')
    allowed = np.array([1/x for x in range(2,10)] + list(range(1,10)))
    for m in matrices:
        if not np.isfinite(m).all() or not np.allclose(np.diag(m), 1) or not np.allclose(m*m.T, 1):
            raise ValueError('Matrices must be finite, positive, reciprocal, with unit diagonal')
        if not np.all(np.min(abs(m[...,None]-allowed), axis=-1) < 1e-7):
            raise ValueError('Use the Saaty 1–9 scale or reciprocals')
    def solve(m):
        vals, vecs = np.linalg.eig(m)
        index = np.argmax(vals.real)
        v = np.abs(vecs[:,index].real); v /= v.sum()
        cr = max(0., float((vals[index].real-4)/3/.9))
        return {'weights': dict(zip(COMPONENTS, map(float,v))), 'consistency_ratio': cr}
    individual = [solve(m) for m in matrices]
    group = solve(np.exp(np.mean(np.log(matrices), axis=0)))
    return {'individual':individual, 'group':group,
            'accepted': all(x['consistency_ratio'] < .1 for x in individual+[group])}


def mean_ci(values):
    a = np.asarray(values, dtype=float)
    mean = float(a.mean())
    half = float(stats.t.ppf(.975,len(a)-1)*stats.sem(a)) if len(a)>1 else None
    return {'mean':mean, 'sd':float(a.std(ddof=1)) if len(a)>1 else None,
            'ci95': [mean-half,mean+half] if half is not None else None, 'n_seeds':len(a)}


def exact_paired_p(differences):
    import itertools
    d = np.asarray(differences)
    observed = abs(d.mean())
    distribution = [abs(np.mean(d*np.array(s))) for s in itertools.product((-1,1), repeat=len(d))]
    return float(np.mean(np.array(distribution) >= observed-1e-12))
