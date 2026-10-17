"""Rescore fixed held-out choices; never retrain or alter the original ledger."""
from pathlib import Path
import sys, json, sqlite3, hashlib
from collections import defaultdict
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from research.metrics import score, mean_ci, EQUAL, ORIGINAL
root = Path(__file__).resolve().parents[2]
source = root/'validation/research-comparison-final-20261016'
ahp_path = root/'output/research/AHP_Results.json'
out = root/'output/research/AHP_Posthoc_Sensitivity.json'
if out.exists():
    raise SystemExit('Output exists; preserve the existing analysis.')
ahp = json.loads(ahp_path.read_text())
caps = json.loads((source/'pilot_caps.json').read_text())
records = {r['id']: r for r in map(json.loads, (source/'outcomes.jsonl').read_text().splitlines())}
weights = {'equal': EQUAL, 'original': ORIGINAL, 'ahp': ahp['weights']}
c = sqlite3.connect(f'file:{source}/decisions.sqlite3?mode=ro', uri=True)
groups = defaultdict(list)
rows = c.execute("SELECT class, seed, policy, reward, outcome_id FROM decisions WHERE phase='heldout'").fetchall()
if not rows:
    raise RuntimeError('No heldout decisions found')
for cls, seed, policy, reward, oid in rows:
    r = records[oid]
    assert abs(score(r, caps[cls])['score']/100-reward)<1e-9
    for name, w in weights.items():
        groups[name,cls,policy,seed].append(score(r,caps[cls],w)['score'])
results = {}
for name in weights:
    results[name] = {}
    for cls in sorted({row[0] for row in rows}):
        results[name][cls] = {}
        for policy in sorted({row[2] for row in rows}):
            means = {str(seed):sum(v)/len(v) for (n,k,p,seed),v in groups.items() if (n,k,p)==(name,cls,policy)}
            assert len(means)==5
            results[name][cls][policy] = {'seed_means': means, **mean_ci(list(means.values()))}
inputs = [ahp_path,source/'pilot_caps.json',source/'outcomes.jsonl',source/'decisions.sqlite3']
data = {'method':'Post-hoc rescore of unchanged held-out choices trained under equal weights; no retraining or new network episodes. Reference actions are surrogate actions; not human DSI validation.', 'decisions':len(rows),'weights':weights,'results':results,'inputs':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
out.write_text(json.dumps(data,indent=2)+'\n')
lines = ['# Post-hoc AHP weighting sensitivity','',data['method'],'','| Class | Policy | Equal | Original | AHP |','|---|---|---:|---:|---:|']
for cls in results['equal']:
    for policy in results['equal'][cls]:
        vals = [results[n][cls][policy]['mean'] for n in weights]
        lines.append(f'| {cls} | {policy} | '+ ' | '.join(f'{v:.2f}' for v in vals)+' |')
lines += ['', 'These are the same selected outcomes under different scoring weights. Scores cannot establish how a policy trained with AHP rewards would behave. Each mean averages five seed means. Original records and participant responses are unchanged.']
out.with_suffix('.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
