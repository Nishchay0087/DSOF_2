#!/usr/bin/env python3
"""Collect live response-dependent outcomes, then replay six policies fairly.

Offline policy replay is explicit: each policy sees only its selected outcome.
Unselected counterfactual outcomes are used only for analysis, never learning.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import platform
import sqlite3
import sys
import time
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from research.lab import Lab, CLASSES, PARAMETERS
from research.metrics import score, EQUAL, ORIGINAL, mean_ci, exact_paired_p
from research.policies import Policy, NAMES


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,value): path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')


def analyze(out, records, caps, config):
    db=sqlite3.connect(out/'decisions.sqlite3')
    db.execute('CREATE TABLE decisions(class TEXT, seed INTEGER, policy TEXT, phase TEXT, episode INTEGER, arm INTEGER, reward REAL, outcome_id TEXT, state TEXT)')
    summaries=[]; comparisons=[]
    for kind in config['classes']:
        for seed in config['seeds']:
            train=[records[kind,seed,'train',i] for i in range(config['train'])]
            held=[records[kind,seed,'heldout',i] for i in range(config['heldout'])]
            for name in NAMES:
                policy=Policy(name,seed+NAMES.index(name)*100003)
                for phase,rows in [('train',train),('heldout',held)]:
                    before=policy.snapshot(); rewards=[]; diversions=[]; failures=0; arms=[]; gaps=[]
                    # Hindsight comparator is the best FIXED arm on this phase, not a causal oracle.
                    best_fixed=max(sum(score(r[a],caps[kind])['score'] for r in rows) for a in range(3))
                    for i,row in enumerate(rows):
                        bucket=row[0]['bucket']; arm=policy.choose(bucket,frozen=phase=='heldout'); selected=row[arm]
                        result=score(selected,caps[kind]); reward=result['score']/100
                        if phase=='train': policy.update(arm,reward,bucket)
                        rewards.append(reward*100); arms.append(arm); failures+=selected['status']!='completed'
                        diversions.append(result['components']['diversion'] if result['components'] else 0.)
                        gaps.append(max(score(r,caps[kind])['score'] for r in row)-reward*100)
                        db.execute('INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?,?)',(kind,seed,name,phase,i,arm,reward,selected['id'],json.dumps(policy.snapshot())))
                    if phase=='heldout': assert policy.snapshot()==before, 'Held-out data changed the model'
                    summaries.append({'class':kind,'seed':seed,'policy':name,'phase':phase,'mean_dsi':float(np.mean(rewards)),
                        'mean_surrogate_diversion':float(np.mean(diversions)), 'failures':failures,'episodes':len(rows),
                        'hindsight_fixed_arm_gap_reward_units':(best_fixed-sum(rewards))/100,
                        'selected_arms':[arms.count(a) for a in range(3)], 'terminal_state':policy.snapshot()})
        for phase in ('train','heldout'):
            for name in NAMES:
                group=[r for r in summaries if r['class']==kind and r['phase']==phase and r['policy']==name]
                comparisons.append({'class':kind,'phase':phase,'policy':name,
                    'dsi':mean_ci([r['mean_dsi'] for r in group]),
                    'surrogate_diversion':mean_ci([r['mean_surrogate_diversion'] for r in group]),
                    'failures':sum(r['failures'] for r in group), 'episodes':sum(r['episodes'] for r in group)})
    db.commit(); db.close()
    contrasts=[]
    for kind in config['classes']:
        for name in NAMES[:-1]:
            diff=[]
            for seed in config['seeds']:
                def mean(p): return next(r['mean_dsi'] for r in summaries if r['class']==kind and r['seed']==seed and r['policy']==p and r['phase']=='heldout')
                diff.append(mean('ucb1')-mean(name))
            contrasts.append({'class':kind,'baseline':name,'difference':mean_ci(diff),'paired_exact_p':exact_paired_p(diff)})
    previous=0
    for rank,item in enumerate(sorted(contrasts,key=lambda x:x['paired_exact_p'])):
        previous=max(previous,min(1.,item['paired_exact_p']*(len(contrasts)-rank)))
        item['holm_p_all_contrasts']=previous
    dump(out/'seed_results.json',summaries)
    dump(out/'summary.json',{'comparisons':comparisons,'contrasts':contrasts,'primary_weights':EQUAL,
                           'weights_status':'equal weights; AHP not collected','inference_unit':'seed',
                           'provenance':'offline policy replay of real loopback episodes'})
    # Weight sensitivity is descriptive; it does not retroactively retune policies.
    sensitivity=[]
    weights=[('equal',EQUAL),('original',ORIGINAL)]
    for component in EQUAL:
        for delta in (-.10,-.05,.05,.10):
            w=EQUAL.copy(); w[component]+=delta; total=sum(w.values()); w={k:v/total for k,v in w.items()}
            weights.append((f'{component}{delta:+.2f}',w))
    for kind in config['classes']:
        rows=[row for (c,s,p,i),row in records.items() if c==kind and p=='heldout']
        for label,w in weights:
            means=[float(np.mean([score(r[a],caps[kind],w)['score'] for r in rows])) for a in range(3)]
            sensitivity.append({'class':kind,'weights':label,'values':w,'arm_means':means,'best_arm':int(np.argmax(means))})
    dump(out/'weight_sensitivity.json',sensitivity)
    lines=['# Measured localhost policy-replay benchmark','',
        'This is a controlled protocol pilot, not completion of the professor’s gateway experiment or human validation. ',
        'Actual HTTP, SSH and TCP exchanges were recorded. Six policies were replayed against the same per-seed outcome panels; each learner received only its chosen arm’s reward. '
        'All arms were measured to allow matched comparison and a hindsight fixed-arm gap. It is an offline replay, not deployment of learned routing policies.', '',
        f"Training: {config['train']} episodes per policy/class/seed; held out: {config['heldout']}; seeds: {config['seeds']}. Pilot caps were fixed before collecting the main panels.", '',
        'DSI uses equal weights pending actual AHP judgments. Diversion is action share relative to a local reference surrogate, not protection of real assets. '
        'Persistence is measured wall time and is affected by the fixed worker load and protocol latency. '
        'Attack classes are assigned by the runner; detector and gateway performance are not tested. '
        'SSH arms are fixed Paramiko emulators, not Cowrie. No false-redirection or fingerprint-resistance claim is made.', '',
        '| Class | Policy | Held-out DSI mean (95% t CI across seeds) | Surrogate diversion | Failures |','|---|---|---|---|---|']
    for r in comparisons:
        if r['phase']!='heldout': continue
        ci=r['dsi']['ci95']; ci_text=f'{ci[0]:.2f}, {ci[1]:.2f}' if ci else 'not estimable'
        lines.append(f"| {r['class']} | {r['policy']} | {r['dsi']['mean']:.2f} ({ci_text}) | {r['surrogate_diversion']['mean']:.2f} | {r['failures']}/{r['episodes']} |")
    lines += ['', 'CIs are not clipped to the score range. Five seeds give limited precision. Exact paired two-sided sign-flip tests with five seeds cannot achieve p < 0.05; all 15 held-out contrasts use Holm correction. '
              'Report negative results; this run cannot establish that UCB1 is superior.', '',
              '## Reproduction and evidence', '', '`manifest.json` records settings and source hashes; `outcomes.jsonl` contains protocol events; `decisions.sqlite3` links every choice/reward/state to an outcome; '
              '`seed_results.json`, `summary.json`, `weight_sensitivity.json` contain analysis. Admission failures stay in the denominator with zero reward. '
              'Frozen learners neither update nor explore; random and rule baselines retain their fixed behavior. '
              'The experimental rate-bucket rule is not the current production service selector. ', '',
              '## Still required for the paper', '', 'Consented human sessions and evaluator AHP matrices; the contained routed testbed; Cowrie arm comparison if claiming Cowrie; independent detection evaluation; benign-redirection measurement. '
              'Do not describe scripted records as human judgments or claim completed end-to-end E4/E5.']
    (out/'REPORT.md').write_text('\n'.join(lines)+'\n')


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--train',type=int,default=200); parser.add_argument('--heldout',type=int,default=50)
    parser.add_argument('--pilot',type=int,default=10); parser.add_argument('--workers',type=int,default=6)
    parser.add_argument('--seeds',type=int,nargs='+',default=[11,23,37,53,71])
    parser.add_argument('--classes',nargs='+',choices=CLASSES,default=list(CLASSES))
    args=parser.parse_args()
    if min(args.train,args.heldout,args.pilot,args.workers)<=0 or len(set(args.seeds))!=len(args.seeds) or min(args.seeds)<0:
        parser.error('Positive counts and unique nonnegative seeds required')
    out=args.output.resolve(); out.mkdir(parents=True,exist_ok=False)
    import logging
    transport_log=logging.getLogger('paramiko'); transport_log.addHandler(logging.FileHandler(out/'transport.log')); transport_log.propagate=False; transport_log.setLevel(logging.WARNING)
    config=vars(args).copy();config['output']=str(out)
    config.update({'agent':PARAMETERS,'epsilon':.1,'alpha':.1,'primary_weights':EQUAL,
                   'python':platform.python_version(),'platform':platform.platform(),
                   'collection_started_utc':datetime.now(timezone.utc).isoformat(),
                   'source_hashes':{str(p.relative_to(ROOT)):digest(p) for p in list((ROOT/'research').glob('*.py'))+[Path(__file__).resolve()]}})
    dump(out/'manifest.json',config)
    records={}; pilot={c:[] for c in args.classes}; lab=Lab().start(); start=time.monotonic()
    try:
        with (out/'outcomes.jsonl').open('w') as stream, ThreadPoolExecutor(max_workers=args.workers) as pool:
            def collect(phase):
                tasks=[]
                for kind in args.classes:
                    for seed in ([991] if phase=='pilot' else args.seeds):
                        count=args.pilot if phase=='pilot' else args.train if phase=='train' else args.heldout
                        for i in range(count):
                            # Hash-derived streams avoid overlapping train/test seeds at arbitrary episode counts.
                            stimulus=int.from_bytes(hashlib.sha256(f'{kind}:{seed}:{phase}:{i}'.encode()).digest()[:8],'big')
                            for arm in range(3): tasks.append((kind,seed,phase,i,arm,stimulus))
                # A fixed shuffle avoids measuring all of one arm or class in a single time block.
                import random
                random.Random(817+len(phase)).shuffle(tasks)
                def run(task):
                    kind,seed,phase,i,arm,stimulus=task
                    record=lab.episode(kind,arm,stimulus)
                    record.update({'id':f'{kind}:{seed}:{phase}:{i}:{arm}','run_seed':seed,'phase':phase,'episode':i})
                    return task,record
                for n,(task,record) in enumerate(pool.map(run,tasks),1):
                    kind,seed,phase,i,arm,_=task
                    stream.write(json.dumps(record,allow_nan=False)+'\n')
                    if phase=='pilot': pilot[kind].append(record)
                    else: records.setdefault((kind,seed,phase,i),[None]*3)[arm]=record
                    if n%300==0: stream.flush(); print(f'{phase}: {n}/{len(tasks)} actual protocol episodes',flush=True)
            collect('pilot')
            caps={}
            for kind,rows in pilot.items():
                valid=[r for r in rows if r['status']=='completed']
                if not valid: raise RuntimeError(f'No successful pilot episodes for {kind}')
                caps[kind]={'actions':max(1.,float(np.percentile([r['actions'] for r in valid],95))),
                            'seconds':max(.001,float(np.percentile([r['duration'] for r in valid],95)))}
            dump(out/'pilot_caps.json',caps); print('Pilot complete; caps locked.',flush=True)
            collect('train'); collect('heldout')
        analyze(out,records,caps,config)
    finally:
        lab.close()
        dump(out/'server_counters.json',lab.counters)
    config['elapsed_seconds']=time.monotonic()-start
    config['evidence_hashes']={p.name:digest(p) for p in out.iterdir() if p.is_file() and p.name!='manifest.json'}
    dump(out/'manifest.json',config)
    print(f'Complete: {out / "REPORT.md"}',flush=True)

if __name__=='__main__': main()
