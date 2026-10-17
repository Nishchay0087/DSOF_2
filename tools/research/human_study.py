#!/usr/bin/env python3
"""Prepare blank study forms, record actual sessions, analyze genuine responses."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
import time
import numpy as np
from scipy.stats import spearmanr
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from research.lab import Lab
from research.metrics import COMPONENTS, EQUAL, ORIGINAL, ahp, score


def write_csv(path,fields,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def prepare(out):
    out.mkdir(parents=True,exist_ok=False)
    rows=[]
    # Six volunteers each complete three classes. Each arm appears twice per class.
    for p in range(6):
        classes=['web','ssh','scan'];random.Random(710+p).shuffle(classes)
        for order,kind in enumerate(classes):
            arm=(p+('web','ssh','scan').index(kind))%3
            rows.append({'session_id':f'S{p*3+order+1:02d}','participant_id':f'P{p+1:02d}',
                         'order':order+1,'class':kind,'arm':arm,'consent_confirmed':'','completed_at':''})
    write_csv(out/'schedule.csv',list(rows[0]),rows)
    fields=['session_id','participant_id','consent_confirmed','belief_real_1_to_5','suspected_honeypot_yes_no','first_suspicion_minute','suspicion_reason','notes']
    write_csv(out/'responses.csv',fields,[{k:r[k] for k in ('session_id','participant_id')} for r in rows])
    fields=['evaluator_id','E_over_I','E_over_D','E_over_P','I_over_D','I_over_P','D_over_P']
    write_csv(out/'ahp.csv',fields,[{'evaluator_id':f'R{i}'} for i in range(1,4)])
    print(out)


def capture(args):
    with (args.study/'schedule.csv').open() as f: schedule=list(csv.DictReader(f))
    row=next((r for r in schedule if r['session_id']==args.session),None)
    if row is None: raise ValueError('Session is not in the schedule')
    if not args.consent: raise ValueError('Confirm actual consent using --consent only after signed consent')
    out=args.study/'sessions';out.mkdir(exist_ok=True)
    path=out/(args.session+'.json')
    if path.exists(): raise ValueError('Existing session must not be overwritten')
    lab=Lab(audit=True).start(); kind=row['class']; arm=int(row['arm'])
    started=time.time(); ended_normally=False
    print(f'Session {args.session}; assigned target ports: {lab.endpoints[kind,arm]}',flush=True)
    print(f'Second target (HTTP reference surrogate): http://127.0.0.1:{lab.endpoints["reference",0][0]}/',flush=True)
    if kind=='web': print(f'Open http://127.0.0.1:{lab.endpoints[kind,arm][0]}/login?user=admin&password=demo',flush=True)
    if kind=='ssh': print(f'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=accept-new -p {lab.endpoints[kind,arm][0]} demo@127.0.0.1 whoami\nUse synthetic password demo. Only fixed command responses; no interactive shell.',flush=True)
    print('Recording actual server events. Ctrl+C stops early; normal limit is '+str(args.minutes)+' minutes.',flush=True)
    try:
        while time.time()-started < args.minutes*60: time.sleep(.2)
        ended_normally=True
    except KeyboardInterrupt: pass
    finally:
        lab.close()
        events=[e for e in lab.audit if (e['class']==kind and e['arm']==arm) or e['class']=='reference']
        decoy=[e for e in events if e['class']!='reference']; texts=[e['action'] for e in decoy]
        artefacts=[any('password' in a for a in texts),bool(decoy),any('/search' in a for a in texts),
                   any(('dashboard' in e['response'].lower() or (kind=='ssh' and e['action']!='password authentication [credential value omitted]' and 'unavailable' not in e['response'])) for e in decoy)]
        record={'session_id':row['session_id'],'participant_id':row['participant_id'],'class':kind,'arm':arm,
                'consent_confirmed':True,'status':'completed' if ended_normally else 'interrupted',
                'actions':len(decoy),'duration':max(e['timestamp'] for e in events)-min(e['timestamp'] for e in events) if events else 0.,
                'reference_actions':len(events)-len(decoy),'artefacts':artefacts,'events':events,
                'started_utc':datetime.fromtimestamp(started,timezone.utc).isoformat(),
                'diversion_scope':'local reference surrogate; not real protected assets',
                'note':'Server-observed events only; failed connection attempts are not captured. Audit artefact flags before preregistered analysis.'}
        path.write_text(json.dumps(record,indent=2)+'\n'); print('Saved '+str(path))


def numeric(value):
    if '/' in value:
        a,b=value.split('/');return float(a)/float(b)
    return float(value)


def analyze(args):
    with (args.study/'ahp.csv').open() as f: evaluators=list(csv.DictReader(f))
    matrices=[]
    pairs=[(0,1),(0,2),(0,3),(1,2),(1,3),(2,3)]
    columns=['E_over_I','E_over_D','E_over_P','I_over_D','I_over_P','D_over_P']
    for evaluator in evaluators:
        if any(not evaluator[c].strip() for c in columns): raise ValueError('AHP form is incomplete; no weights or human results will be invented')
        matrix=np.ones((4,4))
        for (i,j),c in zip(pairs,columns): matrix[i,j]=numeric(evaluator[c]);matrix[j,i]=1/matrix[i,j]
        matrices.append(matrix)
    weights=ahp(matrices)
    if not weights['accepted']: raise ValueError('AHP consistency ratio >= 0.10; ask evaluators to review their own judgments without steering them')
    cap_record=json.loads(args.caps.read_text())
    if cap_record.get('source') != 'actual_human_pilot': raise ValueError('Use caps calibrated from separate human pilot recordings, not fast scripted-agent caps')
    caps=cap_record['caps']
    with (args.study/'responses.csv').open() as f: responses=list(csv.DictReader(f))
    if len({r['session_id'] for r in responses}) != len(responses): raise ValueError('Duplicate responses')
    records=[]; excluded=[]
    for r in responses:
        file=args.study/'sessions'/(r['session_id']+'.json')
        if not file.exists() or not r['belief_real_1_to_5']:
            excluded.append({'session_id':r['session_id'],'reason':'missing recording or response'});continue
        if r['consent_confirmed'].strip().lower()!='yes': raise ValueError('Missing consent confirmation')
        raw=json.loads(file.read_text())
        if raw['participant_id']!=r['participant_id'] or not raw['consent_confirmed']: raise ValueError('Identity/consent mismatch')
        if raw['started_utc'] <= cap_record['locked_at_utc']: raise ValueError('Main sessions must start after caps are locked')
        if raw['status']!='completed':
            excluded.append({'session_id':r['session_id'],'reason':raw['status']});continue
        if not raw['actions']:
            excluded.append({'session_id':r['session_id'],'reason':'no observed actions'});continue
        belief=int(r['belief_real_1_to_5'])
        if belief not in range(1,6): raise ValueError('Belief must be 1–5')
        if r['suspected_honeypot_yes_no'].lower() not in ('yes','no'): raise ValueError('Answer suspicion yes/no')
        records.append({'participant':r['participant_id'],'class':raw['class'],'belief':belief,
                        'dsi_ahp':score(raw,caps[raw['class']],weights['group']['weights'])['score'],
                        'dsi_equal':score(raw,caps[raw['class']])['score'],
                        'dsi_original':score(raw,caps[raw['class']],ORIGINAL)['score'],
                        'duration':raw['duration'],'actions':raw['actions']})
    people=sorted({r['participant'] for r in records})
    if len(people)<3: raise ValueError('At least three actual participants with complete data are required; this is still only a pilot')
    def corr(rows,key):
        x=[r[key] for r in rows];y=[r['belief'] for r in rows]
        return None if len(set(x))<2 or len(set(y))<2 else float(spearmanr(x,y).statistic)
    keys=['dsi_ahp','dsi_equal','dsi_original','duration','actions']
    rng=random.Random(12041);samples={k:[] for k in keys};diffs={k:[] for k in keys[1:]}
    for _ in range(5000):
        sample=[r for p in rng.choices(people,k=len(people)) for r in records if r['participant']==p]
        corrs={k:corr(sample,k) for k in keys}
        for k,v in corrs.items():
            if v is not None: samples[k].append(v)
        for k in diffs:
            if corrs['dsi_ahp'] is not None and corrs[k] is not None: diffs[k].append(corrs['dsi_ahp']-corrs[k])
    def ci(a): return list(map(float,np.percentile(a,[2.5,97.5]))) if a else None
    report={'status':'pilot_analysis_of_supplied_human_records','participants':len(people),'sessions':len(records),
            'excluded':excluded,'ahp':weights,
            'correlations':{k:{'spearman':corr(records,k),'participant_cluster_bootstrap_ci95':ci(v),'valid_bootstrap_samples':len(v)} for k,v in samples.items()},
            'paired_correlation_differences':{k:{'ci95':ci(v),'valid_samples':len(v)} for k,v in diffs.items()},
            'limits':'Exploratory pooled correlations can be confounded by class and order. Cluster CIs reflect repeated participants but are unstable with small N. No Roy/Aradi equivalence claimed; missing compatible telemetry. No causal proof of production deception.'}
    target=args.study/'human_results.json'
    if target.exists(): raise ValueError('Preserve the prior analysis before rerunning')
    target.write_text(json.dumps(report,indent=2,allow_nan=False)+'\n');print(target)


def main():
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('prepare');p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('calibrate');p.add_argument('--pilot-study',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('capture');p.add_argument('--study',type=Path,required=True);p.add_argument('--session',required=True);p.add_argument('--consent',action='store_true');p.add_argument('--minutes',type=float,default=20)
    p=sub.add_parser('analyze');p.add_argument('--study',type=Path,required=True);p.add_argument('--caps',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='prepare': prepare(args.output)
    elif args.command=='calibrate':
        if args.output.exists(): raise ValueError('Caps cannot be overwritten')
        rows=[json.loads(p.read_text()) for p in (args.pilot_study/'sessions').glob('*.json')]
        caps={}
        for kind in ('web','ssh','scan'):
            valid=[r for r in rows if r['class']==kind and r['status']=='completed' and r['consent_confirmed'] and r['actions']>0]
            if len(valid)<3: raise ValueError('Collect at least three separate pilot sessions per class before locking caps')
            caps[kind]={'actions':max(1.,float(np.percentile([r['actions'] for r in valid],95))), 'seconds':max(.001,float(np.percentile([r['duration'] for r in valid],95)))}
        args.output.write_text(json.dumps({'source':'actual_human_pilot','locked_at_utc':datetime.now(timezone.utc).isoformat(),'caps':caps,'pilot_session_count':len(rows)},indent=2)+'\n')
        print(args.output)
    elif args.command=='capture':
        if not 0 < args.minutes <= 60: parser.error('Duration must be >0 and <=60 minutes')
        capture(args)
    else: analyze(args)

if __name__=='__main__': main()
