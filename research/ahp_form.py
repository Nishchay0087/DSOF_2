"""Collect independent evaluator judgments; preserve every submitted revision."""
from datetime import datetime, timezone
from html import escape
import hashlib
import json
from pathlib import Path
import secrets
import numpy as np
from flask import Flask, request, render_template_string, redirect
from .human_web import STYLE
from .metrics import ahp

PAIRS=[('E_I','Engagement','Intelligence',0,1),('E_D','Engagement','Diversion',0,2),
       ('E_P','Engagement','Persistence',0,3),('I_D','Intelligence','Diversion',1,2),
       ('I_P','Intelligence','Persistence',1,3),('D_P','Diversion','Persistence',2,3)]
SCALE={str(n):float(n) for n in range(1,10)} | {f'1/{n}':1/n for n in range(2,10)}
VERSION='dsi-ahp-expert-judgment-v1'


def matrix_from(answers):
    m=np.ones((4,4))
    for key,_,_,i,j in PAIRS:
        if answers.get(key) not in SCALE: raise ValueError('Answer all six comparisons using the displayed scale.')
        m[i,j]=SCALE[answers[key]];m[j,i]=1/m[i,j]
    return m


def individual(m):
    vals,vecs=np.linalg.eig(m);i=np.argmax(vals.real)
    v=np.abs(vecs[:,i].real);v/=v.sum()
    return {'weights':list(map(float,v)), 'consistency_ratio':max(0.,float((vals[i].real-4)/3/.9))}


def latest_records(folder):
    records=[]
    for identity in ('R01','R02','R03','R04','R05'):
        paths=sorted(Path(folder).glob(identity+'-*.json'))
        if paths:
            p=paths[-1];r=json.loads(p.read_text());r['source_file']=p.name
            r['source_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();records.append(r)
    return records


def summarize(folder):
    records=latest_records(folder)
    # Never silently drop an inconsistent evaluator to produce desirable weights.
    base={'version':VERSION,'evaluators_submitted':len(records),
          'inputs':[{'id':r['evaluator_id'],'file':r['source_file'],'sha256':r['source_sha256']} for r in records],
          'meaning':'Expert importance judgments, not empirical validation of DSI or deception',
          'status':'awaiting_evaluators','weights':None}
    if len(records)>=3:
        result=ahp([matrix_from(r['answers']).tolist() for r in records])
        base['calculation']=result
        base['status']='consistent_judgments' if result['accepted'] else 'consistency_review_needed'
        if result['accepted']:base['weights']=result['group']['weights']
    return base


def create_app(folder,evaluator_id):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    if evaluator_id not in ('R01','R02','R03','R04','R05'): raise ValueError('Use evaluator R01 through R05')
    app=Flask(__name__);app.config['MAX_CONTENT_LENGTH']=8192
    csrf=secrets.token_urlsafe(32)
    def page(body):
        return render_template_string('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DSI evaluator form</title><style>{{style|safe}}</style></head><body><header><strong>DSI evaluator study</strong></header><main>{{body|safe}}</main></body></html>',style=STYLE,body=body)
    @app.before_request
    def guard():
        if request.remote_addr not in ('127.0.0.1','::1') or request.host.split(':')[0]!='127.0.0.1':return 'Local access only',403
        if request.method=='POST' and not secrets.compare_digest(request.form.get('csrf',''),csrf):return 'Refresh and try again.',403
    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store'
        response.headers['Content-Security-Policy']="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
        response.headers['X-Content-Type-Options']='nosniff';return response
    @app.route('/',methods=['GET','POST'])
    def form():
        values={};message=''
        if request.method=='POST':
            values={k:request.form.get(k,'') for k,*_ in PAIRS}
            try:
                m=matrix_from(values)
                if request.form.get('confirm')!='on':raise ValueError('Confirm these are your own independent judgments.')
                role=request.form.get('role','')
                if role not in ('faculty','security_practitioner','experienced_student'):raise ValueError('Choose your evaluator background.')
                result=individual(m)
                revisions=sorted(folder.glob(evaluator_id+'-*.json'));revision=len(revisions)+1
                path=folder/f'{evaluator_id}-{revision:03d}.json'
                record={'version':VERSION,'evaluator_id':evaluator_id,'revision':revision,
                        'submitted_at':datetime.now(timezone.utc).isoformat(),'role':role,
                        'independent_judgments_confirmed':True,'answers':values,'matrix':m.tolist(),
                        'individual':result,'notes':request.form.get('notes','').strip()[:1000]}
                with path.open('x') as f:json.dump(record,f,indent=2,allow_nan=False)
                return redirect('/saved')
            except ValueError as e:message='<p class="error">'+escape(str(e))+'</p>'
        body=f'<h1>Compare the DSI components</h1><p>Evaluator {evaluator_id}. Judge the importance of each component for deception success. Do this independently, without viewing participant ratings or another evaluator’s answers.</p>'+message
        body+='''<div class="panel"><h2>What the four components mean</h2><p><strong>Engagement:</strong> volume of actions directed to a decoy after detection; capped logarithmic action count.</p><p><strong>Intelligence:</strong> diversity of captured evidence: credentials, tool fingerprint, payload/location, and post-access technique; each category contributes one quarter.</p><p><strong>Diversion:</strong> share of observed post-detection actions directed to decoys rather than protected assets. If either observation stream is missing, this component is unknown.</p><p><strong>Persistence:</strong> time between the first and last observed attacker actions, including returns within a fixed observation window, capped by a pilot-derived limit.</p><p>The proposed index combines these four measures. The present browser usability pilot does not measure protected-asset activity and cannot supply a complete DSI. Your judgments concern the proposed fully instrumented study, not the invoice task’s score.</p></div><p>For each pair, select which component matters more and by how much. Equal importance is 1; moderate 3; strong 5; very strong 7; extreme 9. Values 2, 4, 6 and 8 are intermediate. There is no preferred answer.</p>'''
        body+='<form method="post"><input type="hidden" name="csrf" value="'+csrf+'"><label for="role">Evaluator background</label><select id="role" name="role" required><option value="">Choose</option><option value="faculty">Faculty</option><option value="security_practitioner">Security practitioner</option><option value="experienced_student">Experienced security student</option></select>'
        for key,left,right,_,_ in PAIRS:
            body+=f'<label for="{key}">{left} compared with {right}</label><select id="{key}" name="{key}" required><option value="">Choose your judgment</option>'
            options=[('1','Equally important')]+[(str(n),f'{left} is {n} times as important') for n in range(2,10)]+[(f'1/{n}',f'{right} is {n} times as important') for n in range(2,10)]
            for value,label in options:body+=f'<option value="{value}"'+(' selected' if values.get(key)==value else '')+'>'+label+'</option>'
            body+='</select>'
        body+='''<label for="notes">Optional reasoning (no personal information)</label><textarea id="notes" name="notes" maxlength="1000"></textarea><p>Responses are stored locally under your evaluator code. The facilitator must explain retention and withdrawal arrangements. You may leave without submitting.</p><div class="check"><input id="confirm" name="confirm" type="checkbox" required><label for="confirm">These are my own independent judgments. I agree to their use in this research analysis.</label></div><button>Save my judgments</button></form>'''
        return page(body)
    @app.get('/saved')
    def saved():
        paths=sorted(folder.glob(evaluator_id+'-*.json'))
        if not paths:return redirect('/')
        r=json.loads(paths[-1].read_text());cr=r['individual']['consistency_ratio']
        body=f'<h1>Your judgments are saved</h1><p>Evaluator {evaluator_id}, revision {r["revision"]}. Consistency ratio: <strong>{cr:.3f}</strong>.</p>'
        if cr>=.1:body+='<p>The comparisons exceed the predeclared consistency threshold of 0.10. Review whether your own judgments agree with one another. Do not choose values merely to obtain a particular score or weighting. A revision preserves your previous submission.</p><a class="button" href="/">Review my judgments</a>'
        else:body+='<p>The comparisons meet the predeclared consistency threshold. You can return the Mac to the facilitator.</p>'
        body+='<p>Consistency is not proof that DSI is valid. No other evaluators’ judgments or group weights are shown here.</p>'
        return page(body)
    return app
