"""Versioned, browser-based human usability pilot. All business data is fictional.

Independent of the v1 protocol benchmark and dashboard. No shell, SQL evaluation,
external requests, real credentials, or production asset diversion.
"""
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import hashlib
import json
import secrets
import threading
import time
from flask import Flask, request, session, redirect, render_template_string

VERSION = 'human-web-usability-v2'
REPORTS = [
    {'id':'INV-1042','client':'Cedar Labs','amount':'₹24,600','status':'Pending review','owner':'Mira Rao',
     'detail':'October support renewal. The purchase-order reference must be checked before approval.'},
    {'id':'INV-1043','client':'Harbor Studio','amount':'₹18,200','status':'Approved','owner':'Arun Shah',
     'detail':'Design support package. Purchase order verified on 12 October.'},
    {'id':'INV-1044','client':'Northfield Books','amount':'₹9,800','status':'Paid','owner':'Mira Rao',
     'detail':'Catalogue maintenance. Payment reference PAY-2804.'},
]
STYLE = '''
:root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172d3b;background:#f2f5f7;font-size:16px}
*{box-sizing:border-box}body{margin:0}header{background:#122c3b;color:white;padding:22px max(24px,calc((100% - 1000px)/2));display:flex;align-items:center;justify-content:space-between;gap:20px}header strong{font-size:21px}header a{color:#cde5ed}main{max-width:1000px;margin:36px auto;padding:0 24px}h1{font-size:32px;line-height:1.15;margin:8px 0 18px}h2{font-size:21px}p,li{line-height:1.65}small,.muted{color:#566d7a}.panel{background:white;border:1px solid #d8e1e7;border-radius:12px;padding:28px;margin:20px 0}.narrow{max-width:520px;margin:40px auto}label{display:block;font-weight:600;margin:18px 0 8px}input,select,textarea{font:inherit;width:100%;padding:12px;border:1px solid #aabcc6;border-radius:6px}textarea{min-height:95px}button,.button{display:inline-block;background:#176a70;color:white;border:0;border-radius:6px;padding:12px 18px;font:inherit;text-decoration:none;cursor:pointer;margin-top:14px}a{color:#166470}nav{display:flex;gap:24px;flex-wrap:wrap}.notice{background:#edf6f5;padding:14px 18px;border-left:4px solid #237a74}.error{background:#fff1ee;color:#8a3123;padding:14px;border-left:4px solid #bd533a}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:14px 8px;border-bottom:1px solid #e1e7eb}th{color:#526a77;font-size:13px}footer{padding:24px;text-align:center;font-size:13px;color:#627983}.pill{display:inline-block;background:#e7f2ee;color:#24634c;padding:4px 10px;border-radius:20px;font-size:13px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid .panel{margin:0}.check{display:flex;gap:12px;align-items:start}.check input{width:auto;margin-top:6px}.check label{margin:0;font-weight:400}@media(max-width:700px){.grid{grid-template-columns:1fr}table{font-size:13px}main{padding:0 16px}.panel{padding:18px}header{padding:18px}h1{font-size:26px}}
'''
BASE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{title}} · Northstar Workspace</title><style>{{style|safe}}</style></head><body><header><strong>Northstar Workspace</strong><a href="/study">Task instructions</a></header><main>{{content|safe}}</main><footer>Local research workspace · Use only the supplied demonstration credentials</footer></body></html>'''


def atomic_json(path, value):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')
    tmp.replace(path)


class Study:
    def __init__(self, folder, session_id, participant_id, arm, minutes):
        self.folder=Path(folder); self.folder.mkdir(parents=True,exist_ok=True)
        self.path=self.folder/(session_id+'.json')
        if self.path.exists(): raise ValueError('This session already exists. Use a new session ID; do not overwrite participant evidence.')
        self.lock=threading.RLock(); self.arm=arm; self.limit=minutes*60
        self.token=secrets.token_urlsafe(32)
        self.record={'version':VERSION,'session_id':session_id,'participant_id':participant_id,'arm':arm,
            'purpose':'assisted_web_usability_pilot_not_deception_validation','status':'awaiting_consent',
            'created_at':datetime.now(timezone.utc).isoformat(),'started_at':None,'ended_at':None,
            'consent_confirmed':False,'events':[],'feedback':None,'stop_reason':None,
            'prior_lab_exposure':None,'actions':0,'duration_seconds':0.,'reference_actions':None,
            'dsi':None,'dsi_reason':'No independently observed protected-asset actions; usability pilot only',
            'settings':{'maximum_minutes':minutes,'arm_definition': ['sign_in_rejection_with_help','working_dashboard_reports','working_dashboard_reports_and_archive'][arm]},
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        self.start_mono=None; self.notes={}; self.save()
    def save(self): atomic_json(self.path,self.record)
    def begin(self, prior):
        with self.lock:
            if self.record['status']!='awaiting_consent': return
            self.start_mono=time.monotonic()
            self.record.update(status='active',consent_confirmed=True,started_at=datetime.now(timezone.utc).isoformat(),prior_lab_exposure=prior)
            self.save()
    def event(self, action, **details):
        with self.lock:
            if self.record['status']!='active': return
            # Only explicit navigations/submissions are counted, never CSS/favicon/polling.
            elapsed=time.monotonic()-self.start_mono
            self.record['events'].append({'seconds':round(elapsed,3),'action':action,**details})
            self.record['actions']=len(self.record['events'])
            self.record['duration_seconds']=round(elapsed,3)
            self.save()
    def stop(self, reason):
        with self.lock:
            if self.record['status']!='active': return
            self.record.update(status='awaiting_feedback',stop_reason=reason,
                ended_at=datetime.now(timezone.utc).isoformat(),duration_seconds=round(time.monotonic()-self.start_mono,3))
            self.save()
    def check_timeout(self):
        with self.lock:
            if self.record['status']=='active' and time.monotonic()-self.start_mono>=self.limit: self.stop('time_limit')
    def feedback(self, values):
        with self.lock:
            if self.record['status']!='awaiting_feedback': raise ValueError('Session has not finished')
            self.record['feedback']=values
            self.record['status']='completed'  # Participant finish is a valid observed outcome, not a technical failure.
            self.save()
    def interrupt(self):
        with self.lock:
            if self.record['status'] in ('active','awaiting_consent'):
                self.record.update(status='interrupted',stop_reason='operator_shutdown',ended_at=datetime.now(timezone.utc).isoformat())
                self.save()


def create_app(study):
    app=Flask(__name__);app.secret_key=secrets.token_bytes(32)
    app.config.update(MAX_CONTENT_LENGTH=8192,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict')
    def csrf(): return '<input type="hidden" name="csrf" value="'+escape(study.token)+'">'
    def page(title, content, code=200):
        if study.record['status']=='active':
            content='<nav><a href="/dashboard">Overview</a><a href="/reports">Reports</a><a href="/help">Help</a><a href="/finish">Finish task</a></nav>'+content
        return render_template_string(BASE,title=title,style=STYLE,content=content),code
    @app.before_request
    def guard():
        if request.remote_addr not in ('127.0.0.1','::1'): return 'Local access only',403
        if not request.host.startswith('127.0.0.1:') and request.host!='localhost': return 'Invalid host',403
        if request.method=='POST' and not secrets.compare_digest(request.form.get('csrf',''),study.token): return 'Refresh the form and try again.',403
        study.check_timeout()
        if request.path in ('/favicon.ico',): return '',204
        if request.path=='/health': return None
        status=study.record['status']
        if status=='completed' and request.path!='/thanks': return redirect('/thanks')
        if status=='awaiting_feedback' and request.path not in ('/feedback','/thanks'): return redirect('/feedback')
        if status=='awaiting_consent' and request.path not in ('/','/study','/begin'): return redirect('/study')
        if status=='interrupted': return 'This recording has ended. Ask the facilitator for a new session.',410
    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store'
        response.headers['Content-Security-Policy']="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['X-Content-Type-Options']='nosniff'
        return response
    @app.get('/health')
    def health(): return {'version':VERSION,'status':study.record['status']}
    @app.get('/')
    def index(): return redirect('/study' if study.record['status']=='awaiting_consent' else '/login')
    @app.get('/study')
    def instructions():
        content='''<h1>Review an invoice</h1><p>Explore the workspace and find invoice <strong>INV-1042</strong>. If you can access it, identify its client and status, then leave a short review note. You can stop if you cannot proceed.</p><div class="notice">Use username <strong>demo</strong> and password <strong>demo</strong>. Do not use personal credentials.</div><div class="panel"><h2>Before you begin</h2><p>This is a voluntary local research exercise. Some services may be simulated. We record page visits, task submissions, timing and your questionnaire answers under a participant code. Password values are not saved. Enter no personal information. You can stop at any time; a short session is a valid outcome. The facilitator must explain retention and withdrawal arrangements before you agree.</p><p>This is a usability pilot. Your answers do not affect marks or access to services.</p>'''
        if study.record['status']=='awaiting_consent':
            content+='<form action="/begin" method="post">'+csrf()+'''<label for="prior">Have you already used an earlier version of this lab?</label><select id="prior" name="prior" required><option value="">Choose</option><option value="yes">Yes</option><option value="no">No</option></select><div class="check"><input id="consent" name="consent" type="checkbox" required><label for="consent">The facilitator explained the study and data arrangements. I voluntarily agree to participate and have my interactions recorded.</label></div><button>Agree and start</button></form>'''
        else: content+='<a class="button" href="/login">Return to workspace</a>'
        return page('Task instructions',content+'</div>')
    @app.post('/begin')
    def begin():
        if request.form.get('consent')!='on' or request.form.get('prior') not in ('yes','no'): return 'Consent and prior exposure response required.',400
        study.begin(request.form['prior']); return redirect('/login')
    @app.route('/login',methods=['GET','POST'])
    def login():
        error=''
        if request.method=='POST':
            valid=request.form.get('username')=='demo' and request.form.get('password')=='demo'
            accepted=valid and study.arm>0
            study.event('login_attempt',accepted=accepted,credentials_supplied=bool(request.form.get('username') and request.form.get('password')))
            if accepted: session['signed_in']=True; return redirect('/dashboard')
            error='<p class="error">Sign-in was not accepted. Check the supplied demonstration credentials. You can read Help or finish the task if you cannot continue.</p>'
        else: study.event('view_login')
        return page('Sign in','<div class="panel narrow"><p class="muted">ACCOUNT ACCESS</p><h1>Sign in</h1>'+error+'<form method="post">'+csrf()+'''<label for="username">Username</label><input id="username" name="username" autocomplete="off" maxlength="80" required><label for="password">Password</label><input id="password" type="password" name="password" autocomplete="off" maxlength="80" required><button>Sign in</button></form><p><a href="/help">Need help signing in?</a></p></div>''')
    def authorized(): return bool(session.get('signed_in')) and study.arm>0
    @app.get('/dashboard')
    def dashboard():
        if not authorized(): return redirect('/login')
        study.event('view_dashboard')
        return page('Overview','''<p class="muted">OPERATIONS</p><h1>Invoice workspace</h1><p>Review open invoices and record the next action for the account team.</p><div class="grid"><div class="panel"><small>Pending review</small><h2>1 invoice</h2></div><div class="panel"><small>Approved</small><h2>1 invoice</h2></div><div class="panel"><small>Paid</small><h2>1 invoice</h2></div></div><div class="panel"><h2>Review queue</h2><p>INV-1042 needs a purchase-order check before approval.</p><a class="button" href="/reports/INV-1042">Open invoice</a></div>''')
    @app.get('/reports')
    def reports():
        if not authorized(): return redirect('/login')
        query=request.args.get('q','')[:120]; study.event('search_reports' if query else 'view_reports',query=query)
        selected=[r for r in REPORTS if query.lower() in (r['id']+' '+r['client']+' '+r['status']).lower()]
        content='<h1>Reports</h1><form><label for="q">Find an invoice or client</label><input id="q" name="q" value="'+escape(query,quote=True)+'" maxlength="120"><button>Search</button></form><div class="panel"><table><thead><tr><th>Invoice</th><th>Client</th><th>Status</th></tr></thead><tbody>'
        for r in selected: content+=f'<tr><td><a href="/reports/{r["id"]}">{r["id"]}</a></td><td>{r["client"]}</td><td>{r["status"]}</td></tr>'
        if not selected: content+='<tr><td colspan="3">No matching invoices. Try an invoice number or client name.</td></tr>'
        return page('Reports',content+'</tbody></table></div>')
    @app.route('/reports/<invoice>',methods=['GET','POST'])
    def detail(invoice):
        if not authorized(): return redirect('/login')
        r=next((r for r in REPORTS if r['id']==invoice),None)
        if r is None: return page('Not found','<h1>Invoice not found</h1><a href="/reports">Back to reports</a>',404)
        notice=''
        if request.method=='POST':
            note=request.form.get('note','').strip()[:500]
            if not note: return page('Note required','<p>Please enter a note.</p><a href="'+request.path+'">Return to invoice</a>',400)
            study.notes[invoice]=note;study.event('save_note',invoice=invoice,note=note);notice='<p class="notice" role="status">Your review note was saved for this session.</p>'
        else: study.event('view_invoice',invoice=invoice)
        content=f'<p class="muted">INVOICE DETAILS</p><h1>{r["id"]}</h1>{notice}<div class="panel"><span class="pill">{r["status"]}</span><h2>{r["client"]}</h2><p>Amount: {r["amount"]}<br>Owner: {r["owner"]}</p><p>{r["detail"]}</p>'
        if study.arm==2: content+='<p><a href="/archive">View the purchasing archive</a> for related account notes.</p>'
        content+='</div><div class="panel"><h2>Review note</h2><p>Use only fictional task information. Your note is recorded with this session.</p><form method="post">'+csrf()+'<label for="note">Next action</label><textarea id="note" name="note" maxlength="500" required>'+escape(study.notes.get(invoice,''))+'</textarea><button>Save note</button></form></div>'
        return page(invoice,content)
    @app.get('/archive')
    def archive():
        if not authorized(): return redirect('/login')
        if study.arm!=2: return page('Not found','<h1>Page not found</h1><a href="/reports">Return to reports</a>',404)
        study.event('view_archive')
        return page('Purchasing archive','<h1>Purchasing archive</h1><div class="panel"><h2>Cedar Labs · October renewal</h2><p>The purchase order is awaiting the account owner’s confirmation. Record a follow-up note on INV-1042 before approval.</p><a href="/reports/INV-1042">Return to INV-1042</a></div>')
    @app.get('/help')
    def help_page():
        study.event('view_help')
        return page('Help','<h1>Workspace help</h1><div class="panel"><h2>Signing in</h2><p>Use the demonstration account supplied on your task sheet. There is no password reset or external account registration.</p><h2>Finding a report</h2><p>After signing in, open Reports and search by invoice number or client. Open the matching invoice to read details and save a note.</p><h2>Cannot proceed?</h2><p>You may finish now and tell us what prevented progress. Repeated retries are not required.</p><a class="button" href="/finish">Finish task</a></div>')
    @app.route('/finish',methods=['GET','POST'])
    def finish():
        if request.method=='POST':
            reason=request.form.get('reason')
            if reason not in ('task_complete','cannot_proceed','choose_to_stop'): return 'Choose a reason',400
            study.stop(reason);return redirect('/feedback')
        return page('Finish task','<h1>Finish this session</h1><p>You do not need to wait for the time limit.</p><form method="post">'+csrf()+'''<label for="reason">Why are you finishing?</label><select id="reason" name="reason" required><option value="">Choose</option><option value="task_complete">I finished the task</option><option value="cannot_proceed">I cannot proceed</option><option value="choose_to_stop">I choose to stop</option></select><button>Continue to questionnaire</button></form>''')
    @app.route('/feedback',methods=['GET','POST'])
    def feedback():
        if study.record['status']=='active': return redirect('/finish')
        if request.method=='POST':
            rating=request.form.get('rating'); suspicion=request.form.get('suspicion'); confidence=request.form.get('task_result')
            if rating not in ('1','2','3','4','5') or suspicion not in ('honeypot','broken','both','neither','unsure') or confidence not in ('yes','partly','no'): return 'Complete all required selections.',400
            values={'belief_real_1_to_5':int(rating),'interpretation':suspicion,'task_completed_self_report':confidence,
                    'first_suspicion':request.form.get('when','').strip()[:200],
                    'reason':request.form.get('reason','').strip()[:1000],'submitted_at':datetime.now(timezone.utc).isoformat()}
            study.feedback(values);return redirect('/thanks')
        return page('Questionnaire','''<h1>Your observations</h1><p>There are no correct answers. Describe what you actually experienced.</p><form method="post">'''+csrf()+'''<label for="rating">How genuine did the service seem?</label><select id="rating" name="rating" required><option value="">Choose</option><option value="1">1 — Definitely simulated</option><option value="2">2 — Probably simulated</option><option value="3">3 — Unsure</option><option value="4">4 — Probably genuine</option><option value="5">5 — Definitely genuine</option></select><label for="suspicion">What did you think you were using?</label><select id="suspicion" name="suspicion" required><option value="">Choose</option><option value="honeypot">A deliberate honeypot or decoy</option><option value="broken">A broken or unavailable website</option><option value="both">Both seemed possible</option><option value="neither">Neither</option><option value="unsure">Unsure</option></select><label for="task_result">Were you able to finish the invoice task?</label><select id="task_result" name="task_result" required><option value="">Choose</option><option value="yes">Yes</option><option value="partly">Partly</option><option value="no">No</option></select><label for="when">When did you first become suspicious, if at all?</label><input id="when" name="when" maxlength="200" placeholder="For example, after the first sign-in attempt; or never"><label for="reason">What led you to that view?</label><textarea id="reason" name="reason" maxlength="1000"></textarea><button>Save my answers</button></form>''')
    @app.get('/thanks')
    def thanks():
        if study.record['status']!='completed': return redirect('/study')
        return page('Saved','<h1>Your answers have been saved</h1><p>Thank you. You can close this tab and return the Mac to the facilitator. The facilitator will provide the study debrief and withdrawal information.</p>')
    @app.errorhandler(404)
    def missing(_):
        study.event('unknown_page')
        return page('Not found','<h1>Page not found</h1><p>This address is not available.</p><a href="/help">Open Help</a>',404)
    return app
