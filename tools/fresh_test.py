"""Fresh loopback packets -> trusted capture -> alert -> actual honeypot session.

Never submits features, predicts via API, or injects alert records.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import time
import uuid
from urllib.parse import quote
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'Harmless DSOF local target. No input is executed.'
        self.send_response(200)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):
        pass

def wait_for(fetch, predicate, timeout=20):
    deadline = time.monotonic()+timeout
    latest = None
    while time.monotonic() < deadline:
        latest = fetch()
        for row in latest:
            if predicate(row):
                return row
        time.sleep(.25)
    raise RuntimeError('Timed out waiting for required recorded evidence; latest='+str(latest)[:800])

def run(base, benign=False, attack='sqli', segmented=False, timeout=20):
    test_id = str(uuid.uuid4())
    client = requests.Session()
    client.trust_env = False
    def get(path):
        r=client.get(base+path,timeout=5)
        r.raise_for_status()
        return r.json()
    ready = get('/api/ready')
    if not ready['ready']:
        raise RuntimeError('Application, model and collector must be ready')
    if not any('loopback' in x.lower() or x in ('lo','lo0') for x in ready['collector']['interfaces']):
        raise RuntimeError('Fresh localhost tests require the loopback capture interface')
    target = ThreadingHTTPServer(('127.0.0.1',0),Target)
    thread = threading.Thread(target=target.serve_forever,daemon=True)
    thread.start()
    try:
        token=(ROOT/'data'/'control.token').read_text().strip()
        registered=client.post(base+'/api/tests/register',json={'test_id':test_id,'target_port':target.server_port},
                               headers={'Authorization':'Bearer '+token},timeout=5)
        registered.raise_for_status()
        paths={'sqli':'/search?q='+quote("' OR 1=1 --"),'xss':'/search?q='+quote('<script>alert(1)</script>'),
               'traversal':'/download?file='+quote('../../etc/passwd',safe='')}
        path='/search?q=ordinary+books' if benign else paths[attack]
        request=(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-DSOF-Test-ID: {test_id}\r\n'
                 'Cookie: discussion=select+your+book\r\nConnection: close\r\n\r\n').encode('ascii')
        with socket.create_connection(('127.0.0.1',target.server_port),timeout=5) as conn:
            conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            if segmented:
                cut=request.index(b' HTTP')//2
                conn.sendall(request[:cut]);time.sleep(.15);conn.sendall(request[cut:])
            else:
                conn.sendall(request)
            while conn.recv(8192):
                pass
        query='?test_id='+test_id
        flow=wait_for(lambda:get('/api/flows'+query),lambda f:f.get('test_id')==test_id,timeout)
        result={'test_id':test_id,'kind':'benign' if benign else attack,'origin':flow['origin'],'flow_id':flow['id'],
                'original_ml':flow['ml'],'http_ml':flow.get('http_ml'),'feature_error':flow['feature_error'],'segmented_send':segmented}
        if flow.get('feature_error') or not flow.get('ml'):
            raise RuntimeError('Captured flow did not complete model inference: '+str(flow.get('feature_error')))
        if flow['origin']!='manual_test':
            raise RuntimeError('Fresh traffic origin was not registered correctly')
        if benign:
            alerts=get('/api/alerts'+query)
            if any(a['rules'] for a in alerts):
                raise RuntimeError('Benign request triggered HTTP rule')
            result['http_rule_false_positive']=False
            result['ml_alerts']=alerts
            result['verified']='fresh captured benign flow; no HTTP rule match'
            print(json.dumps(result,indent=2),flush=True)
            return result
        alert=wait_for(lambda:get('/api/alerts'+query),lambda a:bool(a['rules']),timeout)
        if not alert['rules'] or not alert['capture_derived']:
            raise RuntimeError('Required trusted captured HTTP rule missing')
        deployment=wait_for(lambda:get('/api/honeypots'),lambda d:d['id']==alert['deployment_id'] and d['state']=='listening',timeout)
        if deployment.get('kind')!='web':
            raise RuntimeError('Expected web emulator')
        hp_port=deployment['port']
        # A new TCP connection is actual follow-up, not redirection. Header is a correlation ID.
        hp=client.get(f'http://127.0.0.1:{hp_port}/login',headers={'X-DSOF-Test-ID':test_id,'Connection':'close'},timeout=5)
        hp.raise_for_status()
        session=wait_for(lambda:get('/api/sessions'+query),lambda s:s.get('state')!='active' and s.get('interaction_count',0)>=1,timeout)
        evidence=get('/api/sessions/'+session['id'])
        if evidence.get('alert_id')!=alert['id'] or evidence['deployment_id']!=deployment['id']:
            raise RuntimeError('Session evidence links are incorrect')
        if not evidence.get('interactions') or not evidence.get('dsi'):
            raise RuntimeError('Actual session interactions and DSI are required')
        from dsof.dsi import calculate_dsi
        dsi=evidence['dsi']
        reproduced=calculate_dsi(dsi['inputs'],provisional=dsi['provisional'],weights=dsi['weights'],normalizers=dsi['normalizers'])
        if reproduced['score']!=dsi['score']:
            raise RuntimeError('Persisted DSI did not reproduce')
        from dsof.evaluation import calculate_eidp
        evaluation = evidence.get('evaluation')
        if evaluation:
            check = calculate_eidp({**evaluation['inputs'],'state':evidence['state']},
                                  prior_sessions=evaluation['prior_sessions_24h'],
                                  protected_connections=evaluation['protected_connections_during_session'])
            if check['score'] != evaluation['score']:
                raise RuntimeError('Four-component DSI did not reproduce')
        result.update(alert_id=alert['id'],detecting_component=alert['detection_source'],rules=alert['rules'],
                      deployment_id=deployment['id'],listening_verified=True,session_id=evidence['id'],dsi=dsi,evaluation=evaluation,
                      attacker_profile=alert.get('attacker_profile'),strategy_decision=alert.get('strategy_decision'),
                      verified='actual captured request, alert, listener, follow-up session and reproducible DSI')
        print(json.dumps(result,indent=2),flush=True)
        return result
    finally:
        target.shutdown();target.server_close();thread.join(timeout=2);client.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url',default='http://127.0.0.1:5000')
    parser.add_argument('--benign',action='store_true')
    parser.add_argument('--attack',choices=['sqli','xss','traversal'],default='sqli')
    parser.add_argument('--segmented',action='store_true')
    parser.add_argument('--loop',action='store_true')
    parser.add_argument('--interval',type=float,default=10)
    parser.add_argument('--timeout',type=float,default=20)
    args=parser.parse_args()
    if args.interval<1 or args.timeout<1:
        parser.error('interval and timeout must be >= 1 second')
    from urllib.parse import urlparse
    if urlparse(args.base_url).hostname not in ('127.0.0.1','localhost'):
        parser.error('Fresh test application must be localhost')
    try:
        while True:
            run(args.base_url,args.benign,args.attack,args.segmented,args.timeout)
            if not args.loop:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('Fresh traffic test stopped; temporary HTTP target cleaned up.')
        return 0
    except Exception as exc:
        print('FAILED: '+str(exc),file=sys.stderr)
        return 1

if __name__=='__main__':
    raise SystemExit(main())
