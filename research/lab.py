"""Real loopback protocols with fixed virtual responses. No OS commands execute.

These are experimental emulators, not Cowrie, a gateway or a production network.
Agent decisions depend on response content, never the arm index.
"""
import hashlib
import http.client
import json
import random
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote
import paramiko

CLASSES = ('web', 'ssh', 'scan')
PARAMETERS = {'continue_success':.90, 'continue_failure':.25, 'follow_breadcrumb':.65,
              'visit_reference_after_stop':.35, 'max_actions':12, 'action_delay_seconds':.002}


def response(kind, arm, request):
    """Versioned arm definitions, consumed by actual network handlers."""
    if kind == 'web':
        if arm == 0:
            return 401, 'Login rejected'
        if 'user=admin' in request:
            return 200, 'Admin dashboard: users reports settings'
        if arm == 2 and ('OR' in request or 'UNION' in request):
            return 200, 'SQL syntax detail; records: user=demo; role=analyst; breadcrumb=/records'
        if '/records' in request:
            return (200, 'Records: demo-001 demo-002') if arm == 2 else (404, 'Not found')
        return 200, 'Admin dashboard: users reports settings'
    if kind == 'ssh':
        if arm == 0:
            return 0, 'command unavailable'
        commands = {'whoami':'analyst', 'pwd':'/home/analyst', 'ls':'reports welcome.txt',
                    'id':'uid=1001(analyst)', 'uname -a':'Linux billing-node 6.8',
                    'cat welcome.txt':'Finance workspace', 'cat reports':'report-001: pending'}
        if arm == 2:
            commands['ls'] = 'reports welcome.txt history.txt'
            commands['cat welcome.txt'] = 'Workspace; breadcrumb=cat history.txt'
            commands['cat history.txt'] = 'Demo history: SELECT records; synthetic credential demo:demo'
        return 0, commands.get(request, 'command unavailable')
    return 0, ('service ready' if arm < 2 else 'SSH-2.0-OpenSSH_9.6\r\nHTTP/1.1 200 OK')


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


class Lab:
    def __init__(self, audit=False):
        self.audit_enabled=audit
        self.servers=[]; self.endpoints={}; self.key=paramiko.RSAKey.generate(2048)
        self.counters={'http':0,'ssh_commands':0,'ssh_auth':0,'scan':0,'reference':0}
        self.lock=threading.Lock(); self.audit=[]
    def count(self, key):
        with self.lock: self.counters[key]+=1
    def event(self, kind, arm, action, reply):
        if not self.audit_enabled: return
        with self.lock:
            self.audit.append({'timestamp':time.time(), 'class':kind, 'arm':arm, 'action':action[:1024], 'response':reply[:1024]})
    def start(self):
        owner=self
        class HTTP(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.server.kind == 'reference':
                    owner.count('reference'); code, body=200, 'reference asset surrogate'
                else:
                    owner.count('http'); code,body=response('web',self.server.arm,unquote(self.path))
                owner.event(self.server.kind,self.server.arm,self.path,body)
                raw=body.encode(); self.send_response(code)
                self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self,*args): pass
        class Scan(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                try:
                    self.request.recv(256); owner.count('scan')
                    body=response('scan',self.server.arm,'')[1]
                    owner.event('scan',self.server.arm,'service probe',body)
                    self.request.sendall(body.encode())
                except (OSError,TimeoutError): pass
        class SSH(socketserver.BaseRequestHandler):
            def handle(self):
                arm=self.server.arm
                class Auth(paramiko.ServerInterface):
                    def __init__(self): self.commands={}; self.ready=threading.Condition()
                    def get_allowed_auths(self,u): return 'password'
                    def check_auth_password(self,u,p):
                        owner.count('ssh_auth'); owner.event('ssh',arm,'password authentication [credential value omitted]','accepted'); return paramiko.AUTH_SUCCESSFUL
                    def check_channel_request(self,k,i):
                        return paramiko.OPEN_SUCCEEDED if k=='session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                    def check_channel_exec_request(self,ch,command):
                        with self.ready:
                            self.commands[ch.get_id()]=command[:1024].decode('utf8','replace'); self.ready.notify_all()
                        return True
                transport=paramiko.Transport(self.request); transport.add_server_key(owner.key)
                auth=Auth()
                try:
                    transport.start_server(server=auth)
                    while transport.is_active():
                        channel=transport.accept(.2)
                        if channel is None: continue
                        with auth.ready:
                            auth.ready.wait_for(lambda:channel.get_id() in auth.commands,timeout=3)
                            command=auth.commands.pop(channel.get_id(),None)
                        if command is not None:
                            owner.count('ssh_commands')
                            body=response('ssh',arm,command)[1]
                            owner.event('ssh',arm,command,body)
                            channel.sendall(body.encode()+b'\n'); channel.send_exit_status(0)
                        channel.close()
                except (OSError,EOFError,paramiko.SSHException): pass
                finally: transport.close()
        for kind in ('web','ssh','scan','reference'):
            for arm in (range(3) if kind!='reference' else range(1)):
                ports=[]
                # Breadth is one service for A1, three for A2 and A3.
                for _ in range(1 if kind!='scan' or arm==0 else 3):
                    server=(ThreadingHTTPServer if kind in ('web','reference') else TCPServer)(('127.0.0.1',0), HTTP if kind in ('web','reference') else SSH if kind=='ssh' else Scan)
                    server.kind=kind; server.arm=arm
                    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True); thread.start()
                    self.servers.append((server,thread)); ports.append(server.server_address[1])
                self.endpoints[kind,arm]=ports
        return self
    def close(self):
        for server,thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(2)
    def http(self,port,path):
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        try:
            client.request('GET',path,headers={'User-Agent':'DSOF-consented-lab-agent/1'})
            r=client.getresponse(); return r.status,r.read(8192).decode()
        finally: client.close()
    def episode(self, kind, arm, seed):
        rng=random.Random(seed); bucket=rng.randrange(3)
        # Pre-sampled per-step draws allow matching random stimuli across arms.
        draws=[(rng.random(),rng.random()) for _ in range(PARAMETERS['max_actions'])]
        events=[]; reference_actions=0; status='completed'; error=None; ssh=None
        artefacts=[False,False,False,False]; start=time.monotonic(); stopped=False
        def log(action,body,destination='decoy'):
            events.append({'seconds':time.monotonic()-start,'action':action,'response':body[:512],'destination':destination})
        try:
            if kind=='ssh':
                port=self.endpoints[kind,arm][0]; ssh=paramiko.SSHClient()
                ssh.get_host_keys().add(f'[127.0.0.1]:{port}',self.key.get_name(),self.key)
                ssh.connect('127.0.0.1',port=port,username='demo',password='demo-only',look_for_keys=False,allow_agent=False,timeout=3)
                log('password authentication','accepted'); artefacts[0:2]=[True,True]
            next_action=None
            for i,(continue_draw,breadcrumb_draw) in enumerate(draws):
                if kind=='web':
                    path=next_action or ('/login?user=admin&password=demo' if i==0 else ('/search?q=%27%20OR%201%3D1--' if i%2 else '/admin'))
                    code,body=self.http(self.endpoints[kind,arm][0],path); log(path,body)
                    artefacts[0] |= 'password=' in path; artefacts[1]=True; artefacts[2] |= '/search' in path
                    artefacts[3] |= 'records:' in body.lower() or 'dashboard' in body.lower()
                    success=code==200
                    next_action='/records' if 'breadcrumb=' in body and breadcrumb_draw < PARAMETERS['follow_breadcrumb'] else None
                elif kind=='ssh':
                    command=next_action or ('whoami','pwd','ls','cat welcome.txt','id','uname -a','cat reports')[i%7]
                    _,out,_=ssh.exec_command(command,timeout=3); body=out.read(8192).decode(); log(command,body)
                    success='unavailable' not in body; artefacts[3] |= success
                    next_action='cat history.txt' if 'breadcrumb=' in body and breadcrumb_draw < PARAMETERS['follow_breadcrumb'] else None
                else:
                    ports=self.endpoints[kind,arm]
                    # Probe fixed service slots; closed slots are measured on a bound, non-listening socket.
                    port=ports[i%3] if i%3 < len(ports) else None
                    if port is None:
                        with socket.socket() as closed:
                            closed.bind(('127.0.0.1',0))
                            try:
                                with socket.create_connection(closed.getsockname(),timeout=.05): pass
                                raise RuntimeError('Unexpected listener on closed control')
                            except (ConnectionRefusedError,TimeoutError) as exc: body='connection refused' if isinstance(exc,ConnectionRefusedError) else 'probe timeout'; success=False
                    else:
                        with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
                            sock.settimeout(3); sock.sendall(b'probe\n'); body=sock.recv(512).decode(); success=bool(body)
                    log('service probe',body); artefacts[1]=True
                if continue_draw > PARAMETERS['continue_success' if success else 'continue_failure']:
                    stopped=True; break
                time.sleep(PARAMETERS['action_delay_seconds']*(bucket+1))
            if stopped and rng.random() < PARAMETERS['visit_reference_after_stop']:
                _,body=self.http(self.endpoints['reference',0][0],'/'); reference_actions=1; log('reference visit',body,'reference')
        except (OSError,EOFError,paramiko.SSHException) as exc:
            status='failed'; error=type(exc).__name__+': '+str(exc)
        finally:
            if ssh: ssh.close()
        decoy=[e for e in events if e['destination']=='decoy']
        # Duration excludes handshakes before the first observed attacker event.
        duration=max(0.,events[-1]['seconds']-events[0]['seconds']) if len(events)>1 else 0.
        return {'class':kind,'arm':arm,'seed':seed,'bucket':bucket,'status':status,'error':error,
                'actions':len(decoy),'duration':duration,'reference_actions':reference_actions,
                'artefacts':artefacts,'events':events,'fingerprint_stop':None,
                'provenance':'actual_loopback_protocol_with_scripted_agent',
                'diversion_scope':'decoy_vs_loopback_reference_surrogate_not_real_assets'}
