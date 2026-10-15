"""Real localhost protocol checks; no external hosts or operating-system commands."""
import json
from pathlib import Path
import socket
import time
import paramiko
import requests

ROOT=Path(__file__).resolve().parent.parent
base='http://127.0.0.1:5050'
client=requests.Session();client.trust_env=False
headers={'Authorization':'Bearer '+(ROOT/'data'/'control.token').read_text().strip()}
results=[]
for kind in ('ssh','database'):
    response=client.post(base+'/api/honeypots',json={'service':kind},headers=headers,timeout=10)
    response.raise_for_status();deployment=response.json()
    if deployment['state']!='listening':raise RuntimeError(deployment)
    if kind=='ssh':
        ssh=paramiko.SSHClient()
        # The expected host key is from this application's local key file.
        key=paramiko.RSAKey.from_private_key_file(str(ROOT/'data'/'ssh_host_key'))
        ssh.get_host_keys().add(f'[127.0.0.1]:{deployment["port"]}',key.get_name(),key)
        try:
            ssh.connect('127.0.0.1',port=deployment['port'],username='local-research-test',password='test-only',
                        look_for_keys=False,allow_agent=False,timeout=5)
            _,stdout,_=ssh.exec_command('whoami',timeout=5)
            assert stdout.read()==b'analyst\n'
        finally: ssh.close()
    else:
        with socket.create_connection(('127.0.0.1',deployment['port']),timeout=5) as sock:
            sock.settimeout(5);banner=sock.recv(4096)
            assert b'DSOF DATABASE' in banner
            sock.sendall(b'TABLES\nSELECT example\nQUIT\n')
            reply=b''
            while True:
                data=sock.recv(4096)
                if not data:break
                reply+=data
            assert b'audit_events' in reply and b'0 rows' in reply and b'BYE' in reply
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        response=client.get(base+'/api/sessions',params={'deployment_id':deployment['id']},timeout=5)
        response.raise_for_status()
        sessions=[s for s in response.json() if s['state']=='completed']
        if sessions:break
        time.sleep(.05)
    assert sessions and sessions[0]['interaction_count']>0
    results.append({'service':kind,'protocol':deployment['protocol'],'deployment_id':deployment['id'],
                    'session_id':sessions[0]['id'],'interactions':sessions[0]['interaction_count'],
                    'verified':'real localhost connection and persisted completed session',
                    'procedure':'manual local acceptance test; not an external attack'})
    print(f'{kind}: PASS — actual protocol, completed session, persisted interactions')
path=ROOT/'validation'/'macos-services.json';path.write_text(json.dumps(results,indent=2)+'\n')
client.close()
