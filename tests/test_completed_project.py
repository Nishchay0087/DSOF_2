"""Operational integration tests use isolated databases and explicit fixtures."""
import os
import struct
import threading
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from dsof.api import create_app
from dsof.config import Config
from dsof.evaluation import calculate_eidp
from dsof.pcap_pipe import PipeCollector

@pytest.fixture
def client(tmp_path):
    config=Config(capture=False,db_path=tmp_path/'app.db',token_path=tmp_path/'token')
    with TestClient(create_app(config,start=False),base_url='http://localhost') as c:
        yield c,config

def test_fastapi_readiness_snapshot_and_provenance(client):
    c,_=client
    assert c.get('/api/health').status_code==200
    assert c.get('/api/ready').status_code==503
    data=c.get('/api/state').json()
    assert data['model']['ready']
    assert data['alerts']==[] and data['strategy_rankings']==[]
    assert c.post('/api/predict',json={'features':{}}).status_code==401
    assert c.get('/api/alerts?limit=0').status_code==400
    assert c.get('/api/health',headers={'Host':'evil.example'}).status_code==403

def test_fastapi_login_cookie_and_csrf(client):
    c,config=client
    assert c.post('/api/auth/login',json={'token':'wrong'}).status_code==401
    r=c.post('/api/auth/login',json={'token':config.token_path.read_text()})
    assert r.status_code==200 and 'HttpOnly' in r.headers['set-cookie']
    assert c.get('/api/auth').json()['authenticated']
    assert c.post('/api/collector/control',json={'action':'stop'},headers={'Origin':'https://evil.example'}).status_code==403
    assert c.post('/api/collector/control',json={'action':'stop'}).status_code==200
    assert c.post('/api/predict',json={'features':{},'origin':'live'}).status_code==422
    assert c.post('/api/auth/logout',json={}).status_code==200
    assert not c.get('/api/auth').json()['authenticated']

def test_fastapi_websocket_and_export(client):
    c,_=client
    with c.websocket_connect('ws://localhost/ws',headers={'Origin':'http://localhost'}) as ws:
        assert ws.receive_json()['flows']==[]
    with pytest.raises(Exception):
        with c.websocket_connect('ws://localhost/ws',headers={'Origin':'https://evil.example'}):
            pass
    r=c.get('/api/export')
    assert r.status_code==200 and 'attachment' in r.headers['content-disposition']

def test_eidp_is_reproducible_and_missing_diversion_is_not_zero():
    s={'duration_seconds':120,'interaction_count':20,'distinct_actions':5,'max_depth':4,'state':'completed'}
    assert calculate_eidp(s,prior_sessions=3,protected_connections=0)['score']==100
    result=calculate_eidp(s,prior_sessions=0,protected_connections=1)
    assert result['components']['diversion']==50 and result['score']==75
    assert calculate_eidp(s,prior_sessions=0)['score'] is None
    with pytest.raises(ValueError):
        calculate_eidp(s,prior_sessions=-1)

def test_fifo_capture_decodes_actual_pcap_format_and_disconnects(tmp_path):
    from scapy.all import IP,TCP,Raw
    path=tmp_path/'capture.pipe'
    os.mkfifo(path,0o600)
    received=[]
    collector=PipeCollector(path,['lo0'],received.append,[5050],64)
    assert collector.start()['state']=='waiting_for_sensor'
    raw=bytes(IP(src='127.0.0.1',dst='127.0.0.1')/TCP(sport=12345,dport=9090)/Raw(b'unit-fixture'))
    header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101)
    packet=struct.pack('<IIII',int(time.time()),0,len(raw),len(raw))+raw
    writer=os.open(path,os.O_WRONLY)
    try:
        # Fragment both the global header and packet record across writes.
        os.write(writer,header[:9]);os.write(writer,header[9:]+packet[:10]);os.write(writer,packet[10:])
        deadline=time.monotonic()+3
        while not received and time.monotonic()<deadline:
            time.sleep(.02)
        assert received and received[0].payload==b'unit-fixture'
        assert collector.status()['ready']
    finally:
        os.close(writer)
    deadline=time.monotonic()+3
    while collector.status()['ready'] and time.monotonic()<deadline:
        time.sleep(.02)
    assert not collector.status()['ready']
    collector.stop()
    assert not collector._reader.is_alive()

def test_real_ssh_transport_records_commands_without_execution(tmp_path):
    import paramiko
    from dsof.store import Store
    from dsof.honeypots import Orchestrator
    store=Store(tmp_path/'ssh.db')
    pots=Orchestrator(store,ports={'web':0,'ssh':0,'database':0},ssh_protocol='ssh')
    client=paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        dep=pots.ensure('ssh',origin='manual_test')
        assert dep['state']=='listening',dep
        assert store.list('sessions')==[]  # Health probe is not attacker evidence.
        client.connect('127.0.0.1',port=dep['port'],username='research',password='test-only',
                       look_for_keys=False,allow_agent=False,timeout=3)
        _,out,_=client.exec_command('whoami',timeout=3)
        assert out.read()==b'analyst\n'
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            rows=store.list('sessions')
            if rows and rows[0]['state']=='completed':break
            time.sleep(.02)
        assert rows[0]['state']=='completed'
        actions=store.list('interactions',session_id=rows[0]['id'])
        assert any(r.get('command')=='whoami' for r in actions)
        assert 'test-only' not in str(actions)
    finally:
        client.close();pots.stop_all();store.close()
