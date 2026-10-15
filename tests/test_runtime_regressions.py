"""Synthetic boundary regressions, not live network evidence."""
import subprocess
import sys
from pathlib import Path
import pytest
from dsof.__main__ import InstanceLock
from dsof.capture import Collector
from dsof.config import Config, ROOT

def test_duplicate_instance_is_actionable_and_lock_releases(tmp_path):
    path = tmp_path / 'instance.lock'
    held = InstanceLock(path)
    command = [sys.executable,'-c',
               'from pathlib import Path; from dsof.__main__ import InstanceLock; import sys; InstanceLock(Path(sys.argv[1]))',str(path)]
    try:
        blocked = subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10)
        assert blocked.returncode != 0
        assert 'Another DSOF instance' in blocked.stderr
    finally:
        held.close()
    released = subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=10)
    assert released.returncode == 0,released.stderr

def test_loopback_scope_does_not_accept_external_endpoints():
    from scapy.all import IP,TCP,Raw
    collector = Collector([r'\Device\NPF_Loopback'],lambda packet:None)
    remote = IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=12345,dport=80)/Raw(b'not loopback')
    remote.sniffed_on = r'\Device\NPF_Loopback'
    collector._on_raw(remote)
    assert collector.status()['queue_depth'] == 0
    assert collector.status()['scope_excluded_packets'] == 1
    local = IP(src='127.0.0.1',dst='127.0.0.1')/TCP(sport=12345,dport=80)/Raw(b'loopback')
    local.sniffed_on = r'\Device\NPF_Loopback'
    collector._on_raw(local)
    assert collector.status()['queue_depth'] == 1
    collector.stop()

def test_configuration_rejects_capture_queue_beyond_backend_limit():
    with pytest.raises(ValueError,match='100000'):
        Config(queue_size=100001).validate()

def test_control_api_needs_token_and_reports_disabled_capture(tmp_path):
    from dsof.app import create_app
    config = Config(capture=False,db_path=tmp_path/'test.sqlite3',token_path=tmp_path/'token')
    app = create_app(config)
    try:
        client=app.test_client()
        assert client.post('/api/collector/control',json={'action':'stop'}).status_code == 401
        headers={'Authorization':'Bearer '+config.token_path.read_text()}
        assert client.post('/api/collector/control',headers=headers,json={'action':'unknown'}).status_code == 400
        assert client.post('/api/collector/control',headers=headers,json={'action':'start'}).status_code == 409
        result=client.post('/api/collector/control',headers=headers,json={'action':'stop'})
        assert result.status_code == 200 and not result.json['ready']
    finally:
        app.extensions['dsof_shutdown']()
