import json
import pytest
from research.human_web import Study, create_app


def setup(tmp_path,arm=1):
    study=Study(tmp_path,'TEST','PTEST',arm,10)
    client=create_app(study).test_client()
    return study,client

def post(client,study,path,**data):
    return client.post(path,data={'csrf':study.token,**data},base_url='http://127.0.0.1:5059',follow_redirects=True)

def get(client,path):return client.get(path,base_url='http://127.0.0.1:5059',follow_redirects=True)

def begin(c,s):return post(c,s,'/begin',consent='on',prior='no')

def test_consent_and_real_browser_task(tmp_path):
    s,c=setup(tmp_path)
    assert b'Before you begin' in get(c,'/reports').data
    assert s.record['actions']==0 and s.record['started_at'] is None
    begin(c,s)
    assert b'not accepted' in post(c,s,'/login',username='demo',password='wrong').data
    assert b'Invoice workspace' in post(c,s,'/login',username='demo',password='demo').data
    assert b'Cedar Labs' in get(c,'/reports?q=INV-1042').data
    assert b'Pending review' in get(c,'/reports/INV-1042').data
    assert b'was saved' in post(c,s,'/reports/INV-1042',note='Check purchase order').data
    assert b'Check purchase order' in get(c,'/reports/INV-1042').data
    assert b'Your observations' in post(c,s,'/finish',reason='task_complete').data
    assert s.record['stop_reason']=='task_complete'
    result=post(c,s,'/feedback',rating='2',suspicion='broken',task_result='yes',when='First login',reason='Test input')
    assert b'answers have been saved' in result.data
    saved=json.loads(s.path.read_text())
    assert saved['status']=='completed' and saved['feedback']['interpretation']=='broken'
    assert saved['dsi'] is None and 'wrong' not in s.path.read_text()
    s.interrupt();assert s.record['status']=='completed'

def test_reject_arm_still_has_usable_help_and_voluntary_finish(tmp_path):
    s,c=setup(tmp_path,0);begin(c,s)
    assert b'not accepted' in post(c,s,'/login',username='demo',password='demo').data
    assert b'Cannot proceed' in get(c,'/help').data
    post(c,s,'/finish',reason='cannot_proceed')
    post(c,s,'/feedback',rating='1',suspicion='neither',task_result='no')
    assert s.record['status']=='completed' and s.record['stop_reason']=='cannot_proceed'

def test_archive_is_arm_specific(tmp_path):
    s,c=setup(tmp_path,2);begin(c,s);post(c,s,'/login',username='demo',password='demo')
    assert b'purchasing archive' in get(c,'/reports/INV-1042').data
    assert b'account owner' in get(c,'/archive').data

def test_csrf_no_overwrite_and_escaping(tmp_path):
    s,c=setup(tmp_path)
    assert c.post('/begin',data={'consent':'on','prior':'no'},base_url='http://127.0.0.1:5059').status_code==403
    assert c.get('/study',base_url='http://evil.test:5059').status_code==403
    with pytest.raises(ValueError):Study(tmp_path,'TEST','PTEST',1,10)
    begin(c,s);post(c,s,'/login',username='demo',password='demo')
    response=post(c,s,'/reports/INV-1042',note='<script>alert(1)</script>')
    assert b'<script>' not in response.data and b'&lt;script&gt;' in response.data
    count=s.record['actions']; get(c,'/favicon.ico');get(c,'/health')
    assert count==s.record['actions']

def test_timeout_and_feedback_missing_fields(tmp_path):
    s,c=setup(tmp_path);begin(c,s)
    s.start_mono-=601;s.check_timeout()
    assert s.record['stop_reason']=='time_limit'
    assert post(c,s,'/feedback',rating='1').status_code==400
    assert s.record['feedback'] is None
