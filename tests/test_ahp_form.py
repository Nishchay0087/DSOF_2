import json,re
import numpy as np
from research.ahp_form import create_app,matrix_from,individual,summarize,PAIRS

def test_reciprocal_matrix():
    answers=dict(zip([p[0] for p in PAIRS],['2','4','8','2','4','2']))
    m=matrix_from(answers)
    assert np.allclose(m*m.T,1)
    assert individual(m)['consistency_ratio']<1e-10
    assert np.allclose(individual(m)['weights'],np.array([8,4,2,1])/15)

def submit(folder,identity,answers):
    client=create_app(folder,identity).test_client();base='http://127.0.0.1:5000'
    html=client.get('/',base_url=base).data.decode()
    token=re.search('name="csrf" value="([^"]+)"',html).group(1)
    return client.post('/',base_url=base,data={'csrf':token,'confirm':'on','role':'faculty',**answers},follow_redirects=True)

def test_blank_not_fabricated_and_valid_group(tmp_path):
    assert summarize(tmp_path)['weights'] is None
    equal={p[0]:'1' for p in PAIRS}
    for i in range(1,4):
        assert b'judgments are saved' in submit(tmp_path,f'R0{i}',equal).data
        result=summarize(tmp_path)
        assert (result['weights'] is not None)==(i==3)
    assert result['status']=='consistent_judgments'
    assert all(abs(x-.25)<1e-10 for x in result['weights'].values())

def test_preserve_revisions_and_do_not_drop_inconsistent_evaluator(tmp_path):
    equal={p[0]:'1' for p in PAIRS}
    for i in range(1,4):submit(tmp_path,f'R0{i}',equal)
    before=(tmp_path/'R01-001.json').read_bytes()
    bad={**equal,'E_I':'9','I_D':'9','E_D':'1/9'}
    assert b'exceed' in submit(tmp_path,'R01',bad).data
    assert (tmp_path/'R01-001.json').read_bytes()==before
    result=summarize(tmp_path)
    assert result['status']=='consistency_review_needed' and result['weights'] is None
    assert result['evaluators_submitted']==3

def test_missing_answers_cannot_be_saved(tmp_path):
    response=submit(tmp_path,'R01',{})
    assert b'Answer all six' in response.data
    assert not list(tmp_path.glob('*.json'))
