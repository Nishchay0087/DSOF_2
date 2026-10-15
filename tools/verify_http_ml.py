"""Live localhost smoke test: requires actual HTTP-content ML predictions."""
import contextlib,io,json
from pathlib import Path
from fresh_test import run

results=[]
for case,expected in [('sqli','SQL_INJECTION'),('xss','XSS'),('benign','BENIGN')]:
    with contextlib.redirect_stdout(io.StringIO()):
        result=run('http://127.0.0.1:5050',benign=case=='benign',attack='sqli' if case=='benign' else case)
    content=result.get('http_ml') or {}
    if not content.get('available') or content.get('prediction')!=expected or bool(content.get('attack'))!=(case!='benign'):
        raise RuntimeError(f'{case}: HTTP ML expectation failed: {content}')
    if case=='benign' and result.get('ml_alerts'):
        raise RuntimeError('Benign control generated an alert')
    results.append(result)
    print(f'{case}: PASS — HTTP ML {content["prediction"]} ({content["probability"]:.3f}); flow ML {result["original_ml"]["prediction"]}',flush=True)
path=Path(__file__).resolve().parents[1]/'validation/http-ml-live.json'
path.write_text(json.dumps({'meaning':'Live smoke tests of known syntax; not held-out accuracy evaluation','results':results},indent=2)+'\n')
print(f'Evidence: {path}')
