"""Independent, bounded HTTP field classifier. Raw field values are not persisted."""
import hashlib
import json
import threading
from pathlib import Path

class HTTPContentModel:
    def __init__(self, directory=None):
        self.directory=Path(directory or Path(__file__).resolve().parents[1]/'artifacts/http_content')
        self.lock=threading.Lock()
        self.model=None
        self._status={'ready':False,'version':'http-content-v1','error':None}
        try:
            import joblib
            manifest=json.loads((self.directory/'manifest.json').read_text())
            path=self.directory/'model.joblib'
            if hashlib.sha256(path.read_bytes()).hexdigest()!=manifest['model_sha256']:
                raise ValueError('HTTP model integrity mismatch')
            self.model=joblib.load(path)
            if list(self.model.classes_)!=manifest['classes'] or set(manifest['classes'])!={'BENIGN','SQL_INJECTION','XSS'}:
                raise ValueError('HTTP model classes do not match manifest')
            if not .5 <= manifest['threshold'] <= 1:
                raise ValueError('HTTP model threshold is invalid')
            self.manifest=manifest
            self._status.update(ready=True,classes=manifest['classes'],threshold=manifest['threshold'],
                                model_sha256=manifest['model_sha256'],training_provenance=manifest['provenance'],
                                evaluation=manifest['reports'],limitations=manifest['limits'])
        except Exception as exc:
            self._status['error']=f'{type(exc).__name__}: {exc}'

    def status(self):
        return dict(self._status)

    def predict_fields(self, fields):
        if not self._status['ready']:
            return {'available':False,'error':self._status['error'],'attack':False}
        # Limit work independently of request parsing. Report partial coverage.
        selected=[]; budget=32768; truncated=False
        for value,location in fields:
            if not value.strip():
                continue
            if len(selected)>=128 or budget<=0:
                truncated=True;break
            text=value[:min(4096,budget)]
            truncated |= len(text)<len(value)
            selected.append((text,location));budget-=len(text)
        if not selected:
            return {'available':True,'attack':False,'prediction':'BENIGN','probability':None,'inspected_fields':0}
        try:
            with self.lock:
                probabilities=self.model.predict_proba([v for v,_ in selected])
            classes=self.manifest['classes'];threshold=self.manifest['threshold']
            outputs=[]
            for (_,location),p in zip(selected,probabilities):
                index=int(p.argmax());label=classes[index];prob=float(p[index])
                outputs.append({'prediction':label,'probability':prob,'attack':label!='BENIGN' and prob>=threshold,
                                'probabilities':dict(zip(classes,map(float,p))),'location':location})
            winner=max(outputs,key=lambda r:(r['attack'],r['probability']))
            return {**winner,'available':True,'threshold':threshold,'inspected_fields':len(selected),
                    'coverage':'partial' if truncated else 'complete', 'model_sha256':self.manifest['model_sha256'],
                    'version':'http-content-v1','probability_calibrated':False,'training_data':'synthetic'}
        except Exception as exc:
            return {'available':False,'attack':False,'error':f'{type(exc).__name__}: HTTP content inference failed'}
