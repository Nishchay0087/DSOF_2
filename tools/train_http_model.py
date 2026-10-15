"""Reproducible synthetic HTTP-content experiment; payloads are inert strings."""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import joblib
import numpy as np
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report,confusion_matrix

# Split at template-family level BEFORE expansion. No captured user data is used.
TRAIN={
'BENIGN':['ordinary books about gardens','search for red shoes','order number {n}','hello {word} how are you','select your book or magazine','union of workers meeting','sleep schedule for children','confirm your booking','/search','/login','/products/{n}','user{n}@example.test','price={n}&sort=ascending','a paragraph about {word}','{"name":"{word}","quantity":{n}}','<p>Welcome {word}</p>','<strong>Title {n}</strong>','<a href="/help">Help</a>','O\'Reilly books','rock and roll music','1 + 1 = 2','document review meeting','javascript programming course','SQL SELECT tutorial','xss prevention documentation','why is this alert showing','please delete my draft','q','search','id','password','username','email','file','../../manual/chapter','normal text with "quotes"'],
'SQL_INJECTION':["' OR {n}={n} --",'" OR "{word}"="{word}" --',"{n} UNION SELECT username,password FROM users --","' AND {n}={n} #","'; SELECT name FROM accounts --","'; DROP TABLE records --","' UNION ALL SELECT NULL,NULL --","{n} AND SLEEP({n})","'; WAITFOR DELAY '0:0:5' --","' OR 'x' LIKE 'x' --","{n} UNION/**/SELECT id FROM members","' AND EXISTS(SELECT * FROM records) --"],
'XSS':['<script>alert({n})</script>','<img src=x onerror=alert({n})>','<svg onload=confirm({n})>','javascript:alert({n})','<body onload=alert({n})>','<input autofocus onfocus=alert({n})>','<iframe src="javascript:confirm({n})"></iframe>','<script>document.title="{word}"</script>','<a href="javascript:alert({n})">open</a>','<video src=x onerror=confirm({n})>','<div onmouseover=alert({n})>{word}</div>']}
VALID={
'BENIGN':['buy blue notebooks','please select a delivery date','<h2>Account settings</h2>','subscription confirmation {n}','/catalog/new','search text: SQL injection defenses'],
'SQL_INJECTION':["') OR ({n}={n}) --","{n} UNION SELECT email FROM customers --","' AND SLEEP(3)--"],
'XSS':['<button onclick=alert({n})>go</button>','<svg/onload=alert({n})>','<script>confirm("hello")</script>']}
TEST={
'BENIGN':['ordinary books','ordinary books for summer','select the green option','O\'Connor family photos','<em>Safe formatting</em>','/account/preferences','annual union membership','how to prevent cross site scripting','reset notification preferences','coffee and tea','invoice reference {n}','the sleep function in Python','javascript event handling tutorial','discussion of database queries'],
'SQL_INJECTION':["admin\') OR {n}={n}--","{n} UNION SELECT customer_name FROM invoices --","\"; SELECT balance FROM ledger --","' OR 'sun'='sun' --"],
'XSS':['<details open ontoggle=alert({n})>','<img src=missing onerror="confirm({n})">','<script>window.alert("notice")</script>','<a href=javascript:confirm({n})>continue</a>']}

def rows(groups,split):
    out=[]
    for label,templates in groups.items():
        for family,template in enumerate(templates):
            for n,word in [(2,'river'),(7,'forest'),(19,'cloud'),(43,'stone')]:
                text=template.replace('{n}',str(n)).replace('{word}',word)
                for variant in [text,text.upper()]:
                    out.append({'text':variant,'label':label,'family':f'{split}:{label}:{family}','split':split,'source':'project-authored synthetic inert HTTP field'})
    return out

def main():
    train,valid,test=rows(TRAIN,'train'),rows(VALID,'validation'),rows(TEST,'test')
    # Duplicates from case/constant templates stay within their original split.
    sets=[{r['text'].lower() for r in part} for part in (train,valid,test)]
    assert not sets[0]&sets[1] and not sets[0]&sets[2] and not sets[1]&sets[2]
    model=make_pipeline(TfidfVectorizer(analyzer='char',ngram_range=(2,5),sublinear_tf=True,max_features=30000),LogisticRegression(C=12,max_iter=1000,class_weight='balanced',random_state=42))
    model.fit([r['text'] for r in train],[r['label'] for r in train])
    classes=list(model.classes_)
    # Select threshold using validation only, favor zero observed benign false alarms.
    vp=model.predict_proba([r['text'] for r in valid]); truth=np.array([r['label'] for r in valid])
    def predict(p,t):
        winners=p.argmax(axis=1)
        return np.array([classes[i] if classes[i]=='BENIGN' or p[j,i]>=t else 'BENIGN' for j,i in enumerate(winners)])
    candidates=[]
    for threshold in [.5,.55,.6,.65,.7,.75,.8,.85,.9]:
        pred=predict(vp,threshold)
        fp=int(((truth=='BENIGN')&(pred!='BENIGN')).sum())
        correct=int(((truth!='BENIGN')&(pred==truth)).sum())
        candidates.append((fp,-correct,-threshold,threshold))
    threshold=min(candidates)[-1]
    target=ROOT/'artifacts/http_content';target.mkdir(parents=True,exist_ok=True)
    data=ROOT/'datasets/http_content_synthetic.jsonl'
    data.write_text(''.join(json.dumps(r)+'\n' for r in train+valid+test))
    joblib.dump(model,target/'model.joblib')
    reports={}
    for split,part in [('validation',valid),('test',test)]:
        pred=predict(model.predict_proba([r['text'] for r in part]),threshold)
        truth=[r['label'] for r in part]
        reports[split]={'classification_report':classification_report(truth,pred,labels=classes,output_dict=True,zero_division=0),'confusion_matrix':confusion_matrix(truth,pred,labels=classes).tolist(),'rows':len(part)}
    manifest={'version':'http-content-v1','classes':classes,'threshold':threshold,'model_sha256':hashlib.sha256((target/'model.joblib').read_bytes()).hexdigest(),'dataset_sha256':hashlib.sha256(data.read_bytes()).hexdigest(),'training_rows':len(train),'reports':reports,'provenance':'Project-authored synthetic field examples; template families assigned to splits before expansion. Not a public or real-world benchmark.','limits':['Synthetic examples do not establish real-world accuracy.','Held-out templates share attack syntax; this is not independent-source validation.','Encoded inputs use bounded URL decoding; encrypted HTTPS content is unavailable.','Probabilities are uncalibrated.']}
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (ROOT/'validation/http-content-evaluation.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'threshold':threshold,'reports':reports},indent=2))
if __name__=='__main__':main()
