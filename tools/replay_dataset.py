"""Offline dataset inference replay. Never capture evidence or automatic deployment."""
import argparse
import csv
import json
from pathlib import Path
import sys
import uuid
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from dsof.config import Config
from dsof.model import Model
from dsof.store import Store,utcnow

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',default='traindata/combine.csv')
    parser.add_argument('--limit',type=int,default=20)
    parser.add_argument('--offset',type=int,default=0)
    args=parser.parse_args()
    source=(ROOT/args.file).resolve()
    if not any(source.is_relative_to(ROOT/p) for p in ('datasets','traindata')) or not 1<=args.limit<=10000 or args.offset<0:
        parser.error('Use a workspace dataset, limit 1..10000 and nonnegative offset')
    config=Config.from_env();model=Model(config.artifact_dir)
    if not model.status()['ready']:
        print(json.dumps(model.status()));return 1
    store=Store(config.db_path);accepted=rejected=0
    try:
        with source.open(newline='',encoding='utf-8-sig') as file:
            reader=csv.DictReader(file)
            names=[]
            for raw in reader.fieldnames or []:
                name=raw.strip()
                candidate=name
                suffix=1
                while candidate in names:
                    candidate=f'{name}.{suffix}';suffix+=1
                names.append(candidate)
            reader.fieldnames=names
            if not set(model.schema).issubset(reader.fieldnames or []):
                raise ValueError('CSV does not contain the exact required feature names')
            for index,row in enumerate(reader):
                if index<args.offset:continue
                if index>=args.offset+args.limit:break
                try:
                    features={key:float(row[key]) for key in model.schema}
                    result=model.predict(features)
                    record={'id':str(uuid.uuid4()),'timestamp':utcnow(),'origin':'dataset_replay','capture_derived':False,
                            'source':str(source.relative_to(ROOT)),'row_number':index+2,'dataset_label':row.get('Label',row.get('Attack Type')),
                            'ml':result,'features':features,'inspection':{'state':'not_applicable'}}
                    store.put('flows',record);accepted+=1
                    print(json.dumps({'row':index+2,'origin':'dataset_replay','ml':result}))
                except (ValueError,TypeError) as exc:
                    rejected+=1;print(json.dumps({'row':index+2,'rejected':str(exc)}))
        print(json.dumps({'accepted':accepted,'rejected':rejected,'evaluation_accuracy':None,
                          'note':'Replay of supplied data; not fresh detection or evidence of generalization'}))
        return 1 if rejected or not accepted else 0
    finally:store.close()

if __name__=='__main__':raise SystemExit(main())
