#!/usr/bin/env python3
"""Local evaluator collection and a separate facilitator analysis command."""
import argparse,json,sys
from pathlib import Path
from werkzeug.serving import make_server
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from research.ahp_form import create_app,summarize

def main():
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('run');p.add_argument('--evaluator',choices=['R01','R02','R03','R04','R05'],required=True);p.add_argument('--port',type=int,default=0)
    p=sub.add_parser('analyze');p.add_argument('--output',type=Path,default=ROOT/'output/research/AHP_Results.json')
    for p in sub.choices.values():p.add_argument('--study',type=Path,default=ROOT/'research/study/ahp-evaluators')
    args=parser.parse_args()
    if args.command=='analyze':
        result=summarize(args.study)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        if args.output.exists():parser.error('Output exists. Choose a new --output to preserve previous analysis.')
        args.output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
        print(json.dumps(result,indent=2));print('Saved '+str(args.output));return
    app=create_app(args.study,args.evaluator)
    server=make_server('127.0.0.1',args.port,app)
    print(f'Open http://127.0.0.1:{server.server_port}/',flush=True)
    print('Give the form to the named evaluator. Do not suggest answers. Ctrl+C closes it after they submit.',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:print('\nClosed; saved judgments remain in '+str(args.study))
    finally:server.server_close()
if __name__=='__main__':main()
