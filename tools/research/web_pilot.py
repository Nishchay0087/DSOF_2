#!/usr/bin/env python3
"""Run a new, separately versioned web usability pilot on this Mac."""
import argparse
import csv
import json
from pathlib import Path
import random
import re
import sys
import time
import threading
from werkzeug.serving import make_server
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from research.human_web import VERSION, Study, create_app


def prepare(folder):
    folder.mkdir(parents=True,exist_ok=False)
    arms=[0,1,2]*6;random.Random(162026).shuffle(arms)
    with (folder/'schedule.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['session_id','participant_id','arm'])
        writer.writeheader()
        for i,arm in enumerate(arms,1):writer.writerow({'session_id':f'V2W{i:02d}','participant_id':f'V2P{i:02d}','arm':arm})
    (folder/'study.json').write_text(json.dumps({'version':VERSION,'purpose':'web usability pilot only',
        'assignment':'18 independent participants, one session each; balanced six per arm',
        'note':'Do not reuse a participant under another ID. Existing lab exposure must be disclosed. No human results prefilled.'},indent=2)+'\n')
    print('Prepared blank v2 schedule: '+str(folder/'schedule.csv'))


def serve(folder, session_id, minutes, port):
    if json.loads((folder/'study.json').read_text())['version']!=VERSION: raise ValueError('Wrong study version')
    with (folder/'schedule.csv').open() as f: rows=list(csv.DictReader(f))
    row=next((r for r in rows if r['session_id']==session_id),None)
    if row is None: raise ValueError('Session is not in this study schedule')
    # Bind before creating a participant record, so a port conflict cannot consume an ID.
    holder={}
    def dispatch(environ,start_response): return holder['app'](environ,start_response)
    server=make_server('127.0.0.1',port,dispatch,threaded=False)
    try:
        study=Study(folder/'sessions',row['session_id'],row['participant_id'],int(row['arm']),minutes)
        holder['app']=create_app(study)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        print(f'Open http://127.0.0.1:{server.server_port}/study',flush=True)
        print('Give the browser to the participant. The timer starts only after Agree and start.',flush=True)
        print('They can finish in the browser at any time. Do not run probe commands.',flush=True)
        print('Ctrl+C ends the recorder. Completed questionnaire answers are saved automatically.',flush=True)
        while True:
            study.check_timeout()
            if study.record['status']=='completed':
                print('Answers saved: '+str(study.path),flush=True)
                print('Leave this Terminal open until the participant has read the confirmation. Ctrl+C closes the service.',flush=True)
                while True: time.sleep(.25)
            time.sleep(.25)
    except KeyboardInterrupt:
        if 'study' in locals():
            study.interrupt();print('\nSaved '+str(study.path),flush=True)
    finally:
        if 'thread' in locals():server.shutdown();thread.join(3)
        server.server_close()


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('prepare');a.add_argument('--study',type=Path,default=ROOT/'research/study/web-pilot-v2')
    a=sub.add_parser('run');a.add_argument('--study',type=Path,default=ROOT/'research/study/web-pilot-v2');a.add_argument('--session',required=True);a.add_argument('--minutes',type=float,default=10);a.add_argument('--port',type=int,default=0)
    args=p.parse_args()
    if args.command=='prepare':prepare(args.study)
    else:
        if not 0<args.minutes<=30 or not 0<=args.port<=65535:p.error('Use 1–30 minutes and a valid port (0 chooses a free port).')
        if not re.fullmatch(r'V2W\d{2}',args.session):p.error('Use the scheduled V2W session ID')
        serve(args.study,args.session,args.minutes,args.port)
if __name__=='__main__':main()
