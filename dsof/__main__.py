"""PowerShell entry point: python -m dsof check|validate|run."""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import socket
import sys
from pathlib import Path
from .config import Config, ROOT

class InstanceLock:
    def __init__(self, path=ROOT/'data'/'instance.lock'):
        path.parent.mkdir(parents=True,exist_ok=True)
        self.handle = open(path,'a+b')
        if path.stat().st_size == 0:
            self.handle.write(b'0')
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RuntimeError('Another DSOF instance holds data/instance.lock. Stop that instance first.')

    def close(self):
        self.handle.close()

class JSONFormatter(logging.Formatter):
    def format(self, record):
        from .store import utcnow
        return json.dumps({'timestamp':utcnow(),'level':record.levelname,'logger':record.name,
                           'message':record.getMessage(),'exception':self.formatException(record.exc_info) if record.exc_info else None})

def main():
    parser = argparse.ArgumentParser(description='Dynamic Security Orchestration Framework')
    parser.add_argument('command',choices=['check','validate','run'])
    args = parser.parse_args()
    try:
        config = Config.from_env()
        if args.command == 'check':
            if config.capture_mode == 'fifo':
                from urllib.request import urlopen
                from urllib.error import HTTPError
                try:
                    with urlopen(f'http://{config.host}:{config.port}/api/ready',timeout=3) as response:
                        result = json.load(response)
                except HTTPError as exc:
                    result = json.load(exc)
                except OSError as exc:
                    print(json.dumps({'ready':False,'error':'Start the backend and macOS capture helper first','detail':str(exc)},indent=2))
                    return 1
                print(json.dumps(result,indent=2))
                return 0 if result.get('ready') else 1
            from .capture import capture_prerequisites, Collector
            result = capture_prerequisites()
            collector = Collector(config.interfaces,lambda packet:None,[config.port,*config.ports.values()],config.queue_size)
            try:
                collector.start()
                result['selected_interface_probe'] = collector.status()
            finally:
                collector.stop()
            print(json.dumps(result,indent=2,default=str))
            return 0 if result['selected_interface_probe'].get('ready') else 1
        if args.command == 'validate':
            from .model import Model
            model = Model(config.artifact_dir)
            print(json.dumps(model.status(),indent=2,default=str))
            return 0 if model.status().get('ready') else 1
        lock = InstanceLock()
        app = None
        try:
            with socket.socket() as probe:
                if os.name == 'nt':
                    probe.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
                else:
                    probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                probe.bind((config.host,config.port))
            handler = RotatingFileHandler(ROOT/'data'/'dsof.log',maxBytes=2_000_000,backupCount=3,encoding='utf-8')
            handler.setFormatter(JSONFormatter())
            stream = logging.StreamHandler()
            stream.setFormatter(JSONFormatter())
            logging.basicConfig(level=logging.INFO,handlers=[handler,stream],force=True)
            from .api import create_app
            import uvicorn
            app = create_app(config)
            print(f'DSOF dashboard: http://{config.host}:{config.port}  (Ctrl+C to stop)',flush=True)
            uvicorn.run(app,host=config.host,port=config.port,log_level='info',ws='wsproto')
        finally:
            lock.close()
        return 0
    except KeyboardInterrupt:
        print('DSOF stopped; listeners and collector closed.',flush=True)
        return 0
    except Exception as exc:
        print(f'DSOF startup failed: {exc}',file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
