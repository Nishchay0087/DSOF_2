"""Small parameterized SQLite repository with referential integrity and migrations."""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

TABLES = {'flows': (), 'alerts': ('flow_id',), 'deployments': ('alert_id',),
          'sessions': ('deployment_id', 'alert_id'), 'interactions': ('session_id',), 'errors': ()}
REFERENCES = {'flow_id':'flows', 'alert_id':'alerts', 'deployment_id':'deployments', 'session_id':'sessions'}

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')

class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self.conn.execute('PRAGMA foreign_keys=ON')
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA busy_timeout=10000')
        version = self.conn.execute('PRAGMA user_version').fetchone()[0]
        if version > 1:
            raise ValueError('Database schema is newer than this application; use matching DSOF version')
        with self.conn:
            for table, refs in TABLES.items():
                cols = ''.join(f', {r} TEXT REFERENCES {REFERENCES[r]}(id) ON DELETE SET NULL' for r in refs)
                self.conn.execute(f'CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, origin TEXT NOT NULL, data TEXT NOT NULL{cols})')
                self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_time ON {table}(timestamp DESC)')
                self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_origin ON {table}(origin, timestamp DESC)')
                for ref in refs:
                    self.conn.execute(f'CREATE INDEX IF NOT EXISTS idx_{table}_{ref} ON {table}({ref})')
            self.conn.execute('PRAGMA user_version=1')

    def put(self, table, record):
        if table not in TABLES:
            raise ValueError('Unknown table')
        record = dict(record)
        record.setdefault('id', str(uuid.uuid4()))
        record.setdefault('timestamp', utcnow())
        record.setdefault('origin', 'operational')
        refs = TABLES[table]
        cols = ['id','timestamp','origin','data',*refs]
        values = [record['id'],record['timestamp'],record['origin'],json.dumps(record,allow_nan=False),*(record.get(r) for r in refs)]
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)}) ON CONFLICT(id) DO UPDATE SET " + ','.join(f'{c}=excluded.{c}' for c in cols[1:])
        with self.lock, self.conn:
            self.conn.execute(sql, values)
        return record

    def get(self, table, record_id):
        if table not in TABLES:
            raise ValueError('Unknown table')
        with self.lock:
            row = self.conn.execute(f'SELECT data FROM {table} WHERE id=?',(record_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, table, limit=100, **filters):
        if table not in TABLES or not 1 <= int(limit) <= 10000:
            raise ValueError('Invalid table or limit')
        clauses, args = [], []
        for key,value in filters.items():
            if not key.replace('_','').isalnum():
                raise ValueError('Invalid filter')
            if key in ('id','timestamp','origin',*TABLES[table]):
                clauses.append(f'{key}=?')
            else:
                clauses.append('json_extract(data, ?) = ?')
                args.append('$.'+key)
            args.append(value)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        with self.lock:
            rows = self.conn.execute(f'SELECT data FROM {table}{where} ORDER BY timestamp DESC, id DESC LIMIT ?',(*args,int(limit))).fetchall()
        return [json.loads(r[0]) for r in rows]

    def counts(self):
        with self.lock:
            return {t:dict(self.conn.execute(f'SELECT origin,COUNT(*) FROM {t} GROUP BY origin').fetchall()) for t in ('flows','alerts','sessions')}

    def recover(self):
        from .dsi import calculate_dsi
        for dep in self.list('deployments',10000):
            if dep.get('state') in ('requested','starting','listening'):
                dep.update(state='stopped', last_error='Previous process ended; listener is not running', stopped_at=utcnow())
                self.put('deployments',dep)
        for session in self.list('sessions',10000):
            if session.get('state') == 'active':
                session.update(state='interrupted', ended_at=utcnow(), recovery_note='Duration ends at last recorded evidence; process downtime excluded')
                # The recorded duration is retained; never infer engagement during downtime.
                if session.get('dsi'):
                    session['dsi']['provisional'] = False
                if session.get('evaluation'):
                    session['evaluation']['provisional'] = False
                self.put('sessions',session)

    def retain(self, days):
        cutoff = (datetime.now(timezone.utc)-timedelta(days=days)).isoformat(timespec='milliseconds')
        # Remove leaves first. Keep parents referenced by newer records.
        with self.lock, self.conn:
            self.conn.execute('DELETE FROM interactions WHERE timestamp < ? AND session_id NOT IN (SELECT id FROM sessions WHERE timestamp >= ?)',(cutoff,cutoff))
            self.conn.execute('DELETE FROM sessions WHERE timestamp < ? AND id NOT IN (SELECT session_id FROM interactions WHERE session_id IS NOT NULL)',(cutoff,))
            self.conn.execute('DELETE FROM deployments WHERE timestamp < ? AND id NOT IN (SELECT deployment_id FROM sessions WHERE deployment_id IS NOT NULL)',(cutoff,))
            self.conn.execute('DELETE FROM alerts WHERE timestamp < ? AND id NOT IN (SELECT alert_id FROM deployments WHERE alert_id IS NOT NULL UNION SELECT alert_id FROM sessions WHERE alert_id IS NOT NULL)',(cutoff,))
            self.conn.execute('DELETE FROM flows WHERE timestamp < ? AND id NOT IN (SELECT flow_id FROM alerts WHERE flow_id IS NOT NULL)',(cutoff,))
            self.conn.execute('DELETE FROM errors WHERE timestamp < ?',(cutoff,))

    def close(self):
        with self.lock:
            self.conn.close()
