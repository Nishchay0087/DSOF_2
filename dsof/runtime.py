"""Shared application lifecycle and authoritative snapshots."""
import os
import secrets
import threading
from .config import Config
from .engine import Engine
from .store import Store, utcnow

class Runtime:
    def __init__(self, config=None):
        self.config = (config or Config.from_env()).validate()
        self.store = Store(self.config.db_path)
        self.store.recover()
        self.store.retain(self.config.retention_days)
        self.config.token_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.config.token_path.exists():
            fd = os.open(self.config.token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(secrets.token_urlsafe(32))
        self.token = self.config.token_path.read_text().strip()
        if len(self.token) < 24:
            raise ValueError('Invalid local control token')
        self.changed = threading.Event()
        self.engine = Engine(self.config, self.store, self.changed.set)

    def snapshot(self):
        e, s = self.engine, self.store
        return {'timestamp':utcnow(), 'collector':e.collector.status(), 'model':e.model.status(),
                'engine':e.status(), 'counts':s.counts(), 'flows':s.list('flows',100),
                'alerts':s.list('alerts',100), 'deployments':e.pots.status(),
                'sessions':s.list('sessions',100), 'errors':s.list('errors',20),
                'config':self.config.safe(), 'strategy_rankings':e.optimizer.rankings()}

    def close(self):
        self.engine.stop()
        self.store.close()
