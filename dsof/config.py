"""Validated settings. All writable paths remain beneath this workspace."""
from dataclasses import dataclass, field
from pathlib import Path
import os
import platform

ROOT = Path(__file__).resolve().parent.parent

def load_env(path=ROOT / '.env'):
    if path.exists():
        for line in path.read_text(encoding='utf-8-sig').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' not in line:
                    raise ValueError('Invalid .env line; expected NAME=value')
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

def boolean(name, default):
    value = os.getenv(name, str(default)).lower()
    if value not in ('true', 'false'):
        raise ValueError(f'{name} must be true or false')
    return value == 'true'

@dataclass
class Config:
    host: str = '127.0.0.1'
    port: int = 5000
    capture: bool = True
    capture_mode: str = 'direct'
    protected_ports: list = field(default_factory=list)
    interfaces: list = field(default_factory=lambda: [r'\Device\NPF_Loopback' if platform.system() == 'Windows' else 'lo0' if platform.system() == 'Darwin' else 'lo'])
    honeypot_bind: str = '127.0.0.1'
    ports: dict = field(default_factory=lambda: {'web': 8081, 'ssh': 2222, 'database': 3307})
    allow_remote: bool = False
    ml_threshold: float = .90
    idle_timeout: float = 2
    max_duration: float = 120
    max_flows: int = 2048
    max_packets: int = 100000
    queue_size: int = 8192
    retention_days: int = 7
    db_path: Path = ROOT / 'data' / 'dsof.sqlite3'
    artifact_dir: Path = ROOT / 'artifacts' / 'traindata'
    token_path: Path = ROOT / 'data' / 'control.token'

    def validate(self):
        import ipaddress
        for addr in (self.host, self.honeypot_bind):
            try:
                parsed = ipaddress.ip_address(addr)
            except ValueError as exc:
                raise ValueError('Bind addresses must be explicit IP addresses') from exc
            if parsed.version != 4:
                raise ValueError('Service binds currently require IPv4; capture supports IPv6')
            if not parsed.is_loopback and not self.allow_remote:
                raise ValueError('Non-loopback bind requires DSOF_ALLOW_REMOTE=true')
        ports = [self.port, *self.ports.values()]
        if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(set(ports)) != 4:
            raise ValueError('API and honeypot ports must be distinct integers in 1024..65535')
        if not 0 < self.ml_threshold <= 1:
            raise ValueError('DSOF_ML_THRESHOLD must be in (0,1]')
        if not .1 <= self.idle_timeout <= self.max_duration <= 3600:
            raise ValueError('Flow timeouts require 0.1 <= idle <= max <= 3600 seconds')
        for k in ('max_flows', 'max_packets', 'queue_size'):
            if not 1 <= getattr(self, k) <= 1_000_000:
                raise ValueError(f'{k} must be in 1..1000000')
        if self.queue_size > 100000:
            raise ValueError('queue_size must not exceed 100000')
        if not 1 <= self.retention_days <= 365:
            raise ValueError('retention_days must be in 1..365')
        if self.capture and not self.interfaces:
            raise ValueError('Select at least one capture interface')
        if self.capture_mode not in ('direct','fifo'):
            raise ValueError('DSOF_CAPTURE_MODE must be direct or fifo')
        if any(type(p) is not int or not 1 <= p <= 65535 or p in ports for p in self.protected_ports):
            raise ValueError('Protected ports must be valid ports distinct from API and honeypots')
        if self.capture_mode == 'fifo' and (platform.system() == 'Windows' or len(self.interfaces) != 1):
            raise ValueError('FIFO capture requires one interface and a Unix platform')
        for path in (self.db_path, self.token_path, self.artifact_dir):
            if not Path(path).resolve().is_relative_to(ROOT):
                raise ValueError('Paths must remain inside this project workspace')
        return self

    @classmethod
    def from_env(cls):
        load_env()
        c = cls()
        for attr, env in [('host','HOST'),('honeypot_bind','HONEYPOT_BIND')]:
            setattr(c, attr, os.getenv('DSOF_' + env, getattr(c, attr)))
        for attr, env in [('port','PORT'),('max_flows','MAX_FLOWS'),('max_packets','MAX_PACKETS_PER_FLOW'),('queue_size','QUEUE_SIZE'),('retention_days','RETENTION_DAYS')]:
            setattr(c, attr, int(os.getenv('DSOF_' + env, str(getattr(c, attr)))))
        for attr, env in [('ml_threshold','ML_THRESHOLD'),('idle_timeout','FLOW_IDLE_SECONDS'),('max_duration','FLOW_MAX_SECONDS')]:
            setattr(c, attr, float(os.getenv('DSOF_' + env, str(getattr(c, attr)))))
        c.capture = boolean('DSOF_CAPTURE', True)
        c.capture_mode = os.getenv('DSOF_CAPTURE_MODE','direct')
        c.protected_ports = [int(p.strip()) for p in os.getenv('DSOF_PROTECTED_PORTS','').split(',') if p.strip()]
        c.allow_remote = boolean('DSOF_ALLOW_REMOTE', False)
        c.interfaces = [x.strip() for x in os.getenv('DSOF_INTERFACES', ','.join(c.interfaces)).split(',') if x.strip()]
        c.ports = {k:int(os.getenv('DSOF_'+k.upper()+'_PORT', str(v))) for k,v in c.ports.items()}
        return c.validate()

    def safe(self):
        return {'host':self.host,'port':self.port,'interfaces':self.interfaces,'capture_enabled':self.capture,'capture_mode':self.capture_mode,
                'honeypot_bind':self.honeypot_bind,'honeypot_ports':self.ports,'ml_threshold':self.ml_threshold,
                'flow_idle_seconds':self.idle_timeout,'flow_max_seconds':self.max_duration,
                'max_flows':self.max_flows,'queue_size':self.queue_size,'retention_days':self.retention_days,
                'redirects_traffic':False,'protected_ports':self.protected_ports,'feature_contract':'experimental_unverified'}
