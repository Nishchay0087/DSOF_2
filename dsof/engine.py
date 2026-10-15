"""Trusted capture pipeline. No public endpoint can call ingest or create an alert."""
import hashlib
import json
import logging
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path
from .capture import Collector
from .flows import FlowTracker
from .http_detect import HTTPStream
from .model import Model
from .http_model import HTTPContentModel
from .honeypots import Orchestrator
from .store import utcnow
from .strategy import StrategyOptimizer

class Engine:
    def __init__(self, config, store, notify=None):
        self.config, self.store = config, store
        self.optimizer = StrategyOptimizer(store)
        self.protected_connections = deque(maxlen=10000)
        self.telemetry_lock = threading.Lock()
        self.telemetry_overflow_at = 0
        self.notify = notify or (lambda: None)
        self.runtime_id = str(uuid.uuid4())
        self.started_at = utcnow()
        self.model = Model(config.artifact_dir)
        self.http_model = HTTPContentModel()
        self.lock = threading.RLock()
        self.tracker = FlowTracker(max_flows=config.max_flows, idle_timeout=config.idle_timeout,
                                   max_duration=config.max_duration, max_packets=config.max_packets)
        self.streams, self.requests, self.tests = {}, {}, {}
        self.stop_event = threading.Event()
        self.last_error = None
        self.processed_flows = 0
        self.latency_ms = None
        self.policy = json.loads((Path(__file__).resolve().parent.parent/'config.policy.json').read_text())
        if set(self.policy.values()) - {'web','ssh','database'}:
            raise ValueError('config.policy.json supports only web, ssh, database responses')
        dsi_policy = json.loads((Path(__file__).resolve().parent.parent/'config.dsi.json').read_text())
        if set(dsi_policy) != {'weights','normalizers'}:
            raise ValueError('config.dsi.json must contain weights and normalizers')
        self.pots = Orchestrator(store, bind=config.honeypot_bind, ports=config.ports, on_change=self.notify,
                                 dsi_weights=dsi_policy['weights'],dsi_normalizers=dsi_policy['normalizers'],ssh_protocol='ssh',
                                 ssh_host_key_path=config.db_path.parent/'ssh_host_key')
        self.collector = Collector(interfaces=config.interfaces, callback=self._captured_packet,
                                   excluded_ports=[config.port,*config.ports.values()], queue_size=config.queue_size)
        if config.capture_mode == 'fifo':
            from .pcap_pipe import PipeCollector
            from .config import ROOT
            self.collector = PipeCollector(ROOT/'data'/'capture.pipe',config.interfaces,self._captured_packet,
                                           [config.port,*config.ports.values()],config.queue_size)
        self.pots.evaluate = self.evaluate_session

    def evaluate_session(self, session):
        from .evaluation import evaluate_session
        start = datetime.fromisoformat(session['started_at']).timestamp()
        status = self.collector.status()
        count = None
        coverage = {'protected_ports':self.config.protected_ports,'interfaces':self.config.interfaces,
                    'collector_ready':status.get('ready'), 'kernel_drops':'unknown',
                    'scope':'Configured interfaces and ports only; source IP is not an identity'}
        if (self.config.protected_ports and status.get('ready') and status.get('ready_since',float('inf')) <= start
                and not status.get('queue_dropped_packets') and not status.get('callback_errors') and not status.get('queue_depth')):
            with self.telemetry_lock:
                if self.telemetry_overflow_at < start:
                    count = sum(1 for ts, src in self.protected_connections if ts >= start and src == session['remote_address'])
        return evaluate_session(self.store,session,count,coverage)

    def start(self):
        self.worker = threading.Thread(target=self._tick,name='dsof-flow-finalizer',daemon=True)
        self.worker.start()
        if self.config.capture:
            try:
                self.collector.start()
                if not self.collector.status().get('ready') and self.collector.status().get('state') != 'waiting_for_sensor':
                    self.error('capture_start',self.collector.status().get('last_error','Capture did not become ready'))
            except Exception as exc:
                self.error('capture_start', str(exc))
        self.notify()

    def error(self, component, message):
        self.last_error = {'component':component,'message':str(message)[:1000], 'timestamp':utcnow()}
        logging.error(json.dumps(self.last_error))
        try:
            self.store.put('errors',self.last_error)
        except Exception:
            logging.exception('Could not persist operational error')
        self.notify()

    def register_test(self, test_id, port):
        if not isinstance(test_id,str):
            raise ValueError('test_id must be a UUID string')
        test_id = str(uuid.UUID(test_id))
        if type(port) is not int or not 1024 <= port <= 65535 or port in [self.config.port,*self.config.ports.values()]:
            raise ValueError('Test target_port must be a non-control port in 1024..65535')
        with self.lock:
            self.tests = {k:v for k,v in self.tests.items() if v['expires'] > time.time()}
            if len(self.tests) >= 128:
                raise ValueError('Too many registered tests; wait for existing registrations to expire')
            self.tests[test_id] = {'port':port,'expires':time.time()+120}
        return {'test_id':test_id,'target_port':port,'expires_in_seconds':120}

    def _captured_packet(self, packet):
        with self.lock:
            flow = self.tracker.ingest(packet)
            if flow is None:
                return
            if flow.packets == 1 and flow.dport in self.config.protected_ports:
                with self.telemetry_lock:
                    if len(self.protected_connections) == self.protected_connections.maxlen:
                        self.telemetry_overflow_at = time.time()
                    self.protected_connections.append((packet.ts,packet.src))
            if flow.protocol == 'TCP' and packet.src == flow.src and packet.sport == flow.sport:
                stream = self.streams.setdefault(flow.id, HTTPStream(classifier=self.http_model.predict_fields))
                result = stream.feed(packet.seq, packet.payload, syn=bool(packet.flags & 2))
                if result:
                    self.requests.setdefault(flow.id, []).extend(result)
            if hasattr(self.tracker, 'drain_evicted'):
                for old in self.tracker.drain_evicted():
                    self._finish(old, 'resource_limit')

    def _tick(self):
        last_retention = time.monotonic()
        while not self.stop_event.wait(.2):
            try:
                with self.lock:
                    for flow in self.tracker.expire(time.time()):
                        self._finish(flow,'timeout')
                    self.tests = {k:v for k,v in self.tests.items() if v['expires'] > time.time()}
                    # Defensive cleanup if a tracker implementation discards evicted flows.
                    if len(self.streams) > self.config.max_flows:
                        for key in list(self.streams)[:len(self.streams)-self.config.max_flows]:
                            self.streams.pop(key,None)
                            self.requests.pop(key,None)
                if time.monotonic()-last_retention > 3600:
                    self.store.retain(self.config.retention_days)
                    last_retention = time.monotonic()
            except Exception as exc:
                self.error('flow_processing', str(exc))

    def _finish(self, flow, reason):
        if self.store.get('flows',flow.id):
            return
        stream = self.streams.pop(flow.id,None)
        requests = self.requests.pop(flow.id,[])
        origin, test_id = 'live', None
        rules = []
        for req in requests:
            candidate = req.get('test_id')
            registered = self.tests.get(candidate)
            if registered and registered['expires'] > time.time() and registered['port'] == flow.dport and flow.src in ('127.0.0.1','::1') and flow.dst in ('127.0.0.1','::1'):
                origin, test_id = 'manual_test', candidate
            for rule in req.get('rules',[]):
                if rule not in rules:
                    rules.append(rule)
        content_results = [r['http_ml'] for r in requests if r.get('http_ml')]
        http_ml = max(content_results, key=lambda r:(r.get('attack',False),r.get('probability') or 0), default=None)
        content_attack = bool(http_ml and http_ml.get('attack'))
        ml, features, feature_error = None, None, None
        try:
            features = flow.features(self.model.schema or None)
            ml = self.model.predict(features)
        except Exception as exc:
            feature_error = str(exc)[:500]
        summary = flow.summary()
        summary.update(id=flow.id,timestamp=utcnow(),origin=origin,runtime_id=self.runtime_id,
                       src=flow.src,dst=flow.dst,sport=flow.sport,dport=flow.dport,protocol=flow.protocol,
                       test_id=test_id,ml=ml,http_ml=http_ml,feature_error=feature_error,features=features,
                       inspection=stream.status() if stream else {'state':'not_applicable'},
                       request_inspections=[r.get('inspection') for r in requests[:32]], completion_reason=reason)
        self.store.put('flows',summary)
        self.processed_flows += 1
        ml_attack = bool(ml and ml['prediction'] not in self.model.benign_labels and ml['probability'] >= self.config.ml_threshold)
        if not rules and not ml_attack and not content_attack:
            self.notify()
            return
        alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL,'dsof:alert:'+flow.id))
        if self.store.get('alerts',alert_id):
            return
        category = 'Web Attacks' if rules or content_attack else ml['prediction']
        components = (['Flow ML'] if ml_attack else []) + (['HTTP ML'] if content_attack else []) + (['HTTP rule'] if rules else [])
        kind = self.policy.get(category,'web')
        if category == 'Brute Force' and flow.dport in (1433,1521,3306,5432):
            kind = 'database'
        profile = self.optimizer.profile(flow.src, origin)
        decision = self.optimizer.choose(category, profile, kind, origin,
                                         self.pots.dsi_weights, self.pots.dsi_normalizers,
                                         {'protected_ports':self.config.protected_ports,'interfaces':self.config.interfaces})
        kind = decision['selected']
        self.latency_ms = max(0, (time.time()-flow.last)*1000)
        alert = {'id':alert_id,'timestamp':utcnow(),'flow_id':flow.id,'src':flow.src,'dst':flow.dst,
                 'sport':flow.sport,'dport':flow.dport,'protocol':flow.protocol,'origin':origin,
                 'runtime_id':self.runtime_id,'test_id':test_id,'detection_source':' + '.join(components),'detection_components':components,
                 'ml':ml,'http_ml':http_ml,'feature_error':feature_error,'rules':rules[:16],'classification':category,
                 'capture_derived':True,'response_selected':kind,'response_outcome':'requested',
                 'attacker_profile':profile,'strategy_decision':decision,
                 'deployment_id':None,'session_ids':[], 'latency_since_last_packet_ms':self.latency_ms,
                 'meaning':'Suspicious traffic or attempted request; successful exploitation is not established'}
        self.store.put('alerts',alert)
        self.notify()
        try:
            deployment = self.pots.ensure(kind,alert_id=alert_id,origin=origin)
            alert = self.store.get('alerts',alert_id) or alert
            alert.update(deployment_id=deployment['id'],response_outcome=deployment['state'])
            self.store.put('alerts',alert)
        except Exception as exc:
            alert['response_outcome'] = 'failed'
            alert['response_error'] = str(exc)[:500]
            self.store.put('alerts',alert)
            self.error('orchestration',str(exc))
        self.notify()

    def status(self):
        with self.lock:
            return {'runtime_id':self.runtime_id,'started_at':self.started_at,'processed_flows':self.processed_flows,
                    'last_error':self.last_error,'last_detection_latency_ms':self.latency_ms,
                    'http_content_model':self.http_model.status(),'flow_tracker':self.tracker.status()}

    def stop(self):
        self.collector.stop()
        self.stop_event.set()
        if hasattr(self,'worker'):
            self.worker.join(timeout=10)
        with self.lock:
            for flow in self.tracker.expire(time.time()+self.config.max_duration+1):
                self._finish(flow,'shutdown')
        self.pots.stop_all()
