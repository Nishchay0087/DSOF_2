import hmac
import json
import logging
import secrets
import threading
import time
import uuid
from urllib.parse import urlparse
from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO
from werkzeug.exceptions import HTTPException
from .config import Config
from .engine import Engine
from .store import Store, utcnow

def create_app(config=None, start=False):
    config = (config or Config.from_env()).validate()
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=64*1024, JSON_SORT_KEYS=False)
    socketio = SocketIO(app, async_mode='threading', logger=False, engineio_logger=False,
                        cors_allowed_origins=None, max_http_buffer_size=65536)
    store = Store(config.db_path)
    store.recover()
    store.retain(config.retention_days)
    config.token_path.parent.mkdir(parents=True,exist_ok=True)
    if not config.token_path.exists():
        config.token_path.write_text(secrets.token_urlsafe(32),encoding='utf-8')
    token = config.token_path.read_text(encoding='utf-8').strip()
    if len(token) < 24:
        raise ValueError('Control token file must contain at least 24 characters')
    changed = threading.Event()
    engine = Engine(config,store,changed.set)
    app.extensions.update(dsof_engine=engine,dsof_store=store,dsof_socketio=socketio)
    stop_broadcast = threading.Event()

    @app.before_request
    def local_boundary():
        host = request.host.split(':')[0].lower()
        allowed = {'127.0.0.1','localhost',config.host}
        if not config.allow_remote and host not in allowed:
            return jsonify(error='Unrecognized Host header'),403
        if request.method not in ('GET','HEAD','OPTIONS'):
            if request.headers.get('Origin') and urlparse(request.headers['Origin']).netloc != request.host:
                return jsonify(error='Cross-origin mutation forbidden'),403
            provided = request.headers.get('Authorization','')
            if not hmac.compare_digest(provided,'Bearer '+token):
                return jsonify(error='Local control token required'),401

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.description),exc.code

    @app.errorhandler(ValueError)
    def validation_error(exc):
        return jsonify(error=str(exc)),400

    @app.errorhandler(Exception)
    def server_error(exc):
        engine.error('api',str(exc))
        return jsonify(error='Internal error; see operational errors'),500

    @app.after_request
    def security_headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'"
        return response

    def payload():
        if not request.is_json:
            raise ValueError('Expected application/json')
        data = request.get_json()
        if not isinstance(data,dict):
            raise ValueError('Expected a JSON object')
        return data

    def records(table):
        limit = int(request.args.get('limit',100))
        if not 1 <= limit <= 500:
            raise ValueError('limit must be 1..500')
        filters = {}
        for key in ('origin','test_id','runtime_id','flow_id','deployment_id','session_id','alert_id'):
            if key in request.args:
                filters[key] = request.args[key]
        if 'origin' in filters and filters['origin'] not in ('live','manual_test','dataset_replay','manual_inference','operational'):
            raise ValueError('Unknown origin')
        return store.list(table,limit,**filters)

    def state():
        return {'timestamp':utcnow(),'collector':engine.collector.status(),'model':engine.model.status(),
                'engine':engine.status(),'counts':store.counts(),'flows':store.list('flows',50),
                'alerts':store.list('alerts',100),'deployments':engine.pots.status(),
                'sessions':store.list('sessions',100),'errors':store.list('errors',20),'config':config.safe(),
                'strategy_rankings':engine.optimizer.rankings()}

    @app.get('/')
    def dashboard():
        return render_template('index.html')

    @app.get('/api/health')
    def health():
        return jsonify(status='running',timestamp=utcnow(),runtime_id=engine.runtime_id)

    @app.get('/api/ready')
    def ready():
        collector, model = engine.collector.status(), engine.model.status()
        ok = collector.get('ready',False) and model.get('ready',False)
        return jsonify(ready=ok,collector=collector,model=model),200 if ok else 503

    @app.get('/api/state')
    def api_state():
        return jsonify(state())

    @app.get('/api/collector')
    def collector():
        return jsonify(engine.collector.status())

    @app.get('/api/config')
    def configuration():
        return jsonify(config.safe())

    @app.post('/api/collector/control')
    def collector_control():
        data = payload()
        if set(data) != {'action'} or data['action'] not in ('start','stop'):
            raise ValueError('Expected action start or stop')
        if data['action'] == 'start' and not config.capture:
            return jsonify(error='Capture disabled in configuration; enable and restart'),409
        result = engine.collector.start() if data['action'] == 'start' else engine.collector.stop()
        changed.set()
        return jsonify(result),503 if result.get('state') == 'failed' else 200

    @app.get('/api/flows')
    def flows():
        return jsonify(records('flows'))

    @app.get('/api/alerts')
    def alerts():
        return jsonify(records('alerts'))

    @app.get('/api/attacks/latest')
    def latest():
        rows = records('alerts')
        return jsonify(rows[0] if rows else None)

    @app.get('/api/honeypots')
    def honeypots():
        return jsonify(engine.pots.status())

    @app.get('/api/strategies')
    def strategies():
        return jsonify(rankings=engine.optimizer.rankings(), minimum_samples=3,
                       minimum_improvement=5, learning_origin='live')

    @app.get('/api/sessions')
    def sessions():
        return jsonify(records('sessions'))

    @app.get('/api/sessions/<session_id>')
    def session(session_id):
        result = store.get('sessions',session_id)
        if not result:
            return jsonify(error='Session not found'),404
        result['interactions'] = store.list('interactions',500,session_id=session_id)
        return jsonify(result)

    @app.get('/api/errors')
    def errors():
        return jsonify(records('errors'))

    @app.post('/api/predict')
    def predict():
        data = payload()
        if set(data) != {'features'}:
            raise ValueError('Only features is allowed; provenance cannot be submitted')
        if not engine.model.status().get('ready'):
            return jsonify(error='Model unavailable',model=engine.model.status()),503
        result = engine.model.predict(data['features'])
        return jsonify(origin='manual_inference',capture_derived=False,ml=result)

    @app.post('/api/tests/register')
    def register_test():
        data = payload()
        if set(data) != {'test_id','target_port'}:
            raise ValueError('Expected only test_id and target_port')
        if request.remote_addr not in ('127.0.0.1','::1'):
            return jsonify(error='Fresh-test registration is loopback only'),403
        return jsonify(engine.register_test(data['test_id'],data['target_port']))

    @socketio.on('connect')
    def connected(auth=None):
        if not config.allow_remote and request.host.split(':')[0] not in ('127.0.0.1','localhost',config.host):
            return False
        socketio.emit('state',state(),to=request.sid)

    def broadcast():
        while not stop_broadcast.wait(1):
            # A periodic authoritative snapshot detects capture state changes even when no events arrive.
            try:
                socketio.emit('state',state())
                changed.clear()
            except Exception:
                logging.exception('State broadcast failed')

    def shutdown():
        stop_broadcast.set()
        engine.stop()
        if hasattr(app,'broadcast_thread'):
            app.broadcast_thread.join(timeout=3)
        store.close()
    app.extensions['dsof_shutdown'] = shutdown
    if start:
        engine.start()
        app.broadcast_thread = threading.Thread(target=broadcast,daemon=True,name='dsof-dashboard')
        app.broadcast_thread.start()
    return app
