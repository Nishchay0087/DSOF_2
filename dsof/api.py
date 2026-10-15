"""FastAPI control plane. Passive observation and authenticated local operations."""
import asyncio
import hmac
import secrets
import time
import html
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, StrictInt
from starlette.concurrency import run_in_threadpool
from .config import Config, ROOT
from .runtime import Runtime

class Payload(BaseModel):
    model_config = ConfigDict(extra='forbid')
class Action(Payload):
    action: str
class Login(Payload):
    token: str
class Prediction(Payload):
    features: dict
class Registration(Payload):
    test_id: str
    target_port: StrictInt
class Deployment(Payload):
    service: str


def create_app(config=None, start=True):
    config = (config or Config.from_env()).validate()
    sessions = {}
    attempts = {}
    @asynccontextmanager
    async def lifespan(app):
        runtime = Runtime(config)
        app.state.runtime = runtime
        if start:
            runtime.engine.start()
        try:
            yield
        finally:
            await run_in_threadpool(runtime.close)

    app = FastAPI(title='DSOF Research API', version='1.0.0', lifespan=lifespan,
                  docs_url=None, openapi_url='/api/openapi.json', redoc_url=None)
    def authorized(request):
        token = request.headers.get('authorization','')
        if hmac.compare_digest(token, 'Bearer '+app.state.runtime.token):
            return True
        return sessions.get(request.cookies.get('dsof_session',''), 0) > time.monotonic()

    @app.middleware('http')
    async def boundary(request, call_next):
        host = request.url.hostname
        if not config.allow_remote and host not in ('127.0.0.1','localhost',config.host):
            return JSONResponse({'error':'Unrecognized Host header'},403)
        mutation = request.method not in ('GET','HEAD','OPTIONS')
        origin = request.headers.get('origin')
        if mutation and origin and urlparse(origin).netloc != request.headers.get('host'):
            return JSONResponse({'error':'Cross-origin mutation forbidden'},403)
        if (mutation and request.url.path != '/api/auth/login') or config.allow_remote:
            if not authorized(request) and request.url.path != '/api/auth/login':
                return JSONResponse({'error':'Local control token required'},401)
        if mutation:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 65536:
                    return JSONResponse({'error':'Request exceeds 64 KiB'},413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'"})
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({'error':str(exc)},400)

    @app.get('/api/health')
    def health():
        return {'status':'running','runtime_id':app.state.runtime.engine.runtime_id}
    @app.get('/api/docs', response_class=HTMLResponse, include_in_schema=False)
    def documentation():
        schema = app.openapi()
        rows = ''.join('<tr><td>'+html.escape(method.upper())+'</td><td><code>'+html.escape(path)+'</code></td><td>'+html.escape(spec.get('summary',''))+'</td></tr>'
                       for path, methods in schema['paths'].items() for method,spec in methods.items())
        return '<!doctype html><html><head><title>DSOF API</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font:15px system-ui;margin:40px auto;padding:20px;max-width:900px;color:#203640}td{padding:12px;border-bottom:1px solid #ddd}table{width:100%;border-collapse:collapse}a{color:#176f60}</style></head><body><h1>DSOF Research API</h1><p>Read-only access is available on localhost. Mutations require the local Bearer token or an authenticated operator cookie. WebSocket snapshots: <code>/ws</code>.</p><p><a href="/api/openapi.json">Download complete OpenAPI schema</a> · <a href="/">Dashboard</a></p><table><tr><th>Method</th><th>Path</th><th>Purpose</th></tr>'+rows+'</table></body></html>'
    @app.get('/api/state')
    def state():
        return app.state.runtime.snapshot()
    @app.get('/api/ready')
    def ready():
        runtime = app.state.runtime
        collector, model = runtime.engine.collector.status(), runtime.engine.model.status()
        ok = bool(collector['ready'] and model['ready'])
        return JSONResponse({'ready':ok,'collector':collector,'model':model},200 if ok else 503)
    @app.get('/api/config')
    def settings():
        return config.safe()
    @app.get('/api/collector')
    def collector():
        return app.state.runtime.engine.collector.status()
    @app.get('/api/auth')
    def auth(request: Request):
        return {'authenticated':authorized(request)}
    @app.post('/api/auth/login')
    def login(body: Login, request: Request):
        peer = request.client.host
        now = time.monotonic()
        recent = [t for t in attempts.get(peer,[]) if now-t < 60]
        attempts[peer] = recent
        if len(recent) >= 10:
            raise HTTPException(429,'Too many attempts; wait one minute')
        recent.append(now)
        if not hmac.compare_digest(body.token,app.state.runtime.token):
            raise HTTPException(401,'Invalid token')
        for key, expiry in list(sessions.items()):
            if expiry < now:
                sessions.pop(key,None)
        if len(sessions) >= 128:
            raise HTTPException(429,'Too many active sessions')
        sid = secrets.token_urlsafe(32)
        sessions[sid] = now + 3600
        response = JSONResponse({'authenticated':True})
        response.set_cookie('dsof_session',sid,httponly=True,samesite='strict',max_age=3600,
                            secure=request.url.scheme=='https')
        return response
    @app.post('/api/auth/logout')
    def logout(request: Request):
        sessions.pop(request.cookies.get('dsof_session',''),None)
        response = JSONResponse({'authenticated':False})
        response.delete_cookie('dsof_session')
        return response
    @app.post('/api/collector/control')
    def control(body: Action):
        if body.action not in ('start','stop'):
            raise ValueError('Expected start or stop')
        if body.action == 'start' and not config.capture:
            raise HTTPException(409,'Capture disabled in configuration')
        c = app.state.runtime.engine.collector
        result = c.start() if body.action == 'start' else c.stop()
        return JSONResponse(result,503 if result['state']=='failed' else 200)
    @app.get('/api/honeypots')
    def honeypots():
        return app.state.runtime.engine.pots.status()
    @app.post('/api/honeypots')
    def deploy(body: Deployment):
        result = app.state.runtime.engine.pots.ensure(body.service,origin='manual_test')
        return JSONResponse(result,503 if result['state']=='failed' else 200)
    @app.post('/api/honeypots/stop')
    def stop_honeypots():
        app.state.runtime.engine.pots.stop_all()
        return {'stopped':True}
    @app.get('/api/strategies')
    def strategies():
        return {'rankings':app.state.runtime.engine.optimizer.rankings(), 'minimum_samples':3,
                'minimum_improvement':5,'learning_origin':'live'}
    @app.get('/api/sessions/{session_id}')
    def session(session_id: str):
        s = app.state.runtime.store
        record = s.get('sessions',session_id)
        if not record:
            raise HTTPException(404,'Session not found')
        record['interactions'] = s.list('interactions',500,session_id=session_id)
        return record
    @app.get('/api/attacks/latest')
    def latest():
        rows = app.state.runtime.store.list('alerts',1)
        return rows[0] if rows else None
    @app.post('/api/predict')
    def predict(body: Prediction):
        model = app.state.runtime.engine.model
        if not model.status()['ready']:
            raise HTTPException(503,'Model unavailable')
        return {'origin':'manual_inference','capture_derived':False,'ml':model.predict(body.features)}
    @app.post('/api/tests/register')
    def register(body: Registration, request: Request):
        if request.client.host not in ('127.0.0.1','::1','testclient'):
            raise HTTPException(403,'Loopback only')
        return app.state.runtime.engine.register_test(body.test_id,body.target_port)
    @app.get('/api/export')
    def export():
        data = app.state.runtime.snapshot()
        return JSONResponse(data,headers={'Content-Disposition':'attachment; filename="dsof-evidence.json"'})
    @app.get('/api/{table}')
    def records(table: str, request: Request, limit: int=100):
        if table not in ('flows','alerts','sessions','errors'):
            raise HTTPException(404,'Unknown resource')
        if not 1 <= limit <= 500:
            raise ValueError('limit must be 1..500')
        filters = {k:v for k,v in request.query_params.items()
                   if k in ('origin','test_id','runtime_id','flow_id','deployment_id','session_id','alert_id')}
        return app.state.runtime.store.list(table,limit,**filters)
    @app.websocket('/ws')
    async def websocket(ws: WebSocket):
        origin = ws.headers.get('origin')
        host = ws.headers.get('host','')
        if (not config.allow_remote and ws.url.hostname not in ('127.0.0.1','localhost',config.host)) or (origin and urlparse(origin).netloc != host) or (config.allow_remote and not authorized(ws)):
            await ws.close(code=1008)
            return
        await ws.accept()
        try:
            while True:
                await ws.send_json(await run_in_threadpool(app.state.runtime.snapshot))
                await asyncio.sleep(1)
        except (WebSocketDisconnect, RuntimeError):
            pass
    dist = ROOT/'frontend'/'dist'
    if (dist/'assets').exists():
        app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
    @app.get('/')
    def dashboard():
        if not (dist/'index.html').exists():
            raise HTTPException(503,'Build frontend first: pnpm --dir frontend build')
        return FileResponse(dist/'index.html')
    return app
