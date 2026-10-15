"""Bounded local emulators. No submitted command, SQL, file or credential is used."""

from __future__ import annotations

import datetime as dt
import hmac
import logging
import re
import secrets
import socket
import socketserver
import threading
import time
import uuid
from urllib.parse import urlsplit

from .dsi import calculate_dsi, validate_policy

LOG = logging.getLogger(__name__)
TEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
KINDS = {"web", "ssh", "database"}


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


class _BoundedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, address, owner, deployment):
        self.owner = owner
        self.deployment = deployment
        self.health_token = secrets.token_urlsafe(32)
        self.capacity = threading.BoundedSemaphore(owner.max_connections)
        self.connection_lock = threading.Lock()
        self.connections = set()
        self.workers = set()
        self.rejected_connections = 0
        self.stopping = threading.Event()
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.rejected_connections += 1
            self.shutdown_request(request)
            return
        with self.connection_lock:
            self.connections.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            with self.connection_lock:
                self.connections.discard(request)
            self.capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        thread = threading.current_thread()
        with self.connection_lock:
            self.workers.add(thread)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.connection_lock:
                self.connections.discard(request)
                self.workers.discard(thread)
            self.capacity.release()

    def handle_error(self, request, client_address):
        self.owner._error("honeypot_handler", "A session handler failed; inspect server logs", self.deployment["id"])
        LOG.exception("Honeypot session handler failed")

    def close_sessions(self):
        self.stopping.set()
        with self.connection_lock:
            connections = list(self.connections)
            workers = list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=2)


class _Session:
    def __init__(self, server, peer, started, started_at, test_id=None):
        self.server = server
        self.owner = server.owner
        self.started = started
        self.actions = set()
        deployment = server.deployment
        alert = None
        matched_test_id = None
        if test_id and TEST_ID.fullmatch(test_id):
            rows = self.owner.store.list("alerts", limit=1, test_id=test_id)
            if rows and rows[0].get("src") == peer[0] and rows[0].get("deployment_id") == deployment["id"]:
                alert = rows[0]
                matched_test_id = test_id
        if alert is None:
            candidates = self.owner.store.list('alerts',1,deployment_id=deployment['id'],src=peer[0],origin='live')
            if candidates:
                candidate = candidates[0]
                age = dt.datetime.now(dt.timezone.utc).timestamp()-dt.datetime.fromisoformat(candidate['timestamp']).timestamp()
                if 0 <= age <= 300:
                    alert = candidate
        self.record = {
            "id": str(uuid.uuid4()), "timestamp": utcnow(),
            "deployment_id": deployment["id"],
            "alert_id": alert["id"] if alert else None,
            "test_id": matched_test_id,
            "association": "known_test_id" if matched_test_id else "deployment_trigger" if alert else "unattributed",
            "origin": alert.get("origin", "live") if alert else "live",
            "service": deployment["kind"],
            "remote_address": peer[0], "remote_port": peer[1],
            "started_at": started_at, "ended_at": None,
            "duration_seconds": 0.0, "interaction_count": 0,
            "distinct_actions": 0, "max_depth": 0, "state": "active",
        }
        self.persist(provisional=True)

    def persist(self, provisional):
        self.record["duration_seconds"] = round(max(0, time.monotonic() - self.started), 6)
        self.record["dsi"] = calculate_dsi(
            self.record, provisional=provisional,
            weights=self.owner.dsi_weights, normalizers=self.owner.dsi_normalizers,
        )
        from .evaluation import evaluate_session
        evaluator = getattr(self.owner,'evaluate',None)
        self.record['evaluation'] = evaluator(self.record) if evaluator else evaluate_session(self.owner.store,self.record)
        self.owner.store.put("sessions", self.record)
        if self.record.get("alert_id"):
            # Sessions also have a relational alert_id; the bounded convenience
            # list is for event consumers, not the canonical complete query.
            with self.owner.store.lock:
                alert = self.owner.store.get("alerts", self.record["alert_id"])
                if alert and self.record["id"] not in alert.get("session_ids", []):
                    alert["session_ids"] = (alert.get("session_ids", []) + [self.record["id"]])[-100:]
                    self.owner.store.put("alerts", alert)
        self.owner._notify()

    def interaction(self, action, depth, *, method=None, byte_count=0, **details):
        if action not in ("unknown_path", "unsupported_method", "unsupported_input"):
            self.actions.add(action)
        self.record["interaction_count"] += 1
        self.record["distinct_actions"] = len(self.actions)
        self.record["max_depth"] = max(self.record["max_depth"], depth)
        evidence = {
            "id": str(uuid.uuid4()), "timestamp": utcnow(),
            "session_id": self.record["id"], "origin": self.record["origin"],
            "action": action, "depth": depth, "byte_count": byte_count,
        }
        if method is not None:
            evidence["method"] = method
        evidence.update(details)
        self.owner.store.put("interactions", evidence)
        self.persist(provisional=True)

    def finish(self, reason):
        self.record["state"] = "interrupted" if self.server.stopping.is_set() else "completed"
        self.record["end_reason"] = reason
        self.record["ended_at"] = utcnow()
        self.persist(provisional=False)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.session = None
        self.started = time.monotonic()
        self.started_at = utcnow()
        self.deadline = self.started + self.server.owner.session_timeout
        self.buffer = b""
        self.total_bytes = 0
        self.is_health = False
        reason = "peer_closed"
        try:
            if self.server.deployment['kind'] == 'ssh' and self.server.owner.ssh_protocol == 'ssh':
                from .ssh_service import serve
                reason = serve(self)
            elif self.server.deployment["kind"] == "web":
                reason = self.http()
            else:
                reason = self.lines()
        except (TimeoutError, socket.timeout):
            reason = "timeout"
        except (ConnectionError, OSError):
            reason = "connection_closed"
        except ValueError:
            reason = "protocol_or_resource_limit"
        finally:
            # A connection without application data remains real evidence, but a
            # positively authenticated internal health probe is excluded.
            if not self.is_health and self.session is None:
                self.open_session()
            if self.session:
                self.session.finish(reason)

    def open_session(self, test_id=None):
        if self.session is None:
            self.session = _Session(self.server, self.client_address, self.started, self.started_at, test_id)
        return self.session

    def recv(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.request.settimeout(min(remaining, self.server.owner.idle_timeout))
        chunk = self.request.recv(4096)
        self.total_bytes += len(chunk)
        if self.total_bytes > self.server.owner.max_session_bytes:
            raise ValueError("session byte limit")
        return chunk

    def read_until(self, delimiter, limit):
        while delimiter not in self.buffer:
            if len(self.buffer) >= limit:
                raise ValueError("message limit")
            chunk = self.recv()
            if not chunk:
                return None
            self.buffer += chunk
        message, self.buffer = self.buffer.split(delimiter, 1)
        if len(message) + len(delimiter) > limit:
            raise ValueError("message limit")
        return message

    def send_http(self, status, body, *, close=True, content_type="text/html; charset=utf-8"):
        payload = body.encode("utf-8")
        self.request.sendall(
            (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(payload)}\r\n"
             f"Connection: {'close' if close else 'keep-alive'}\r\n"
             "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
             "Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'\r\n\r\n").encode("ascii") + payload
        )

    def http(self):
        for _ in range(self.server.owner.max_interactions):
            header = self.read_until(b"\r\n\r\n", self.server.owner.max_header_bytes)
            if header is None:
                return "peer_closed"
            lines = header.decode("iso-8859-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
                self.send_http("400 Bad Request", "Invalid HTTP/1 request")
                return "invalid_request"
            method, target, version = parts
            if not re.fullmatch(r"[A-Z]{1,16}", method):
                raise ValueError("invalid method")
            if len(lines) > 100:
                raise ValueError("header count limit")
            headers = {}
            for line in lines[1:]:
                if ":" not in line or line[:1].isspace():
                    raise ValueError("invalid header")
                key, value = line.split(":", 1)
                key = key.strip().lower()
                if key in headers:
                    raise ValueError("ambiguous duplicate header")
                headers[key] = value.strip()
            token = headers.get("x-dsof-health", "")
            if self.session is None and target == "/__dsof_health" and method == "GET" and hmac.compare_digest(token.encode("utf-8"), self.server.health_token.encode("ascii")):
                self.is_health = True
                self.send_http("200 OK", "DSOF-READY", content_type="text/plain")
                return "health_probe"
            self.open_session(headers.get("x-dsof-test-id"))
            if "transfer-encoding" in headers:
                self.send_http("501 Not Implemented", "Chunked request bodies are unsupported")
                return "unsupported_transfer_encoding"
            length_value = headers.get("content-length", "0")
            if not length_value.isascii() or not length_value.isdigit():
                raise ValueError("invalid content length")
            length = int(length_value)
            if length > self.server.owner.max_body_bytes:
                self.send_http("413 Content Too Large", "Request body limit exceeded")
                return "body_limit"
            while len(self.buffer) < length:
                chunk = self.recv()
                if not chunk:
                    return "incomplete_body"
                self.buffer += chunk
            # Intentionally discard bodies and query strings; never store them.
            self.buffer = self.buffer[length:]
            try:
                path = urlsplit(target).path
            except ValueError:
                return "invalid_target"
            close = headers.get("connection", "").lower() == "close" or version == "HTTP/1.0"
            if method not in ("GET", "HEAD", "POST"):
                action, depth = "unsupported_method", 0
                status, body = "405 Method Not Allowed", "Supported methods: GET, HEAD, POST"
            elif path == "/login" and method == "POST":
                action, depth = "login_submission", 2
                status, body = "200 OK", "<h1>Emulated application</h1><p>Login attempt recorded. Access denied.</p>"
            elif path == "/login":
                action, depth = "login_page", 1
                status, body = "200 OK", '<h1>Emulated application login</h1><form method="post" action="/login"><label>User <input name="user"></label><label>Password <input type="password" name="password"></label><button>Sign in</button></form>'
            elif path == "/admin":
                action, depth = "restricted_area", 2
                status, body = "403 Forbidden", "<h1>Emulated application</h1><p>Access denied.</p>"
            elif path in ("/search", "/api/query"):
                action, depth = "application_query", 2
                status, body = "200 OK", "<h1>Emulated application</h1><p>No records.</p>"
            elif path == "/robots.txt":
                action, depth = "robots_request", 1
                status, body = "200 OK", "User-agent: *\nDisallow: /admin\n"
            elif path == "/":
                action, depth = "landing_page", 1
                status, body = "200 OK", '<h1>DSOF emulated application</h1><p><a href="/login">Login</a></p>'
            else:
                action, depth = "unknown_path", 0
                status, body = "404 Not Found", "<h1>Emulated application</h1><p>Not found.</p>"
            self.session.interaction(action, depth, method=method, byte_count=len(header) + 4 + length)
            self.send_http(status, "" if method == "HEAD" else body, close=close)
            if close:
                return "request_complete"
        return "interaction_limit"

    def lines(self):
        kind = self.server.deployment["kind"]
        banner = "SSH-2.0-DSOF_EMULATOR\r\nThis is a line emulator, not SSH. Commands: HELP, USER, AUTH, LIST, QUIT.\r\n" if kind == "ssh" else "DSOF DATABASE LINE EMULATOR. Commands: HELP, AUTH, TABLES, SELECT, QUIT.\r\n"
        self.request.sendall(banner.encode("ascii"))
        for _ in range(self.server.owner.max_interactions):
            raw = self.read_until(b"\n", self.server.owner.max_line_bytes)
            if raw is None:
                return "peer_closed"
            line = raw.rstrip(b"\r").decode("utf-8", errors="replace")
            if self.session is None and hmac.compare_digest(raw.rstrip(b"\r"), ("DSOF-HEALTH " + self.server.health_token).encode("ascii")):
                self.is_health = True
                self.request.sendall(b"DSOF-READY\r\n")
                return "health_probe"
            self.open_session()
            verb = line.split(" ", 1)[0].upper()
            if verb == "QUIT":
                action, depth, reply = "quit", 0, "BYE"
            elif verb == "HELP":
                action, depth, reply = "help", 1, "Emulation only; no submitted commands or queries execute."
            elif verb in ("AUTH", "USER"):
                action, depth, reply = "authentication_attempt", 2, "DENIED"
            elif kind == "ssh" and verb == "LIST":
                action, depth, reply = "directory_listing", 2, "EMULATED: documents logs"
            elif kind == "database" and verb in ("SHOW", "TABLES"):
                action, depth, reply = "table_listing", 2, "EMULATED: audit_events"
            elif kind == "database" and verb == "SELECT":
                action, depth, reply = "query_attempt", 3, "EMULATED: 0 rows"
            else:
                action, depth, reply = "unsupported_input", 0, "UNSUPPORTED; nothing executed"
            self.session.interaction(action, depth, byte_count=len(raw) + 1)
            self.request.sendall((reply + "\r\n").encode("ascii"))
            if verb == "QUIT":
                return "quit"
        return "interaction_limit"


class Orchestrator:
    """Idempotent process-local listener management; store writes are durable.

    ``on_change()`` is an optional no-argument notification callback. Its errors
    cannot terminate a listener. A failed deployment is returned as a record.
    """

    def __init__(self, store, bind="127.0.0.1", ports=None, on_change=None, **limits):
        allowed = {"ssh_host_key_path", "ssh_protocol", "max_connections", "max_services", "session_timeout", "idle_timeout", "max_interactions", "max_header_bytes", "max_body_bytes", "max_line_bytes", "max_session_bytes", "cooldown_seconds", "dsi_weights", "dsi_normalizers"}
        unknown = set(limits) - allowed
        if unknown:
            raise ValueError("Unknown honeypot limits: " + ", ".join(sorted(unknown)))
        self.store, self.bind, self.on_change = store, bind, on_change
        self.ssh_protocol = limits.get('ssh_protocol','line')
        if self.ssh_protocol not in ('line','ssh'):
            raise ValueError('SSH protocol must be line or ssh')
        if self.ssh_protocol == 'ssh':
            import paramiko
            key_path = limits.get('ssh_host_key_path')
            if key_path and key_path.exists():
                self.ssh_host_key = paramiko.RSAKey.from_private_key_file(str(key_path))
            else:
                self.ssh_host_key = paramiko.RSAKey.generate(2048)
                if key_path:
                    import os
                    with os.fdopen(os.open(key_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
                        self.ssh_host_key.write_private_key(stream)
        self.ports = dict(ports or {"web": 8081, "ssh": 2222, "database": 3307})
        if set(self.ports) != KINDS:
            raise ValueError("Honeypot ports must define web, ssh and database")
        if any(isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535 for port in self.ports.values()):
            raise ValueError("Honeypot ports must be integers between 0 and 65535")
        defaults = dict(max_connections=16, max_services=3, session_timeout=30.0, idle_timeout=5.0, max_interactions=50, max_header_bytes=16384, max_body_bytes=32768, max_line_bytes=4096, max_session_bytes=131072, cooldown_seconds=2.0)
        for key, default in defaults.items():
            value = limits.get(key, default)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 10_000_000:
                raise ValueError(f"Honeypot {key} must be positive and bounded")
            if key not in ("session_timeout", "idle_timeout", "cooldown_seconds") and not isinstance(value, int):
                raise ValueError(f"Honeypot {key} must be an integer")
            setattr(self, key, value)
        self.dsi_weights, self.dsi_normalizers = validate_policy(limits.get("dsi_weights"), limits.get("dsi_normalizers"))
        self.lock = threading.RLock()
        self.servers = {}
        self.latest = {}
        self.last_attempt = {}

    def _notify(self):
        if self.on_change:
            try:
                self.on_change()
            except Exception:
                LOG.exception("Honeypot update callback failed")

    def _error(self, component, message, deployment_id=None):
        try:
            self.store.put("errors", {"id": str(uuid.uuid4()), "timestamp": utcnow(), "component": component, "message": message, "deployment_id": deployment_id})
        except Exception:
            LOG.exception("Cannot persist honeypot error")

    def _state(self, record, state, **fields):
        record.update(state=state, updated_at=utcnow(), **fields)
        self.store.put("deployments", record)
        self._notify()

    def _health(self, server):
        address = self.bind
        if address == "0.0.0.0":
            address = "127.0.0.1"
        elif address == "::":
            address = "::1"
        if server.deployment['kind'] == 'ssh' and self.ssh_protocol == 'ssh':
            from .ssh_service import health
            health(server,address,server.server_address[1])
            return
        with socket.create_connection((address, server.server_address[1]), timeout=2) as probe:
            probe.settimeout(2)
            if server.deployment["kind"] == "web":
                probe.sendall((f"GET /__dsof_health HTTP/1.1\r\nHost: localhost\r\nX-DSOF-Health: {server.health_token}\r\nConnection: close\r\n\r\n").encode("ascii"))
            else:
                probe.sendall(("DSOF-HEALTH " + server.health_token + "\n").encode("ascii"))
            result = b""
            while len(result) < 4096 and b"DSOF-READY" not in result:
                chunk = probe.recv(1024)
                if not chunk:
                    break
                result += chunk
            if b"DSOF-READY" not in result:
                raise RuntimeError("Listener did not pass its protocol readiness probe")

    def ensure(self, kind, alert_id=None, origin="live"):
        if kind not in KINDS:
            raise ValueError("Supported honeypot kinds: web, ssh, database")
        if origin not in ("live", "manual_test", "manual test", "dataset_replay", "dataset replay", "replay", "historical"):
            raise ValueError("Invalid traffic origin")
        with self.lock:
            self.status()
            if kind in self.servers:
                record = self.latest[kind]
                if alert_id:
                    record["latest_alert_id"] = alert_id
                    record["related_alert_ids"] = list(dict.fromkeys(record.get("related_alert_ids", []) + [alert_id]))[-100:]
                    self.store.put("deployments", record)
                return dict(record)
            now = time.monotonic()
            if kind in self.last_attempt and now - self.last_attempt[kind] < self.cooldown_seconds:
                return dict(self.latest[kind])
            self.last_attempt[kind] = now
            record = {
                "id": str(uuid.uuid4()), "timestamp": utcnow(), "kind": kind,
                "emulated": True, "bind": self.bind, "port": self.ports[kind],
                "protocol": self.ssh_protocol if kind == 'ssh' else 'http' if kind == 'web' else 'line',
                "alert_id": alert_id, "origin": origin, "state": "requested",
                "latest_alert_id": alert_id, "related_alert_ids": [alert_id] if alert_id else [],
                "ready_at": None, "error": None, "rejected_connections": 0,
            }
            self.latest[kind] = record
            self._state(record, "requested")
            if len(self.servers) >= self.max_services:
                self._state(record, "failed", error="Maximum concurrent honeypot services reached")
                return dict(record)
            self._state(record, "starting")
            server = None
            thread = None
            try:
                # bind/listen is atomic; a separate port availability check has a race.
                server = _BoundedServer((self.bind, self.ports[kind]), self, record)
                record["port"] = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, name=f"dsof-honeypot-{kind}", daemon=True)
                thread.start()
                self._health(server)
                self.servers[kind] = (server, thread)
                self._state(record, "listening", ready_at=utcnow())
            except Exception as exc:
                if server:
                    if thread and thread.is_alive():
                        server.shutdown()
                    server.close_sessions()
                    server.server_close()
                self._state(record, "failed", error=f"{type(exc).__name__}: {exc}")
                self._error("honeypot_start", record["error"], record["id"])
            return dict(record)

    def status(self):
        with self.lock:
            for kind, (server, thread) in list(self.servers.items()):
                record = self.latest[kind]
                if not thread.is_alive() or server.socket.fileno() == -1:
                    self._state(record, "failed", error="Listener thread or socket stopped unexpectedly")
                    server.close_sessions()
                    server.server_close()
                    del self.servers[kind]
                elif record.get("rejected_connections") != server.rejected_connections:
                    record["rejected_connections"] = server.rejected_connections
                    self.store.put("deployments", record)
            return self.store.list("deployments", limit=100)

    def stop_all(self):
        with self.lock:
            for kind, (server, thread) in list(self.servers.items()):
                server.stopping.set()
                server.shutdown()
                server.close_sessions()
                server.server_close()
                thread.join(timeout=3)
                self._state(self.latest[kind], "stopped", stopped_at=utcnow())
            self.servers.clear()


def select_honeypot(category, destination_port=None, mapping=None):
    """Small configurable policy shared by the detector and API documentation."""
    if mapping and category in mapping:
        selected = mapping[category]
        if selected not in KINDS:
            raise ValueError(f"Unsupported mapped honeypot: {selected}")
        return selected
    normalized = str(category).lower().replace("_", " ")
    if "brute" in normalized:
        return "database" if destination_port in (1433, 1521, 3306, 5432, 27017) else "ssh"
    if "sql" in normalized or "database" in normalized:
        return "web" if destination_port in (80, 443, 8000, 8080) or "injection" in normalized else "database"
    return "web"
