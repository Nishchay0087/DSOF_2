"""Real local sockets and durable evidence; no fabricated runtime sessions."""
import http.client
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from dsof.dsi import calculate_dsi
from dsof.honeypots import Orchestrator, select_honeypot
from dsof.store import Store


def eventually(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.01)
    raise AssertionError("Expected observed state did not arrive before timeout")


@pytest.fixture
def service(tmp_path):
    store = Store(tmp_path / "sessions.sqlite3")
    manager = Orchestrator(store, ports={"web": 0, "ssh": 0, "database": 0}, idle_timeout=1)
    yield store, manager
    manager.stop_all()
    store.close()


def request(port, path="/", method="GET", headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request(method, path, body=body, headers={"Connection": "close", **(headers or {})})
    response = connection.getresponse()
    status, payload = response.status, response.read()
    connection.close()
    return status, payload


def completed(store):
    return [row for row in store.list("sessions") if row["state"] != "active"]


def test_http_actual_listener_session_and_reproducible_score(service):
    store, manager = service
    deployment = manager.ensure("web")
    assert deployment["state"] == "listening"
    assert deployment["ready_at"]
    assert store.list("sessions") == []  # Protocol health probe is excluded.
    assert manager.ensure("web")["id"] == deployment["id"]
    status, body = request(deployment["port"], "/login", "POST", body="user=secret-person&password=never-persist-this")
    assert status == 200 and b"Access denied" in body
    session = eventually(lambda: completed(store))[0]
    assert session["deployment_id"] == deployment["id"]
    assert session["interaction_count"] == 1
    assert session["distinct_actions"] == 1
    assert session["max_depth"] == 2
    assert session["duration_seconds"] >= 0
    assert session["dsi"]["provisional"] is False
    assert session["dsi"]["score"] < 20
    saved = session["dsi"]
    assert calculate_dsi(saved["inputs"], weights=saved["weights"], normalizers=saved["normalizers"]) == saved
    serialized = json.dumps(store.list("interactions") + store.list("sessions"))
    assert "secret-person" not in serialized and "never-persist-this" not in serialized
    assert store.list("interactions")[0]["action"] == "login_submission"


def test_http_keepalive_updates_provisional_then_final(service):
    store, manager = service
    deployment = manager.ensure("web")
    connection = http.client.HTTPConnection("127.0.0.1", deployment["port"], timeout=3)
    connection.request("GET", "/")
    assert connection.getresponse().read()
    first = eventually(lambda: store.list("sessions"))[0]
    assert first["state"] == "active" and first["dsi"]["provisional"]
    connection.request("GET", "/robots.txt", headers={"Connection": "close"})
    assert connection.getresponse().read()
    connection.close()
    final = eventually(lambda: completed(store))[0]
    assert final["id"] == first["id"]
    assert final["interaction_count"] == 2 and final["distinct_actions"] == 2
    assert not final["dsi"]["provisional"]


@pytest.mark.parametrize("kind,commands,expected", [
    ("ssh", b"HELP\nUSER no-secret-retention\nLIST\nQUIT\n", "directory_listing"),
    ("database", b"AUTH no-secret-retention\nTABLES\nSELECT dangerous-input-is-never-executed;\nQUIT\n", "query_attempt"),
])
def test_line_emulators_use_actual_connections(service, kind, commands, expected):
    store, manager = service
    deployment = manager.ensure(kind)
    assert deployment["state"] == "listening"
    assert not store.list("sessions")
    with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=3) as client:
        client.sendall(commands)
        received = b""
        while b"BYE" not in received:
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk
    assert b"BYE" in received
    session = eventually(lambda: completed(store))[0]
    assert session["interaction_count"] == 4
    interactions = store.list("interactions", session_id=session["id"])
    assert expected in [row["action"] for row in interactions]
    assert "no-secret-retention" not in json.dumps(interactions)
    assert "dangerous-input" not in json.dumps(interactions)


def test_known_test_id_requires_matching_peer_and_deployment(service):
    store, manager = service
    alert = store.put("alerts", {"id": "known-alert", "test_id": "known-test", "origin": "manual_test", "src": "127.0.0.1"})
    deployment = manager.ensure("web", alert_id=alert["id"], origin="manual_test")
    alert["deployment_id"] = deployment["id"]
    store.put("alerts", alert)
    request(deployment["port"], headers={"X-DSOF-Test-ID": "known-test"})
    session = eventually(lambda: completed(store))[0]
    assert session["test_id"] == "known-test" and session["origin"] == "manual_test"
    assert session["alert_id"] == "known-alert"
    assert session["id"] in store.get("alerts", "known-alert")["session_ids"]
    request(deployment["port"], headers={"X-DSOF-Test-ID": "invented-test", "X-DSOF-Origin": "manual_test"})
    rows = eventually(lambda: completed(store) if len(completed(store)) == 2 else None)
    assert next(row for row in rows if row["test_id"] is None)["origin"] == "live"
    alert["src"] = "192.0.2.7"
    store.put("alerts", alert)
    request(deployment["port"], headers={"X-DSOF-Test-ID": "known-test"})
    rows = eventually(lambda: completed(store) if len(completed(store)) == 3 else None)
    assert len([row for row in rows if row["test_id"] is None]) == 2


def test_port_conflict_fails_truthfully_and_cooldown_is_idempotent(service):
    store, manager = service
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        manager.ports["web"] = occupied.getsockname()[1]
        first = manager.ensure("web")
        second = manager.ensure("web")
    assert first["state"] == "failed" and first["ready_at"] is None
    assert first["error"] and first["id"] == second["id"]
    assert not store.list("sessions")
    assert store.list("errors")


def test_failed_readiness_never_reports_listening(service, monkeypatch):
    store, manager = service
    opened = []

    def fail_probe(server):
        opened.append(server.server_address[1])
        raise RuntimeError("Readiness response absent")

    monkeypatch.setattr(manager, "_health", fail_probe)
    deployment = manager.ensure("web")
    assert deployment["state"] == "failed"
    assert deployment["ready_at"] is None
    assert "Readiness response absent" in deployment["error"]
    assert not store.list("sessions")
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", opened[0]), timeout=.3)


def test_concurrent_ensure_keeps_one_listener(service):
    store, manager = service
    with ThreadPoolExecutor(max_workers=6) as pool:
        records = list(pool.map(lambda _: manager.ensure("web"), range(12)))
    assert len({record["id"] for record in records}) == 1
    assert all(record["state"] == "listening" for record in records)
    assert len(store.list("deployments")) == 1
    assert request(records[0]["port"])[0] == 200


def test_shutdown_closes_ports_and_finishes_active_sessions(service):
    store, manager = service
    deployment = manager.ensure("database")
    with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=2) as client:
        client.sendall(b"HELP\n")
        eventually(lambda: store.list("sessions"))
        manager.stop_all()
    session = eventually(lambda: completed(store))[0]
    assert session["state"] == "interrupted" and not session["dsi"]["provisional"]
    assert store.get("deployments", deployment["id"])["state"] == "stopped"
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", deployment["port"]), timeout=.3)


def test_bounded_connections_and_message_sizes(tmp_path):
    store = Store(tmp_path / "bounded.sqlite3")
    manager = Orchestrator(store, ports={"web": 0, "ssh": 0, "database": 0}, max_connections=1, max_body_bytes=16, idle_timeout=.5)
    try:
        deployment = manager.ensure("web")
        server = manager.servers["web"][0]
        eventually(lambda: not server.connections)
        with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=2) as held:
            held.sendall(b"GET / HTTP/1.1\r\n")
            eventually(lambda: len(server.connections) == 1)
            with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=2) as rejected:
                try:
                    assert rejected.recv(1) == b""
                except ConnectionResetError:
                    pass
            eventually(lambda: server.rejected_connections == 1)
        eventually(lambda: not server.connections)
        status, _ = request(deployment["port"], "/login", "POST", body="x" * 17)
        assert status == 413
        assert manager.status()[0]["rejected_connections"] == 1
        assert len(server.connections) <= 1
    finally:
        manager.stop_all()
        store.close()


def test_http_unsupported_chunked_requests_do_not_claim_interactions(service):
    store, manager = service
    deployment = manager.ensure("web")
    with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=2) as client:
        client.sendall(b"POST /login HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        assert b"501" in client.recv(1024)
    session = eventually(lambda: completed(store))[0]
    assert session["interaction_count"] == 0
    assert session["end_reason"] == "unsupported_transfer_encoding"


def test_line_interaction_cap_and_unsupported_unicode(service):
    store, manager = service
    manager.max_interactions = 2
    deployment = manager.ensure("ssh")
    with socket.create_connection(("127.0.0.1", deployment["port"]), timeout=2) as client:
        client.sendall("未知\nHELP\nLIST\n".encode("utf-8"))
        received = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            received += chunk
    session = eventually(lambda: completed(store))[0]
    assert session["interaction_count"] == 2
    assert session["distinct_actions"] == 1
    assert session["max_depth"] == 1
    assert session["end_reason"] == "interaction_limit"
    assert b"UNSUPPORTED" in received and b"documents logs" not in received


def test_history_and_session_evidence_survive_reopen(tmp_path):
    path = tmp_path / "persist.sqlite3"
    store = Store(path)
    manager = Orchestrator(store, ports={"web": 0, "ssh": 0, "database": 0})
    deployment = manager.ensure("web")
    request(deployment["port"])
    saved = eventually(lambda: completed(store))[0]
    manager.stop_all()
    store.close()
    reopened = Store(path)
    try:
        reopened.recover()
        manager2 = Orchestrator(reopened, ports={"web": 0, "ssh": 0, "database": 0})
        assert manager2.status()[0]["state"] == "stopped"
        assert reopened.get("sessions", saved["id"])["dsi"] == saved["dsi"]
    finally:
        reopened.close()


def test_dsi_policy_bounds_missing_invalid_and_custom_weights():
    inputs = dict(duration_seconds=60, interaction_count=10, distinct_actions=3, max_depth=2)
    assert calculate_dsi(inputs)["score"] == 52
    assert calculate_dsi({})["score"] is None
    assert calculate_dsi(dict(duration_seconds=1000, interaction_count=1000, distinct_actions=100, max_depth=100))["score"] == 100
    for invalid in (float("nan"), float("inf"), -1, True):
        with pytest.raises(ValueError):
            calculate_dsi({**inputs, "duration_seconds": invalid})
    with pytest.raises(ValueError):
        calculate_dsi({**inputs, "distinct_actions": 11})
    with pytest.raises(ValueError):
        calculate_dsi({**inputs, "interaction_count": 2.5})
    with pytest.raises(ValueError):
        calculate_dsi(inputs, weights={"duration_seconds": 1})
    with pytest.raises(ValueError):
        calculate_dsi(inputs, normalizers={"duration_seconds": 0, "interaction_count": 20, "distinct_actions": 5, "max_depth": 4})
    assert calculate_dsi(inputs, weights={"duration_seconds": 0, "interaction_count": 1, "distinct_actions": 0, "max_depth": 0})["score"] == 50


def test_selection_and_max_services(service):
    store, manager = service
    manager.max_services = 1
    assert manager.ensure("ssh")["state"] == "listening"
    assert manager.ensure("web")["state"] == "failed"
    assert select_honeypot("Brute Force", 22) == "ssh"
    assert select_honeypot("Brute Force", 3306) == "database"
    assert select_honeypot("SQL injection", 8080) == "web"
    assert select_honeypot("custom", mapping={"custom": "database"}) == "database"
    with pytest.raises(ValueError):
        manager.ensure("arbitrary")
