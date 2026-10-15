"""API, persistence and trust-boundary verification.

Packet objects and seeded database records here are explicitly synthetic unit-test
fixtures. They live in disposable workspace databases and are never live-capture
validation evidence. The original model is loaded without retraining or replacement.
"""
import json
from pathlib import Path
import socket
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from dsof.app import create_app
from dsof.config import Config, ROOT
from dsof.dsi import calculate_dsi
from dsof.flows import Flow, Packet
from dsof.store import Store, utcnow


def unused_ports(count=4):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for sock in sockets:
            sock.close()


def unit_flow(target_port=19090, src="127.0.0.1", dst="127.0.0.1", correlation=None):
    """Construct measured features from explicit packets, never a feature shortcut."""
    now = time.time()
    payload = b"GET /search?q=%27+OR+1%3D1-- HTTP/1.1\r\nHost: localhost\r\n"
    if correlation:
        payload += f"X-DSOF-Test-ID: {correlation}\r\n".encode()
    payload += b"\r\n"
    packets = [Packet(now, src, dst, 45678, target_port, "TCP", seq=100, flags=2, window=8192),
               Packet(now + .01, dst, src, target_port, 45678, "TCP", seq=500, flags=18, window=16384),
               Packet(now + .02, src, dst, 45678, target_port, "TCP", payload=payload, seq=101, flags=24, window=8192)]
    flow = Flow(packets[0])
    for packet in packets[1:]:
        flow.add(packet)
    return flow, packets


class APIEngineTests(unittest.TestCase):
    def setUp(self):
        (ROOT / "data").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="test-api-", dir=ROOT / "data")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        ports = unused_ports()
        self.config = Config(capture=False, port=ports[0],
                             ports=dict(zip(("web", "ssh", "database"), ports[1:])),
                             db_path=self.directory / "test.sqlite3", token_path=self.directory / "control.token")
        self.app = create_app(self.config, start=False)
        self.addCleanup(self.app.extensions["dsof_shutdown"])
        self.client = self.app.test_client()
        self.engine = self.app.extensions["dsof_engine"]
        self.store = self.app.extensions["dsof_store"]
        self.auth = {"Authorization": "Bearer " + self.config.token_path.read_text().strip()}
        self.assertTrue(self.engine.model.status()["ready"], self.engine.model.status()["error"])

    def finish_packets(self, *, target_port=19090, src="127.0.0.1", dst="127.0.0.1", correlation=None):
        _, packets = unit_flow(target_port, src, dst, correlation)
        for packet in packets:
            self.engine._captured_packet(packet)
        finished = self.engine.tracker.expire(packets[-1].ts + self.config.max_duration + 1)
        self.assertEqual(len(finished), 1)
        self.engine._finish(finished[0], "synthetic_unit_fixture")
        return finished[0]

    def test_readiness_distinguishes_web_server_from_capture(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        readiness = self.client.get("/api/ready")
        self.assertEqual(readiness.status_code, 503)
        self.assertFalse(readiness.json["ready"])
        self.assertTrue(readiness.json["model"]["ready"])
        self.assertFalse(readiness.json["collector"]["ready"])
        self.assertEqual(self.client.get("/api/attacks/latest").json, None)
        self.assertEqual(self.client.get("/api/alerts").json, [])

    def test_token_authentication_protects_mutations(self):
        for headers in ({}, {"Authorization": "Bearer wrong-token"}):
            response = self.client.post("/api/predict", json={"features": {}}, headers=headers)
            self.assertEqual(response.status_code, 401)
        response = self.client.post("/api/predict", json={"features": {}}, headers=self.auth)
        self.assertEqual(response.status_code, 400)
        self.assertIn("missing", response.json["error"])

    def test_public_caller_cannot_forge_detector_provenance_or_create_alert(self):
        for forged in ({"origin": "live"}, {"capture_derived": True}, {"rules": []}, {"test_id": str(uuid.uuid4())}):
            response = self.client.post("/api/predict", json={"features": {}, **forged}, headers=self.auth)
            self.assertEqual(response.status_code, 400)
            self.assertIn("provenance", response.json["error"])
        self.assertEqual(self.client.post("/api/alerts", json={}, headers=self.auth).status_code, 405)
        self.assertEqual(self.store.list("alerts"), [])

    def test_host_and_cross_origin_mutation_boundaries(self):
        self.assertEqual(self.client.get("/api/state", headers={"Host": "untrusted.example"}).status_code, 403)
        headers = {**self.auth, "Origin": "https://untrusted.example"}
        response = self.client.post("/api/predict", json={"features": {}}, headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Cross-origin", response.json["error"])

    def test_wrong_content_and_malformed_json_have_clear_client_errors(self):
        cases = [("text/plain", "hello"), ("application/json", "[]"),
                 ("application/json", "{broken"), ("application/json", "null")]
        for content_type, data in cases:
            with self.subTest(data=data):
                response = self.client.post("/api/predict", data=data, content_type=content_type, headers=self.auth)
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.json)
        response = self.client.post("/api/predict", data="x" * 70000, content_type="application/json", headers=self.auth)
        self.assertEqual(response.status_code, 413)

    def test_malformed_model_features_are_rejected_without_creating_alerts(self):
        flow, _ = unit_flow()
        valid = flow.features(self.engine.model.schema)
        variants = [[], {**valid, "Destination Port": "80"}, {**valid, "Destination Port": True},
                    {**valid, "Flow Duration": float("nan")}, {**valid, "Flow Duration": float("inf")},
                    {**valid, "Destination Port": 65536}, {**valid, "Flow Duration": -1},
                    {**valid, "made_up": 1}, {k: v for k, v in valid.items() if k != "Flow Duration"}]
        for features in variants:
            response = self.client.post("/api/predict", json={"features": features}, headers=self.auth)
            self.assertEqual(response.status_code, 400, response.json)
        self.assertEqual(self.store.list("alerts"), [])

    def test_manual_inference_preserves_model_output_and_is_not_capture(self):
        flow, _ = unit_flow()
        expected = self.engine.model.predict(flow.features(self.engine.model.schema))
        response = self.client.post("/api/predict", json={"features": flow.features(self.engine.model.schema)}, headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["origin"], "manual_inference")
        self.assertFalse(response.json["capture_derived"])
        self.assertEqual(response.json["ml"]["prediction"], expected["prediction"])
        self.assertEqual(response.json["ml"]["probability"], expected["probability"])
        self.assertEqual(self.store.list("alerts"), [])
        self.assertEqual(self.store.list("flows"), [])

    def test_query_limits_unknown_origins_missing_session_and_safe_config(self):
        for path in ("/api/alerts?limit=0", "/api/alerts?limit=501", "/api/flows?limit=abc", "/api/alerts?origin=forged"):
            self.assertEqual(self.client.get(path).status_code, 400)
        self.assertEqual(self.client.get("/api/sessions/missing").status_code, 404)
        response = self.client.get("/api/config")
        encoded = json.dumps(response.json)
        self.assertNotIn(self.config.token_path.read_text().strip(), encoded)
        self.assertNotIn("token_path", encoded)
        self.assertFalse(response.json["redirects_traffic"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_test_registration_validates_types_scope_and_remote_source(self):
        correlation = str(uuid.uuid4())
        good = {"test_id": correlation, "target_port": 19090}
        self.assertEqual(self.client.post("/api/tests/register", json=good, headers=self.auth).status_code, 200)
        bad = [{**good, "target_port": True}, {**good, "target_port": "19090"},
               {**good, "target_port": 80}, {**good, "target_port": self.config.port},
               {**good, "test_id": "not-a-uuid"}, {**good, "test_id": 123},
               {**good, "test_id": None}, {**good, "origin": "live"}]
        for data in bad:
            with self.subTest(data=data):
                self.assertEqual(self.client.post("/api/tests/register", json=data, headers=self.auth).status_code, 400)
        response = self.client.post("/api/tests/register", json=good, headers=self.auth,
                                    environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
        self.assertEqual(response.status_code, 403)

    def test_flow_finalization_is_idempotent_and_preserves_original_ml(self):
        correlation = str(uuid.uuid4())
        self.engine.register_test(correlation, 19090)
        flow = self.finish_packets(correlation=correlation)
        first = self.store.get("flows", flow.id)
        alerts = self.store.list("alerts")
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertIn(alert['attacker_profile']['level'], ('Beginner','Intermediate','Advanced'))
        self.assertEqual(alert['strategy_decision']['selected'], alert['response_selected'])
        self.assertEqual(self.client.get('/api/strategies').json['rankings'], [])
        self.assertIn('strategy_rankings', self.client.get('/api/state').json)
        self.assertEqual(alert["origin"], "manual_test")
        self.assertEqual(alert["rules"][0]["name"], "sql_boolean_comparison")
        expected = self.engine.model.predict(flow.features(self.engine.model.schema))
        self.assertEqual(alert["ml"]["prediction"], expected["prediction"])
        self.assertEqual(alert["ml"]["probability"], expected["probability"])
        deployments_before = self.store.list("deployments")
        processed_before = self.engine.processed_flows
        self.engine._finish(flow, "synthetic_duplicate_processing")
        self.assertEqual(len(self.store.list("alerts")), 1)
        self.assertEqual(self.store.list("deployments"), deployments_before)
        self.assertEqual(self.store.get("flows", flow.id), first)
        self.assertEqual(self.engine.processed_flows, processed_before)

    def test_test_origin_requires_live_registration_port_and_both_loopback_addresses(self):
        cases = [({}, True), ({"target_port": 19091}, False),
                 ({"src": "192.0.2.2"}, False), ({"dst": "192.0.2.3"}, False),
                 ({"registered": False}, False), ({"expired": True}, False)]
        for overrides, expected_manual in cases:
            with self.subTest(overrides=overrides):
                correlation = str(uuid.uuid4())
                if overrides.get("registered", True):
                    self.engine.register_test(correlation, 19090)
                if overrides.get("expired"):
                    self.engine.tests[correlation]["expires"] = time.time() - 1
                parameters = {k: v for k, v in overrides.items() if k in ("target_port", "src", "dst")}
                flow = self.finish_packets(correlation=correlation, **parameters)
                record = self.store.get("flows", flow.id)
                self.assertEqual(record["origin"], "manual_test" if expected_manual else "live")
                self.assertEqual(record["test_id"], correlation if expected_manual else None)

    def test_socket_connection_and_reconnect_restore_authoritative_snapshot(self):
        socketio = self.app.extensions["dsof_socketio"]
        first = socketio.test_client(self.app, flask_test_client=self.client)
        self.assertTrue(first.is_connected())
        initial = [r for r in first.get_received() if r["name"] == "state"]
        self.assertEqual(len(initial), 1)
        self.assertEqual(initial[0]["args"][0]["alerts"], [])
        first.disconnect()
        seeded = self.store.put("flows", {"origin": "dataset_replay", "fixture": "synthetic unit test"})
        second = socketio.test_client(self.app, flask_test_client=self.client)
        self.addCleanup(lambda: second.disconnect() if second.is_connected() else None)
        restored = [r for r in second.get_received() if r["name"] == "state"][0]["args"][0]
        self.assertIn(seeded["id"], {row["id"] for row in restored["flows"]})
        self.assertEqual(restored["counts"]["flows"]["dataset_replay"], 1)
        self.assertFalse(restored["collector"]["ready"])

    def test_database_api_failure_returns_error_and_persists_operational_detail(self):
        with patch.object(self.store, "list", side_effect=sqlite3.OperationalError("synthetic test database read failure")):
            response = self.client.get("/api/flows")
        self.assertEqual(response.status_code, 500)
        self.assertIn("Internal error", response.json["error"])
        errors = self.store.list("errors")
        self.assertEqual(errors[0]["component"], "api")
        self.assertIn("synthetic test database", errors[0]["message"])


class MissingModelTests(unittest.TestCase):
    def test_missing_artifacts_keep_health_but_fail_readiness_and_inference(self):
        with tempfile.TemporaryDirectory(prefix="test-missing-model-", dir=ROOT / "data") as tmp:
            directory = Path(tmp)
            config = Config(capture=False, db_path=directory / "missing.sqlite3", token_path=directory / "token",
                            artifact_dir=directory / "missing-artifacts")
            app = create_app(config, start=False)
            try:
                client = app.test_client()
                self.assertEqual(client.get("/api/health").status_code, 200)
                response = client.get("/api/ready")
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.json["model"]["ready"])
                self.assertIn("Missing required", response.json["model"]["error"])
                auth = {"Authorization": "Bearer " + config.token_path.read_text().strip()}
                response = client.post("/api/predict", json={"features": {}}, headers=auth)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json["error"], "Model unavailable")
            finally:
                app.extensions["dsof_shutdown"]()


class StorePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test-store-", dir=ROOT / "data")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "store.sqlite3"

    def test_foreign_keys_parameterized_strings_and_origin_counts(self):
        store = Store(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                store.put("alerts", {"flow_id": "does-not-exist", "origin": "live"})
            suspicious = "x'; DROP TABLE flows;--"
            first = store.put("flows", {"id": suspicious, "origin": "live"})
            store.put("flows", {"origin": "dataset_replay"})
            store.put("flows", {"origin": "manual_test"})
            alert = store.put("alerts", {"flow_id": first["id"], "origin": "live"})
            self.assertEqual(store.get("flows", suspicious), first)
            self.assertEqual(store.list("alerts", flow_id=suspicious), [alert])
            self.assertEqual(store.counts()["flows"], {"live": 1, "dataset_replay": 1, "manual_test": 1})
            self.assertEqual(store.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            with self.assertRaises(ValueError):
                store.list("alerts", **{"x); DROP TABLE flows;--": "x"})
        finally:
            store.close()

    def test_restart_recovers_persisted_links_without_inventing_engagement(self):
        inputs = {"duration_seconds": 2.5, "interaction_count": 1, "distinct_actions": 1, "max_depth": 1}
        dsi = calculate_dsi(inputs, provisional=True)
        store = Store(self.path)
        flow = store.put("flows", {"origin": "manual_test"})
        alert = store.put("alerts", {"origin": "manual_test", "flow_id": flow["id"]})
        deployment = store.put("deployments", {"origin": "manual_test", "alert_id": alert["id"], "state": "listening"})
        session = store.put("sessions", {"origin": "manual_test", "deployment_id": deployment["id"],
                                          "alert_id": alert["id"], "state": "active", "dsi": dsi, **inputs})
        interaction = store.put("interactions", {"origin": "manual_test", "session_id": session["id"], "action": "synthetic_unit_fixture"})
        store.close()
        reopened = Store(self.path)
        try:
            reopened.recover()
            self.assertEqual(reopened.get("deployments", deployment["id"])["state"], "stopped")
            result = reopened.get("sessions", session["id"])
            self.assertEqual(result["state"], "interrupted")
            self.assertFalse(result["dsi"]["provisional"])
            self.assertEqual(result["dsi"]["score"], dsi["score"])
            self.assertEqual(result["duration_seconds"], 2.5)
            self.assertEqual(result["dsi"]["inputs"], inputs)
            self.assertEqual(reopened.list("interactions", session_id=session["id"]), [interaction])
            self.assertEqual(reopened.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
            reopened.recover()
            self.assertEqual(reopened.get("sessions", session["id"]), result)
        finally:
            reopened.close()

    def test_retention_preserves_parents_needed_by_newer_session_evidence(self):
        old = "2000-01-01T00:00:00.000+00:00"
        store = Store(self.path)
        try:
            flow = store.put("flows", {"origin": "manual_test", "timestamp": old})
            alert = store.put("alerts", {"origin": "manual_test", "timestamp": old, "flow_id": flow["id"]})
            deployment = store.put("deployments", {"origin": "manual_test", "timestamp": old, "alert_id": alert["id"]})
            session = store.put("sessions", {"origin": "manual_test", "deployment_id": deployment["id"], "alert_id": alert["id"]})
            unreferenced = store.put("flows", {"origin": "dataset_replay", "timestamp": old})
            store.retain(7)
            self.assertIsNotNone(store.get("flows", flow["id"]))
            self.assertIsNotNone(store.get("sessions", session["id"]))
            self.assertIsNone(store.get("flows", unreferenced["id"]))
            self.assertEqual(store.conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
