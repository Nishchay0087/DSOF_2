"""Artifact integrity, analytic packet measurements and collector boundary tests."""
import csv
import hashlib
import json
from pathlib import Path
import queue
import shutil
import socket
import threading
import time

import numpy as np
import pytest

from dsof.capture import Collector, capture_prerequisites
from dsof.flows import FEATURE_NAMES, FlowTracker, Packet, packet_from_scapy
from dsof.model import Model

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def model():
    return Model(ROOT / "artifacts")


@pytest.fixture(scope="module")
def dataset_row():
    with (ROOT / "datasets" / "cicids2017_cleaned.csv").open(newline="", encoding="utf-8") as stream:
        row = next(csv.DictReader(stream))
    return {key: float(row[key]) for key in FEATURE_NAMES}


def test_original_artifact_hash_and_feature_contract(model):
    status = model.status()
    assert status["ready"], status["error"]
    baseline = json.loads((ROOT / "validation" / "model_baseline.json").read_text())
    assert status["sha256"] == baseline["sha256"]
    assert status["original_hash_unchanged"] is True
    assert status["feature_count"] == 52
    assert status["feature_names"] == FEATURE_NAMES
    assert status["feature_contract"] == "experimental_unverified"
    assert status["probability_calibrated"] is False


def test_original_inference_order_is_preserved(model, dataset_row):
    shuffled = dict(reversed(list(dataset_row.items())))
    prediction = model.predict(shuffled)
    expected = model._model.predict_proba(np.array([[dataset_row[k] for k in FEATURE_NAMES]], dtype=np.float32))[0]
    assert list(prediction["probabilities"]) == model.labels
    assert list(prediction["probabilities"].values()) == pytest.approx(expected.tolist())
    assert prediction["probability"] == prediction["probabilities"][prediction["prediction"]]
    assert prediction["encoded_prediction"] == int(model._model.predict(np.array([[dataset_row[k] for k in FEATURE_NAMES]], dtype=np.float32))[0])


@pytest.mark.parametrize("bad", [None, "42", True, float("nan"), float("inf"), 1e39, 10 ** 400])
def test_model_rejects_nonfinite_or_non_numeric(model, dataset_row, bad):
    values = dict(dataset_row, **{"Flow Duration": bad})
    with pytest.raises(ValueError, match="Flow Duration"):
        model.predict(values)


def test_model_rejects_missing_extra_and_bad_units(model, dataset_row):
    missing = dict(dataset_row)
    missing.pop("Flow Duration")
    with pytest.raises(ValueError, match="missing=.*Flow Duration"):
        model.predict(missing)
    with pytest.raises(ValueError, match="unexpected=.*invented"):
        model.predict(dict(dataset_row, invented=0))
    with pytest.raises(ValueError, match="Destination Port"):
        model.predict(dict(dataset_row, **{"Destination Port": 65536}))
    with pytest.raises(ValueError, match="unscaled TCP window"):
        model.predict(dict(dataset_row, Init_Win_bytes_forward=65536))


def test_missing_artifacts_report_failure(tmp_path):
    model = Model(tmp_path)
    assert not model.status()["ready"]
    assert "Missing required files" in model.status()["error"]
    with pytest.raises(ValueError, match="Missing required files"):
        model.predict({})


def test_changed_artifact_is_rejected_before_deserialization(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for name in ("feature_schema.json", "label_classes.json"):
        shutil.copyfile(ROOT / "artifacts" / name, artifacts / name)
    (tmp_path / "validation").mkdir()
    shutil.copyfile(ROOT / "validation" / "model_baseline.json", tmp_path / "validation" / "model_baseline.json")
    (artifacts / "xgb_model.joblib").write_bytes(b"deliberately invalid test fixture")
    status = Model(artifacts).status()
    assert not status["ready"]
    assert "SHA-256 differs" in status["error"]


def test_swapped_schema_order_is_rejected(tmp_path):
    for name in ("xgb_model.joblib", "label_classes.json"):
        shutil.copyfile(ROOT / "artifacts" / name, tmp_path / name)
    schema = FEATURE_NAMES.copy()
    schema[0], schema[1] = schema[1], schema[0]
    (tmp_path / "feature_schema.json").write_text(json.dumps(schema))
    assert "exactly match" in Model(tmp_path).status()["error"]


def p(ts=100, payload=b"", reverse=False, **kwargs):
    values = dict(ts=ts, src="127.0.0.1", dst="127.0.0.1", sport=45001, dport=8080,
                  protocol="TCP", payload=payload, seq=1, flags=0x10, window=4096, header_length=20)
    if reverse:
        values["sport"], values["dport"] = values["dport"], values["sport"]
    values.update(kwargs)
    return Packet(**values)


def test_packet_flow_analytic_calculations_and_units():
    tracker = FlowTracker()
    flow = tracker.ingest(p(payload=b"x" * 100, flags=0x18, header_length=24))
    assert tracker.ingest(p(ts=100.1, payload=b"y" * 200, reverse=True, window=8192)) is flow
    assert tracker.ingest(p(ts=100.3, payload=b"", flags=0x11)) is flow
    features = flow.features()
    assert list(features) == FEATURE_NAMES
    assert features["Destination Port"] == 8080
    assert features["Flow Duration"] == pytest.approx(300000)
    assert features["Total Fwd Packets"] == 2
    assert features["Total Length of Fwd Packets"] == 100
    assert features["Fwd Packet Length Mean"] == 50
    assert features["Fwd Packet Length Std"] == pytest.approx(70.71067811865)
    assert features["Bwd Packet Length Mean"] == 200
    assert features["Packet Length Variance"] == 10000
    assert features["Flow Bytes/s"] == pytest.approx(1000)
    assert features["Flow Packets/s"] == pytest.approx(10)
    assert features["Flow IAT Mean"] == pytest.approx(150000)
    assert features["Fwd IAT Total"] == pytest.approx(300000)
    assert features["Fwd Header Length"] == 44
    assert features["Bwd Header Length"] == 20
    assert features["Init_Win_bytes_forward"] == 4096
    assert features["Init_Win_bytes_backward"] == 8192
    assert features["min_seg_size_forward"] == 20
    assert features["FIN Flag Count"] == 1
    assert features["PSH Flag Count"] == 1
    assert features["ACK Flag Count"] == 3
    assert features["act_data_pkt_fwd"] == 1
    assert features["Active Mean"] == pytest.approx(300000)


def test_zero_duration_has_documented_statistics_and_missing_reverse_sentinel():
    flow = FlowTracker().ingest(p())
    features = flow.features()
    assert features["Flow Duration"] == 0
    assert features["Flow Bytes/s"] == features["Flow Packets/s"] == 0
    assert features["Init_Win_bytes_backward"] == -1
    assert features["Bwd Packet Length Mean"] == 0
    assert features["Packet Length Std"] == 0


def test_flow_resources_and_eviction_remain_bounded():
    tracker = FlowTracker(max_flows=2, max_packets=2, idle_timeout=2, max_duration=5)
    first = tracker.ingest(p())
    tracker.ingest(p(sport=45002))
    tracker.ingest(p(sport=45003))
    assert tracker.status()["active_flows"] == 2
    assert tracker.drain_evicted() == [first]
    flow = tracker.ingest(p(ts=100.1, sport=45003))
    fresh = tracker.ingest(p(ts=100.2, sport=45003))
    assert fresh.id != flow.id
    assert tracker.drain_evicted() == [flow]
    assert len(tracker.expire(103)) == 2
    assert tracker.status()["active_flows"] == 0


def test_retransmissions_are_real_packets_and_timestamps_never_fabricated():
    tracker = FlowTracker()
    flow = tracker.ingest(p(payload=b"hello", seq=10))
    tracker.ingest(p(ts=100.1, payload=b"hello", seq=10))
    tracker.ingest(p(ts=99.9))
    assert flow.packets == 3
    assert flow.features()["Total Length of Fwd Packets"] == 10
    assert flow.features()["Flow Duration"] == pytest.approx(100000)
    assert flow.timestamp_regressions == 1
    assert flow.iat.n == 1


def test_scapy_conversion_tcp_udp_and_fragment_rejection():
    from scapy.all import IP, TCP, UDP, Raw
    raw = IP(bytes(IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=45678, dport=8080, flags="PA", window=1234) / Raw(b"GET / HTTP/1.0\r\n\r\n")))
    raw.time = 123.5
    packet = packet_from_scapy(raw)
    assert packet.payload == b"GET / HTTP/1.0\r\n\r\n"
    assert packet.header_length == 20
    assert packet.window == 1234
    assert packet.flags == 0x18
    assert packet.ts == 123.5
    udp = packet_from_scapy(IP() / UDP(sport=1234, dport=53) / Raw(b"abcd"))
    assert udp.protocol == "UDP" and udp.header_length == 8 and udp.window == -1
    assert packet_from_scapy(IP(flags="MF") / TCP()) is None


def test_capture_queue_is_bounded_and_reports_loss():
    from scapy.all import IP, TCP, Raw
    collector = Collector(["unit-test-interface"], lambda packet: None, queue_size=1)
    raw = IP() / TCP(sport=3000, dport=4000) / Raw(b"abc")
    collector._on_raw(raw)
    collector._on_raw(raw)
    assert collector.status()["queue_depth"] == 1
    assert collector.status()["queue_dropped_packets"] == 1
    assert collector.status()["kernel_dropped_packets"] is None
    collector.stop()


def test_capture_failure_is_not_monitoring():
    collector = Collector(["definitely-invalid-interface"], lambda packet: None)
    status = collector.start()
    assert status["state"] == "failed" and status["ready"] is False
    assert status["last_error"]
    collector.stop()


def test_processing_exception_stops_collector():
    def fail(packet):
        raise RuntimeError("intentional processing error")
    collector = Collector(["test-interface"], fail)
    collector._queue.put((p(), time.perf_counter()))
    worker = threading.Thread(target=collector._consume)
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert collector.status()["state"] == "failed"
    assert collector.status()["callback_errors"] == 1


def test_actual_localhost_capture_when_npcap_available():
    checks = capture_prerequisites()
    loopback = next((row["id"] for row in checks["interfaces"] if row["loopback"]), None)
    if not checks["ready"] or not loopback:
        pytest.skip("Npcap loopback unavailable; mandatory fresh-traffic tool reports this as failure")
    marker = b"DSOF-actual-capture-verification"
    captured = threading.Event()
    def receive(packet):
        if marker in packet.payload:
            captured.set()
    collector = Collector([loopback], receive)
    try:
        status = collector.start()
        if not status['ready'] and 'Permission denied: could not open /dev/bpf' in (status.get('last_error') or ''):
            pytest.skip('Direct BPF access unavailable on macOS; FIFO capture and the fresh-traffic tool validate the configured helper backend separately')
        assert status["ready"], status["last_error"]
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            with socket.create_connection(server.getsockname(), timeout=2) as client:
                peer, _ = server.accept()
                with peer:
                    client.sendall(marker)
                    assert peer.recv(128) == marker
        assert captured.wait(5), "Real loopback payload did not reach trusted capture callback"
        assert collector.status()["processed_packets"] > 0
    finally:
        collector.stop()
    assert collector.status()["state"] == "stopped"
