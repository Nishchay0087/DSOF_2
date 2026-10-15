"""Real Scapy/Npcap collection with bounded producer/consumer isolation."""
from __future__ import annotations

from datetime import datetime, timezone
import platform
import queue
import threading
import time
import ipaddress

from .flows import Packet, packet_from_scapy


def is_loopback_interface(name):
    return name in ('lo', 'lo0') or 'loopback' in name.lower()


def permission_hint():
    if platform.system() == 'Windows':
        return 'Check Npcap is running and the exact interface ID. If Npcap restricts access, use an elevated PowerShell.'
    if platform.system() == 'Darwin':
        return 'Check the exact interface ID and read access to /dev/bpf* capture devices. macOS loopback is lo0.'
    return 'Check the exact interface ID and packet capture permissions (CAP_NET_RAW/CAP_NET_ADMIN).'


def enumerate_interfaces():
    """Return Scapy's capture identifiers (including Npcap loopback), never guessed names."""
    from scapy.all import conf, get_if_list
    result = []
    for name in get_if_list():
        info = conf.ifaces.get(name)
        if info is None:
            try:
                info = conf.ifaces.dev_from_networkname(name)
            except (ValueError, AttributeError):
                pass
        result.append({"id": name, "name": getattr(info, "name", name),
                       "description": getattr(info, "description", ""),
                       "loopback": is_loopback_interface(name) or "loopback" in str(getattr(info, "description", "")).lower()})
    return result


def capture_prerequisites():
    result = {"platform": platform.system(), "ready": False, "interfaces": [], "errors": [],
              "notes": ["A successful collector startup verifies actual device access; interface enumeration alone does not prove capture permission."]}
    try:
        import scapy
        from scapy.all import conf
        result["scapy_version"] = scapy.__version__
        result["pcap_backend_available"] = bool(conf.use_pcap)
        result["interfaces"] = enumerate_interfaces()
        if platform.system() == "Windows" and not conf.use_pcap:
            result["errors"].append("Npcap backend unavailable. Install Npcap with loopback support from npcap.com, restart PowerShell, then retry; install requirements into the active virtual environment.")
        if not result["interfaces"]:
            result["errors"].append("No capture interfaces found. Check Npcap service and permissions.")
        if platform.system() == "Windows" and not any(i["loopback"] for i in result["interfaces"]):
            result["notes"].append("Npcap loopback interface was not found; localhost tests require it.")
        result["ready"] = not result["errors"]
    except Exception as exc:
        result["errors"].append(f"Capture dependency failure: {type(exc).__name__}: {exc}. Install requirements; on Windows install Npcap.")
    return result


# Friendly alias used by CLI integrations.
prerequisites = capture_prerequisites


class Collector:
    def __init__(self, interfaces: list[str], callback, excluded_ports: list[int] | None = None, queue_size: int = 2048):
        if not isinstance(interfaces, list) or not interfaces or not all(isinstance(x, str) and x.strip() for x in interfaces):
            raise ValueError("Select one or more capture interface IDs from the prerequisites command")
        if len(interfaces) > 16 or len(set(interfaces)) != len(interfaces):
            raise ValueError("Capture interfaces must be unique and at most 16")
        if not 1 <= queue_size <= 100000:
            raise ValueError("Capture queue_size must be 1..100000")
        if not callable(callback):
            raise ValueError("Capture callback must be callable")
        excluded_ports = excluded_ports or []
        if any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in excluded_ports):
            raise ValueError("Excluded capture ports must be integers 1..65535")
        self.interfaces = list(interfaces)
        self.callback = callback
        self.excluded_ports = set(excluded_ports)
        self._queue = queue.Queue(maxsize=queue_size)
        self._lock = threading.RLock()
        self._stopping = threading.Event()
        self._sniffer = None
        self._sockets = []
        self._worker = self._watcher = None
        self._status = {"state": "stopped", "ready": False, "interfaces": self.interfaces,
                        "last_packet_time": None, "last_packet_epoch": None, "last_error": None,
                        "captured_packets": 0, "processed_packets": 0, "queue_dropped_packets": 0,
                        "unsupported_packets": 0, "oversized_packets": 0, "callback_errors": 0,
                        "excluded_packets": 0, "queue_capacity": queue_size,
                        "scope_excluded_packets": 0, "opened_interfaces": [], "interface_filters": {},
                        "kernel_dropped_packets": None,
                        "kernel_drop_statistics": "Unavailable through the Scapy capture abstraction; unknown, not zero",
                        "last_processing_latency_ms": None, "max_processing_latency_ms": None}

    def _fail(self, message):
        with self._lock:
            self._status.update(state="failed", ready=False, last_error=message)
        self._stopping.set()

    def start(self):
        with self._lock:
            if self._status["state"] in ("running", "starting"):
                return self.status()
            self._status.update(state="starting", ready=False, last_error=None)
        self._stopping.clear()
        try:
            from scapy.all import AsyncSniffer, conf
            checks = capture_prerequisites()
            if not checks["ready"]:
                raise RuntimeError("; ".join(checks["errors"]))
            names = {row["id"] for row in checks["interfaces"]}
            invalid = [name for name in self.interfaces if name not in names]
            if invalid:
                raise ValueError(f"Unknown capture interface(s): {invalid}. Run prerequisites and copy an exact interface ID into DSOF_INTERFACES.")
            # Open all sockets synchronously so permission/filter/interface errors fail startup.
            bpf = "(tcp or udp)"
            if self.excluded_ports:
                bpf += " and not (" + " or ".join(f"port {p}" for p in sorted(self.excluded_ports)) + ")"
            self._status["capture_filter"] = bpf
            for iface in self.interfaces:
                selected_filter = bpf
                if is_loopback_interface(iface):
                    selected_filter += ' and (net 127.0.0.0/8 or host ::1)'
                capture_socket = conf.L2listen(iface=iface, filter=selected_filter)
                self._sockets.append(capture_socket)
                actual_iface = getattr(capture_socket,'iface',iface)
                self._status['opened_interfaces'] = [str(getattr(s,'iface','unknown')) for s in self._sockets]
                self._status['interface_filters'][iface] = selected_filter
                if str(actual_iface) != iface:
                    raise RuntimeError(f'Capture opened {actual_iface!s} instead of selected {iface}')
            ready = threading.Event()
            self._sniffer = AsyncSniffer(opened_socket=dict(zip(self._sockets, self.interfaces)),
                                         store=False, prn=self._on_raw, started_callback=ready.set)
            self._worker = threading.Thread(target=self._consume, name="dsof-packet-consumer", daemon=True)
            self._worker.start()
            self._sniffer.start()
            if not ready.wait(5):
                error = getattr(self._sniffer, "exception", None)
                raise RuntimeError(f"Capture did not become ready within 5 seconds: {error or 'device did not start'}")
            with self._lock:
                self._status.update(state="running", ready=True, ready_since=time.time())
            self._watcher = threading.Thread(target=self._watch, name="dsof-capture-watch", daemon=True)
            self._watcher.start()
        except Exception as exc:
            self._fail(f"Capture failed: {type(exc).__name__}: {exc}. {permission_hint()}")
            self._close_sockets()
        return self.status()

    def _on_raw(self, raw):
        if self._stopping.is_set():
            return
        try:
            with self._lock:
                self._status["captured_packets"] += 1
            if len(raw) > 262144:
                with self._lock:
                    self._status["oversized_packets"] += 1
                return
            packet = packet_from_scapy(raw)
            if packet is None:
                with self._lock:
                    self._status["unsupported_packets"] += 1
                return
            # Explicit default scope even if a capture driver supplies traffic
            # with non-loopback endpoints on the selected loopback device.
            observed_interface = str(getattr(raw,'sniffed_on',''))
            if is_loopback_interface(observed_interface) and not (
                ipaddress.ip_address(packet.src).is_loopback and ipaddress.ip_address(packet.dst).is_loopback
            ):
                with self._lock:
                    self._status['scope_excluded_packets'] += 1
                return
            with self._lock:
                self._status["last_packet_epoch"] = packet.ts
                self._status["last_packet_time"] = datetime.fromtimestamp(packet.ts, timezone.utc).isoformat()
            if packet.sport in self.excluded_ports or packet.dport in self.excluded_ports:
                with self._lock:
                    self._status["excluded_packets"] += 1
                return
            try:
                self._queue.put_nowait((packet, time.perf_counter()))
            except queue.Full:
                with self._lock:
                    self._status["queue_dropped_packets"] += 1
        except Exception as exc:
            self._fail(f"Capture packet decoding failed: {type(exc).__name__}: {exc}")

    def _consume(self):
        while not self._stopping.is_set():
            try:
                packet, queued_at = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self.callback(packet)
                latency = (time.perf_counter() - queued_at) * 1000
                with self._lock:
                    self._status["processed_packets"] += 1
                    self._status["last_processing_latency_ms"] = latency
                    self._status["max_processing_latency_ms"] = max(latency, self._status["max_processing_latency_ms"] or 0)
            except Exception as exc:
                with self._lock:
                    self._status["callback_errors"] += 1
                self._fail(f"Packet processing failed: {type(exc).__name__}: {exc}. Collector stopped; inspect backend logs and model/flow configuration.")
            finally:
                self._queue.task_done()

    def _watch(self):
        while not self._stopping.wait(0.1):
            if self._sniffer is None or not self._sniffer.running:
                self._fail(f"Capture stopped unexpectedly: {getattr(self._sniffer, 'exception', None) or 'capture socket ended'}. Check interface/Npcap and restart the collector.")
                break
        if self._status["state"] == "failed":
            self._stop_sniffer()
            self._close_sockets()

    def _stop_sniffer(self):
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop(join=False)
            if self._sniffer is not None and getattr(self._sniffer, "thread", None):
                self._sniffer.thread.join(timeout=2)
        except Exception:
            pass  # Original capture failure remains in last_error.

    def _close_sockets(self):
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass
        self._sockets = []

    def stop(self):
        self._stopping.set()
        self._stop_sniffer()
        self._close_sockets()
        current = threading.current_thread()
        for worker in (self._worker, self._watcher):
            if worker is not None and worker is not current:
                worker.join(timeout=3)
        abandoned = 0
        while True:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                abandoned += 1
            except queue.Empty:
                break
        with self._lock:
            self._status["shutdown_discarded_packets"] = self._status.get("shutdown_discarded_packets", 0) + abandoned
            self._status.update(state="stopped", ready=False)
        return self.status()

    def status(self):
        with self._lock:
            result = dict(self._status)
            result["interfaces"] = list(self.interfaces)
            result["queue_depth"] = self._queue.qsize()
            result["drops"] = result["queue_dropped_packets"]
            return result
