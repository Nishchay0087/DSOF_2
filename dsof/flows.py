"""Bounded measured flow statistics. Training extractor parity is unverified.

All current conventions are explicit in docs/FEATURE_CONTRACT.md. No packet
history is retained here; HTTP reassembly is a separate bounded component.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import math
import threading
import uuid


FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Max", "Active Min", "Idle Mean", "Idle Max", "Idle Min",
]


NEW_FEATURE_NAMES = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

@dataclass(frozen=True)
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    payload: bytes = b""
    seq: int = 0
    flags: int = 0
    window: int = 0
    header_length: int = 20
    wire_length: int | None = None


def packet_from_scapy(raw) -> Packet | None:
    """Convert complete unfragmented IPv4/IPv6 TCP/UDP packets only."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
    if IP in raw:
        ip = raw[IP]
        if int(ip.frag) or int(ip.flags) & 1:
            return None  # Fragment reassembly is deliberately unsupported.
    elif IPv6 in raw:
        ip = raw[IPv6]
        if IPv6ExtHdrFragment in raw:
            return None
    else:
        return None
    if TCP in raw:
        transport = raw[TCP]
        protocol = "TCP"
        header_length = int(transport.dataofs or 5) * 4
        seq, flags, window = int(transport.seq), int(transport.flags), int(transport.window)
    elif UDP in raw:
        transport = raw[UDP]
        protocol = "UDP"
        header_length, seq, flags, window = 8, 0, 0, -1
    else:
        return None
    return Packet(float(raw.time), str(ip.src), str(ip.dst), int(transport.sport), int(transport.dport),
                  protocol, bytes(transport.payload), seq, flags, window, header_length, len(raw))


class Stats:
    """Welford sample moments; empty and singleton dispersion is zero."""
    __slots__ = ("n", "total", "mean", "m2", "minimum", "maximum")

    def __init__(self):
        self.n = 0
        self.total = self.mean = self.m2 = self.minimum = self.maximum = 0.0

    def add(self, value: float):
        self.n += 1
        self.total += value
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)
        if self.n == 1:
            self.minimum = self.maximum = value
        else:
            self.minimum = min(self.minimum, value)
            self.maximum = max(self.maximum, value)

    @property
    def variance(self):
        return max(0.0, self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    @property
    def std(self):
        return math.sqrt(self.variance)

    def copy(self):
        result = Stats()
        for attr in self.__slots__:
            setattr(result, attr, getattr(self, attr))
        return result


class Bulk:
    """Payload runs: >=4 packets, <=1s gaps, broken by opposite payload."""
    def __init__(self):
        self.start = self.last = None
        self.count = self.size = 0
        self.runs = self.packets = self.bytes = self.duration = 0

    def add(self, ts, size, opposite_last):
        if not size:
            return
        if (self.last is None or ts < self.last or ts - self.last > 1
                or (opposite_last is not None and opposite_last > self.start)):
            self.start = self.last = ts
            self.count, self.size = 1, size
            return
        previous = self.last
        self.last = ts
        self.count += 1
        self.size += size
        if self.count == 4:
            self.runs += 1
            self.packets += self.count
            self.bytes += self.size
            self.duration += ts - self.start
        elif self.count > 4:
            self.packets += 1
            self.bytes += size
            self.duration += ts - previous

    def features(self):
        return (self.bytes / self.runs if self.runs else 0,
                self.packets / self.runs if self.runs else 0,
                self.bytes / self.duration if self.duration > 0 else 0)


class Flow:
    def __init__(self, packet: Packet, active_gap: float = 5.0, subflow_gap: float = 1.0):
        self.id = str(uuid.uuid4())
        self.src, self.dst, self.sport, self.dport, self.protocol = (
            packet.src, packet.dst, packet.sport, packet.dport, packet.protocol)
        self.first = self.last = packet.ts
        self.packets = 0
        self.lengths, self.fwd, self.bwd = Stats(), Stats(), Stats()
        self.iat, self.fwd_iat, self.bwd_iat = Stats(), Stats(), Stats()
        self.active, self.idle = Stats(), Stats()
        self.active_start = packet.ts
        self.active_gap, self.subflow_gap = active_gap, subflow_gap
        self.subflows = 1
        self.fwd_last = self.bwd_last = None
        self.fwd_header = self.bwd_header = 0
        self.fwd_window = self.bwd_window = -1
        self.fwd_min_header = None
        self.fin = self.psh = self.ack = self.fwd_data = 0
        self.flag_counts = {bit: 0 for bit in (2, 4, 32, 64, 128)}
        self.direction_flags = {"Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0}
        self.fwd_bulk, self.bwd_bulk = Bulk(), Bulk()
        self.timestamp_regressions = 0
        self.end_reason = None
        self.add(packet)

    def forward(self, packet: Packet) -> bool:
        return (packet.src, packet.sport, packet.dst, packet.dport) == (self.src, self.sport, self.dst, self.dport)

    def add(self, packet: Packet):
        is_fwd = self.forward(packet)
        if self.packets:
            gap = packet.ts - self.last
            if gap >= 0:
                self.iat.add(gap * 1_000_000)
                if gap > self.active_gap:
                    self.active.add((self.last - self.active_start) * 1_000_000)
                    self.idle.add(gap * 1_000_000)
                    self.active_start = packet.ts
                if gap > self.subflow_gap:
                    self.subflows += 1
            else:
                self.timestamp_regressions += 1
        length = len(packet.payload)
        self.lengths.add(length)
        bulk, opposite = (self.fwd_bulk, self.bwd_bulk) if is_fwd else (self.bwd_bulk, self.fwd_bulk)
        bulk.add(packet.ts, length, opposite.last)
        direction = "Fwd" if is_fwd else "Bwd"
        for bit in self.flag_counts:
            self.flag_counts[bit] += bool(packet.flags & bit)
        self.direction_flags[direction + " PSH Flags"] += bool(packet.flags & 8)
        self.direction_flags[direction + " URG Flags"] += bool(packet.flags & 32)
        directional_lengths = self.fwd if is_fwd else self.bwd
        directional_iat = self.fwd_iat if is_fwd else self.bwd_iat
        previous = self.fwd_last if is_fwd else self.bwd_last
        if previous is not None and packet.ts >= previous:
            directional_iat.add((packet.ts - previous) * 1_000_000)
        if is_fwd:
            self.fwd_last = max(previous, packet.ts) if previous is not None else packet.ts
            self.fwd_header += packet.header_length
            if not self.fwd.n and packet.protocol == "TCP":
                self.fwd_window = packet.window
            self.fwd_min_header = min(self.fwd_min_header, packet.header_length) if self.fwd_min_header is not None else packet.header_length
            self.fwd_data += int(length > 0)
        else:
            self.bwd_last = max(previous, packet.ts) if previous is not None else packet.ts
            self.bwd_header += packet.header_length
            if not self.bwd.n and packet.protocol == "TCP":
                self.bwd_window = packet.window
        directional_lengths.add(length)
        self.fin += bool(packet.flags & 0x01)
        self.psh += bool(packet.flags & 0x08)
        self.ack += bool(packet.flags & 0x10)
        self.last = max(self.last, packet.ts)
        self.packets += 1

    def features(self, schema=None) -> dict[str, float]:
        duration = self.last - self.first
        # Rate for a zero-duration observation has an explicit defined zero convention.
        rate = lambda value: value / duration if duration > 0 else 0.0
        active = self.active.copy()
        # Include the current observed active interval; never extend duration with wall time.
        active.add((self.last - self.active_start) * 1_000_000)
        values = {
            "Destination Port": self.dport, "Flow Duration": duration * 1_000_000,
            "Total Fwd Packets": self.fwd.n, "Total Length of Fwd Packets": self.fwd.total,
            "Flow Bytes/s": rate(self.lengths.total), "Flow Packets/s": rate(self.packets),
            "Fwd Header Length": self.fwd_header, "Bwd Header Length": self.bwd_header,
            "Fwd Packets/s": rate(self.fwd.n), "Bwd Packets/s": rate(self.bwd.n),
            "Min Packet Length": self.lengths.minimum, "Max Packet Length": self.lengths.maximum,
            "Packet Length Mean": self.lengths.mean, "Packet Length Std": self.lengths.std,
            "Packet Length Variance": self.lengths.variance,
            "FIN Flag Count": self.fin, "PSH Flag Count": self.psh, "ACK Flag Count": self.ack,
            "Average Packet Size": self.lengths.mean, "Subflow Fwd Bytes": self.fwd.total / self.subflows,
            "Init_Win_bytes_forward": self.fwd_window, "Init_Win_bytes_backward": self.bwd_window,
            "act_data_pkt_fwd": self.fwd_data, "min_seg_size_forward": self.fwd_min_header or 0,
        }
        for prefix, stats in (("Fwd Packet Length", self.fwd), ("Bwd Packet Length", self.bwd)):
            values.update({f"{prefix} Max": stats.maximum, f"{prefix} Min": stats.minimum,
                           f"{prefix} Mean": stats.mean, f"{prefix} Std": stats.std})
        for prefix, stats in (("Flow IAT", self.iat), ("Fwd IAT", self.fwd_iat), ("Bwd IAT", self.bwd_iat)):
            values.update({f"{prefix} Mean": stats.mean, f"{prefix} Std": stats.std,
                           f"{prefix} Max": stats.maximum, f"{prefix} Min": stats.minimum})
            if prefix != "Flow IAT":
                values[f"{prefix} Total"] = stats.total
        for prefix, stats in (("Active", active), ("Idle", self.idle)):
            values.update({f"{prefix} Mean": stats.mean, f"{prefix} Max": stats.maximum, f"{prefix} Min": stats.minimum})
        values.update({
            "Total Backward Packets": self.bwd.n, "Total Length of Bwd Packets": self.bwd.total,
            "SYN Flag Count": self.flag_counts[2], "RST Flag Count": self.flag_counts[4],
            "URG Flag Count": self.flag_counts[32], "CWE Flag Count": self.flag_counts[128],
            "ECE Flag Count": self.flag_counts[64], "Down/Up Ratio": self.bwd.n / self.fwd.n if self.fwd.n else 0,
            "Avg Fwd Segment Size": self.fwd.mean, "Avg Bwd Segment Size": self.bwd.mean,
            "Fwd Header Length.1": self.fwd_header, "Subflow Fwd Packets": self.fwd.n / self.subflows,
            "Subflow Bwd Packets": self.bwd.n / self.subflows, "Subflow Bwd Bytes": self.bwd.total / self.subflows,
            "Active Std": active.std, "Idle Std": self.idle.std,
        })
        values.update(self.direction_flags)
        for direction, bulk in (("Fwd", self.fwd_bulk), ("Bwd", self.bwd_bulk)):
            for suffix, value in zip(("Avg Bytes/Bulk", "Avg Packets/Bulk", "Avg Bulk Rate"), bulk.features()):
                values[direction + " " + suffix] = value
        return {name: values[name] for name in (FEATURE_NAMES if schema is None else schema)}

    def summary(self):
        return {"id": self.id, "flow_id": self.id, "src": self.src, "dst": self.dst,
                "sport": self.sport, "dport": self.dport, "protocol": self.protocol,
                "first": self.first, "last": self.last, "packets": self.packets,
                "payload_bytes": int(self.lengths.total), "fwd_packets": self.fwd.n,
                "bwd_packets": self.bwd.n, "duration_ms": (self.last - self.first) * 1000,
                "timestamp_regressions": self.timestamp_regressions,
                "feature_contract": "experimental_unverified", "end_reason": self.end_reason}


class FlowTracker:
    def __init__(self, max_flows=2048, idle_timeout=10.0, max_duration=120.0, max_packets=10000,
                 active_gap=5.0, subflow_gap=1.0):
        if max_flows < 1 or idle_timeout <= 0 or max_duration <= 0 or max_packets < 1 or active_gap <= 0 or subflow_gap <= 0:
            raise ValueError("Flow limits and timeouts must be positive")
        self.max_flows, self.idle_timeout, self.max_duration, self.max_packets = max_flows, idle_timeout, max_duration, max_packets
        self.active_gap, self.subflow_gap = active_gap, subflow_gap
        self.flows = OrderedDict()
        self.lock = threading.RLock()
        self.evicted = self.expired = self.split = 0
        self._removed = deque(maxlen=max_flows)
        self.unprocessed_evictions = 0

    def _remember_removed(self, flow):
        if len(self._removed) == self._removed.maxlen:
            self.unprocessed_evictions += 1
        self._removed.append(flow)

    def drain_evicted(self) -> list[Flow]:
        """Consume capacity evictions and forced splits for a final engine decision."""
        with self.lock:
            result = list(self._removed)
            self._removed.clear()
            return result

    @staticmethod
    def key(packet):
        endpoints = sorted(((packet.src, packet.sport), (packet.dst, packet.dport)))
        return packet.protocol, tuple(endpoints)

    def ingest(self, packet: Packet) -> Flow:
        if not math.isfinite(packet.ts) or packet.ts < 0:
            raise ValueError("Packet timestamp must be finite seconds since epoch")
        with self.lock:
            key = self.key(packet)
            flow = self.flows.get(key)
            if flow and (packet.ts - flow.last > self.idle_timeout or packet.ts - flow.first >= self.max_duration or flow.packets >= self.max_packets):
                flow.end_reason = "split_at_configured_limit"
                self._remember_removed(flow)
                self.split += 1
                del self.flows[key]
                flow = None
            if flow is None:
                if len(self.flows) >= self.max_flows:
                    _, evicted = self.flows.popitem(last=False)
                    evicted.end_reason = "capacity_eviction"
                    self._remember_removed(evicted)
                    self.evicted += 1
                flow = Flow(packet, self.active_gap, self.subflow_gap)
                self.flows[key] = flow
            else:
                flow.add(packet)
            self.flows.move_to_end(key)
            return flow

    def expire(self, now: float) -> list[Flow]:
        with self.lock:
            expired = []
            for key, flow in list(self.flows.items()):
                reason = None
                if now - flow.last >= self.idle_timeout:
                    reason = "idle_timeout"
                elif now - flow.first >= self.max_duration:
                    reason = "maximum_duration"
                elif flow.packets >= self.max_packets:
                    reason = "maximum_packets"
                if reason:
                    flow.end_reason = reason
                    expired.append(self.flows.pop(key))
            self.expired += len(expired)
            return expired

    def status(self):
        with self.lock:
            return {"active_flows": len(self.flows), "max_flows": self.max_flows,
                    "capacity_evictions": self.evicted, "expired_flows": self.expired, "split_flows": self.split,
                    "unprocessed_evictions": self.unprocessed_evictions,
                    "idle_timeout_seconds": self.idle_timeout, "max_duration_seconds": self.max_duration,
                    "max_packets_per_flow": self.max_packets}
