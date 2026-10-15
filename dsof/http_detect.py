"""Bounded HTTP/1 request inspection; indicators are independent of ML inference.

One stream represents one TCP direction. Pass the initial SYN whenever available.
No method in this module grants provenance or treats a test ID as authentication.
"""
from __future__ import annotations

import json
import re
import uuid
from urllib.parse import unquote_plus, urlsplit


_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
_REQUEST_LINE = re.compile(rb"([A-Z]+) ([^\x00-\x20\x7f]+) HTTP/(1\.[01])$")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_RULES = (
    ("sql_union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I)),
    ("sql_boolean_comparison", re.compile(
        r"\b(?:or|and)\s+(?:\d{1,12}|'[^'\r\n]{0,40}'|\"[^\"\r\n]{0,40}\")"
        r"\s*(?:=|like\b)\s*(?:\d{1,12}|'[^'\r\n]{0,40}'|\"[^\"\r\n]{0,40}\")", re.I)),
    ("sql_stacked_statement", re.compile(r";\s*(?:select|drop|insert|update|delete|exec(?:ute)?)\b", re.I)),
    ("sql_time_delay", re.compile(r"\b(?:sleep|benchmark)\s*\(\s*\d|\bwaitfor\s+delay\b", re.I)),
    ("xss_script_tag", re.compile(r"<\s*script\b", re.I)),
    ("xss_event_handler", re.compile(r"<\s*[a-z][^<>\r\n]{0,300}[/\s]on[a-z]{2,20}\s*=", re.I)),
    ("xss_javascript_uri", re.compile(r"\bjavascript\s*:\s*(?:alert|confirm|prompt|eval|document\.|window\.)", re.I)),
    ("path_traversal", re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")),
)
_TERMINAL = {"unsupported", "ambiguous", "resource_limit"}


def _minimal(value: str, limit: int = 160) -> str:
    """A short printable string suitable for escaped UI rendering and persistence."""
    return "".join(c if c.isprintable() else " " for c in value)[:limit]


def _decode(value: str) -> str:
    # A fixed two-pass bound covers ordinary and double URL encoding, not arbitrary
    # recursive decoding. JSON strings are decoded by json.loads before this step.
    for _ in range(2):
        decoded = unquote_plus(value, encoding="utf-8", errors="replace")
        if decoded == value:
            break
        value = decoded
    return value


def _inspect(value: str, location: str) -> list[dict]:
    value = _decode(value)
    # Comments between SQL tokens are whitespace, not executable host instructions.
    # Use a linear scanner rather than a backtracking expression for unclosed comments.
    pieces, cursor = [], 0
    while True:
        start = value.find("/*", cursor)
        if start < 0:
            pieces.append(value[cursor:])
            break
        end = value.find("*/", start + 2)
        if end < 0:
            pieces.append(value[cursor:])
            break
        pieces.extend((value[cursor:start], " "))
        cursor = end + 2
    canonical = "".join(pieces)
    results = []
    for name, pattern in _RULES:
        candidate = canonical if name.startswith("sql_") else value
        match = pattern.search(candidate)
        if match:
            results.append({"name": name, "category": "Web Attacks",
                            "evidence": _minimal(match.group()), "location": location})
    return results


def _fields(encoded: str, location: str) -> tuple[list[tuple[str, str]], bool]:
    pieces = encoded.split("&")
    if len(pieces) > 128:
        return [], False
    # Inspect keys as well as values, but never retain a potentially sensitive key.
    result = []
    for index, piece in enumerate(pieces):
        key, _, value = piece.partition("=")
        result.extend(((key, f"{location}.key[{index}]"), (value, f"{location}.value[{index}]")))
    return result, True


def _request(method: str, target: str, headers: dict[str, str], body: bytes, classifier=None) -> dict:
    path, _, query = target.partition("?")
    if target.lower().startswith(("http://", "https://")):
        try:
            absolute = urlsplit(target)
            path, query = absolute.path or "/", absolute.query
        except ValueError:
            # Malformed absolute-form targets should not persist authorities or credentials.
            path, query = "[invalid absolute target]", ""
    values = [(path, "path")]
    fields, valid = _fields(query, "query")
    values.extend(fields)
    inspection = {"state": "complete", "reason": None}
    if not valid:
        inspection = {"state": "partial", "reason": "Query exceeds 128 fields; query not inspected"}
    if body:
        type_parts = headers.get("content-type", "").split(";")
        content_type = type_parts[0].strip().lower()
        charset = "utf-8"
        for parameter in type_parts[1:]:
            key, _, val = parameter.strip().partition("=")
            if key.lower() == "charset":
                charset = val.strip().strip('"').lower()
        encoding = headers.get("content-encoding", "identity").strip().lower()
        if encoding != "identity" or charset not in {"utf-8", "utf8", "us-ascii"}:
            text = None
            inspection = {"state": "partial", "reason": "Unsupported body content encoding or charset; body not inspected"}
        else:
            try:
                text = body.decode("ascii" if charset == "us-ascii" else "utf-8", errors="strict")
            except UnicodeDecodeError:
                text = None
                inspection = {"state": "partial", "reason": "Body is not valid UTF-8/ASCII; body not inspected"}
        if text is not None:
            if content_type == "application/x-www-form-urlencoded":
                fields, valid = _fields(text, "form")
                values.extend(fields)
                if not valid:
                    inspection = {"state": "partial", "reason": "Form exceeds 128 fields; form not inspected"}
            elif content_type == "application/json" or content_type.endswith("+json"):
                try:
                    obj = json.loads(text)
                    stack = [obj]
                    extracted = []
                    visited = 0
                    while stack:
                        visited += 1
                        if visited > 256:
                            raise ValueError("JSON exceeds 256 nodes")
                        item = stack.pop()
                        if isinstance(item, str):
                            extracted.append((item, f"json.string[{len(extracted)}]"))
                        elif isinstance(item, dict):
                            stack.extend(item.keys())
                            stack.extend(item.values())
                        elif isinstance(item, list):
                            stack.extend(item)
                    values.extend(extracted)
                except (ValueError, RecursionError):
                    inspection = {"state": "partial", "reason": "Invalid or over-complex JSON; body not inspected"}
            elif content_type == "text/plain":
                values.append((text, "text_body"))
            else:
                inspection = {"state": "partial", "reason": "Unsupported Content-Type; body not inspected"}
    rules = []
    seen = set()
    for value, location in values:
        for rule in _inspect(value, location):
            fingerprint = (rule["name"], rule["evidence"], rule["location"])
            if fingerprint not in seen:
                seen.add(fingerprint)
                rules.append(rule)
    test_id = None
    candidate = headers.get("x-dsof-test-id", "")
    try:
        parsed = uuid.UUID(candidate)
        if str(parsed) == candidate.lower():
            test_id = str(parsed)
    except (ValueError, AttributeError):
        pass
    return {"method": method, "path": _minimal(path), "test_id": test_id,
            "rules": rules, "inspection": inspection,
            "http_ml": classifier([(_decode(value), location) for value, location in values]) if classifier else None}


class HTTPStream:
    """Reassemble one direction and inspect each complete HTTP request once.

    Retains at most max_bytes of sequence space over the stream's entire lifetime,
    enabling exact conflict detection for retransmitted already-parsed data. The
    caller owns flow idle/absolute timeouts and the total number of flow objects.
    """

    def __init__(self, max_bytes: int = 65536, max_requests: int = 32, classifier=None):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 256 <= max_bytes <= 1048576:
            raise ValueError("max_bytes must be an integer between 256 and 1048576")
        if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= 1024:
            raise ValueError("max_requests must be an integer between 1 and 1024")
        self.classifier = classifier
        self.max_bytes = max_bytes
        self.max_requests = max_requests
        self._base: int | None = None
        self._syn_seen = False
        self._data = bytearray()
        self._pending: list[tuple[int, bytes]] = []
        self._cursor = 0
        self._requests = 0
        self._received = 0
        self._state = "waiting"
        self._reason: str | None = None

    def status(self) -> dict:
        return {"state": self._state, "reason": self._reason,
                "received_bytes": self._received,
                "buffered_bytes": len(self._data) + sum(len(p) for _, p in self._pending),
                "pending_segments": len(self._pending), "inspected_requests": self._requests,
                "syn_seen": self._syn_seen}

    def _stop(self, state: str, reason: str) -> None:
        self._state, self._reason = state, reason
        # Terminal streams cannot be reparsed. Release packet contents immediately.
        self._data.clear()
        self._pending.clear()

    def feed(self, seq: int, payload: bytes, syn: bool = False) -> list[dict]:
        if isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq <= 0xFFFFFFFF:
            raise ValueError("TCP sequence number must be an integer in 0..2**32-1")
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise ValueError("TCP payload must be bytes")
        if not isinstance(syn, bool):
            raise ValueError("syn must be boolean")
        if self._state in _TERMINAL:
            return []
        payload = bytes(payload)
        start = (seq + int(syn)) & 0xFFFFFFFF
        if self._base is None:
            if not syn and not payload:
                return []
            self._base = start
            self._syn_seen = syn
        elif syn:
            if start != self._base:
                self._stop("ambiguous", "A new SYN sequence was received on an existing stream")
                return []
            self._syn_seen = True
        if not payload:
            return []
        self._received += len(payload)
        position = ((start - self._base + 0x80000000) & 0xFFFFFFFF) - 0x80000000
        if position < 0:
            self._stop("ambiguous", "Data precedes stream origin; initial SYN or earlier segment is missing")
            return []
        end = position + len(payload)
        if end > self.max_bytes:
            self._stop("resource_limit", f"Stream exceeds {self.max_bytes} bytes of sequence space")
            return []
        if position > len(self._data) + min(16384, self.max_bytes):
            self._stop("resource_limit", "Out-of-order gap exceeds 16384 bytes")
            return []
        segments = [(0, bytes(self._data))] + self._pending
        for offset, existing in segments:
            left, right = max(position, offset), min(end, offset + len(existing))
            if left < right and payload[left-position:right-position] != existing[left-offset:right-offset]:
                self._stop("ambiguous", "Conflicting TCP overlap; inspection stopped")
                return []
        if end <= len(self._data):
            return []  # Fully retransmitted previously observed bytes.
        if position <= len(self._data):
            self._data.extend(payload[len(self._data)-position:])
        else:
            self._pending.append((position, payload))
        # Merge overlapping/adjacent future segments. This also removes duplicates.
        merged: list[tuple[int, bytes]] = []
        for offset, part in sorted(self._pending):
            if offset <= len(self._data):
                if offset + len(part) > len(self._data):
                    self._data.extend(part[len(self._data)-offset:])
            elif merged and offset <= merged[-1][0] + len(merged[-1][1]):
                previous, prior = merged[-1]
                overlap = previous + len(prior) - offset
                if overlap < len(part):
                    merged[-1] = (previous, prior + part[overlap:])
            else:
                merged.append((offset, part))
        self._pending = merged
        if len(self._pending) > 64:
            self._stop("resource_limit", "More than 64 disjoint out-of-order segments")
            return []
        self._state, self._reason = "collecting", None
        return self._parse()

    def _parse(self) -> list[dict]:
        result = []
        while self._cursor < len(self._data):
            if self._requests >= self.max_requests:
                self._stop("resource_limit", f"Stream exceeds {self.max_requests} requests")
                break
            available = self._data[self._cursor:]
            if available.startswith(b"\x16\x03") or available.startswith(b"\x17\x03"):
                self._stop("unsupported", "TLS payload is encrypted; no HTTP payload inspection")
                break
            if available.startswith(b"PRI * HTTP/2"):
                self._stop("unsupported", "HTTP/2 is not supported")
                break
            if available.startswith(b"HTTP/"):
                self._stop("unsupported", "HTTP response direction is not inspected")
                break
            marker = available.find(b"\r\n\r\n")
            if marker < 0:
                if len(available) > min(16384, self.max_bytes):
                    self._stop("resource_limit", "HTTP header exceeds configured byte limit")
                elif b"\n\n" in available:
                    self._stop("ambiguous", "HTTP requires CRLF header delimiters")
                elif len(available) >= 16 and not re.match(rb"[A-Z]{1,16} ", available):
                    self._stop("unsupported", "Not a supported HTTP request start; midstream capture cannot be inspected")
                break
            if marker + 4 > 16384:
                self._stop("resource_limit", "HTTP header exceeds 16384 bytes")
                break
            lines = bytes(available[:marker]).split(b"\r\n")
            matched = _REQUEST_LINE.fullmatch(lines[0])
            if not matched:
                self._stop("ambiguous", "Malformed or unsupported HTTP request line")
                break
            method = matched.group(1).decode("ascii")
            if method not in _METHODS:
                self._stop("unsupported", f"HTTP method {method[:20]} is not supported (including tunnels)")
                break
            if len(lines) > 129:
                self._stop("resource_limit", "HTTP request exceeds 128 headers")
                break
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if not separator or not _HEADER_NAME.fullmatch(name) or any(c < 32 and c != 9 or c == 127 for c in value):
                    self._stop("ambiguous", "Malformed HTTP header or obsolete folding")
                    break
                key = name.decode("ascii").lower()
                if key in headers and key in {"content-length", "transfer-encoding", "host", "x-dsof-test-id"}:
                    self._stop("ambiguous", f"Duplicate {key} header")
                    break
                headers[key] = value.decode("latin-1").strip()
            if self._state in _TERMINAL:
                break
            if "transfer-encoding" in headers:
                state = "ambiguous" if "content-length" in headers else "unsupported"
                self._stop(state, "Transfer-Encoding requests (including chunked) are not inspected")
                break
            raw_length = headers.get("content-length", "0")
            if not re.fullmatch(r"[0-9]{1,10}", raw_length):
                self._stop("ambiguous", "Content-Length must be one nonnegative decimal integer")
                break
            length = int(raw_length)
            total = marker + 4 + length
            if self._cursor + total > self.max_bytes:
                self._stop("resource_limit", "Declared body exceeds stream byte limit")
                break
            if len(available) < total:
                self._reason = "Waiting for complete Content-Length body"
                break
            body = bytes(available[marker+4:total])
            target = matched.group(2).decode("utf-8", errors="replace")
            result.append(_request(method, target, headers, body, self.classifier))
            self._requests += 1
            self._cursor += total
            if headers.get("upgrade") or headers.get("connection", "").lower() == "upgrade":
                self._stop("unsupported", "Protocol upgrades are not inspected after this request")
                break
        return result
