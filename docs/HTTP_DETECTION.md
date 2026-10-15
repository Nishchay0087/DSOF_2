# Cleartext HTTP detector

The independent HTTP detector identifies suspicious request indicators. A matched
pattern describes an attempted suspicious request; it does not establish successful
exploitation. Its results never replace the original model prediction or probability.
Numeric flow features can miss a short payload attack, so either detector can supply
evidence for the decision policy.

## Inspected surfaces and rules

HTTP/1.0 and HTTP/1.1 requests support GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS and
TRACE. Inspection examines the request target path, query keys/values, and supported
UTF-8 bodies with an unambiguous Content-Length: form URL encoding, JSON strings/keys
and text/plain. URL decoding is bounded to two passes. Rules identify UNION SELECT,
boolean SQL comparisons, stacked SQL statements and timing functions; script tags,
inline event handlers and selected executable javascript: expressions; and parent
directory path components using slash or backslash. These are conservative indicators,
not a complete SQL/JavaScript parser or proof that a target is vulnerable. Text about
an attack can match the same indicator and requires contextual review.

Headers such as Cookie, Referer and Authorization are not inspected for signatures.
HTTP response bodies are never inspected. Each persisted rule has its name, category,
location and only its matched printable substring (at most 160 characters). The
recorded request path omits the query and is limited to 160 printable characters.
Raw request bodies and full headers are not returned for persistence. Returned strings
remain untrusted and must be rendered as text, never injected into HTML.

X-DSOF-Test-ID accepts only canonical hyphenated UUID strings. It is an untrusted
correlation identifier, never a grant of provenance or manual-test classification.
The collector's separate authenticated registration policy establishes test origin.

## TCP and framing

Each forward TCP direction has an HTTPStream. Passing the initial SYN anchors the
first data byte at SYN sequence + 1 and permits subsequent packets to arrive out of
order. Sequence wrap is handled. The detector assembles contiguous bytes, merges
identical overlapping segments and emits each complete request once. Retransmissions
do not generate duplicate requests. Two distinct requests at distinct sequence
positions remain distinct requests; alert-level deduplication is a separate policy.

Conflicting overlaps stop inspection and release buffered bytes. Already emitted
evidence describes the observed earlier request; a later conflicting retransmission
makes subsequent stream interpretation ambiguous and must remain visible in flow
status. Without the initial SYN, the first observed payload must begin a complete
in-order request prefix. Missing earlier data cannot be reconstructed or guessed.

CRLF framing is required. Duplicate Content-Length, Transfer-Encoding, Host or test
ID headers are rejected, including duplicate equal lengths. Malformed lengths,
obsolete header folding, control characters and mixed Transfer-Encoding/Content-Length
are rejected. The detector waits for the entire declared body before emitting a
request. Unsupported body content types, invalid UTF-8/JSON or over-complex bodies
produce an explicit partial inspection while still permitting target inspection.

## Resource bounds

Defaults are 65,536 bytes of total sequence space per flow direction, 32 requests,
16,384-byte headers, at most 128 headers, 128 query/form fields, 256 visited JSON
nodes, a 16,384-byte gap and 64 disjoint out-of-order segments. Payload bytes are
retained only within these limits to check retransmissions against earlier parsed
requests. Terminal unsupported, ambiguous or resource-limit states discard the
buffers. The flow tracker additionally supplies bounded flow count and idle/absolute
timeouts. The request count limit applies to subsequent requests, so exactly 32
completed requests can be inspected before further input exceeds that limit.

`status()` reports state, reason, received payload bytes (including retransmissions),
buffered unique bytes, pending segment count, inspected request count and whether a
SYN was observed. These are application observations, not NIC/kernel drop statistics.

## Unsupported and limited behavior

TLS/HTTPS payloads are encrypted and cannot be inspected. HTTP/2, chunked or other
Transfer-Encoding request bodies, CONNECT tunnels and post-upgrade traffic are
unsupported. HTTP/3 and other protocols are unsupported. Oversized streams stop
inspection; skipped bytes are never reported as examined. Multipart uploads,
compressed bodies, arbitrary encodings, arbitrary nesting, parser differentials and
obfuscation beyond the documented rules are not comprehensively supported. There is
no TLS interception, exploitation verification or vulnerability scanning.

`feed(seq, payload, syn=False)` returns request dictionaries with method, minimal
path, test_id, rules and an inspection object (`complete` or `partial` with reason).
`status()` separately exposes stream-level waiting/collecting/unsupported/ambiguous/
resource_limit state. Callers must expose these limitations alongside flow evidence.

Automated tests exercise real byte sequences and sequence positions, including
benign requests, segmented bodies, out-of-order delivery, overlap conflict,
retransmission deduplication, sequence wrap, framing ambiguities and resource limits.
Fresh capture validation is separately performed through the full application.
