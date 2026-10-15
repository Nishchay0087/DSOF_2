import json
import unittest
import uuid

from dsof.http_detect import HTTPStream


def request(target="/", *, body=b"", content_type=None, extra=()):
    method = "POST" if body else "GET"
    headers = [f"{method} {target} HTTP/1.1", "Host: localhost"] + list(extra)
    if body:
        headers.append(f"Content-Length: {len(body)}")
    if content_type:
        headers.append(f"Content-Type: {content_type}")
    return "\r\n".join(headers).encode() + b"\r\n\r\n" + body


def inspect(payload):
    stream = HTTPStream()
    stream.feed(100, b"", syn=True)
    return stream, stream.feed(101, payload)


class HTTPDetectionTests(unittest.TestCase):
    def test_query_sql_injection_and_minimal_evidence(self):
        _, found = inspect(request("/search?password=secret&q=%27%20OR%201%3D1--"))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["path"], "/search")
        self.assertEqual(found[0]["rules"][0]["name"], "sql_boolean_comparison")
        self.assertEqual(found[0]["rules"][0]["evidence"], "OR 1=1")
        self.assertNotIn("secret", json.dumps(found))

    def test_supported_attack_families_and_two_pass_url_decode(self):
        samples = [("/?q=UNION%2520SELECT", "sql_union_select"),
                   ("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss_script_tag"),
                   ("/%252e%252e%252fprivate", "path_traversal"),
                   ("/?file=..%5C..%5Csecret", "path_traversal"),
                   ("/?q=%3Cimg%20src=x%20onerror=alert(1)%3E", "xss_event_handler")]
        for target, name in samples:
            with self.subTest(target=target):
                _, found = inspect(request(target))
                self.assertIn(name, {r["name"] for r in found[0]["rules"]})

    def test_decoding_is_bounded(self):
        _, found = inspect(request("/%25252e%25252e%25252fprivate"))
        self.assertEqual(found[0]["rules"], [])

    def test_benign_requests_and_uninspected_headers(self):
        benign = ["/", "/search?q=select+a+book", "/path/file.txt?name=O%27Reilly", "/?page=1&limit=20"]
        for target in benign:
            _, found = inspect(request(target, extra=("Cookie: x=<script> OR 1=1", "Referer: http://a/?q=../etc/passwd")))
            self.assertEqual(found[0]["rules"], [])

    def test_response_payload_is_not_request_evidence(self):
        stream, found = inspect(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n<script>alert(1)")
        self.assertEqual(found, [])
        self.assertEqual(stream.status()["state"], "unsupported")
        self.assertIn("response", stream.status()["reason"])

    def test_bodies_form_json_and_plain(self):
        samples = [(b"user=admin&password=%27+OR+1%3D1--", "application/x-www-form-urlencoded", "sql_boolean_comparison"),
                   (b'{"profile":{"name":"<svg/onload=alert(1)>"}}', "application/json", "xss_event_handler"),
                   (b"../../secret", "text/plain", "path_traversal")]
        for body, content_type, name in samples:
            _, found = inspect(request("/submit", body=body, content_type=content_type))
            self.assertIn(name, {r["name"] for r in found[0]["rules"]})
            self.assertEqual(found[0]["inspection"]["state"], "complete")

    def test_unsupported_or_invalid_body_is_explicit_partial(self):
        samples = [(b"<script>", "application/octet-stream"),
                   (b"{<script>", "application/json"),
                   (b"\xff<script>", "text/plain")]
        for body, content_type in samples:
            _, found = inspect(request(body=body, content_type=content_type))
            self.assertEqual(found[0]["rules"], [])
            self.assertEqual(found[0]["inspection"]["state"], "partial")

    def test_encoded_body_is_not_claimed_inspected_and_uri_credentials_not_returned(self):
        for extra, content_type in ((("Content-Encoding: gzip",), "text/plain"),
                                    ((), "text/plain; charset=iso-8859-1")):
            _, found = inspect(request(body=b"<script>", content_type=content_type, extra=extra))
            self.assertEqual(found[0]["rules"], [])
            self.assertEqual(found[0]["inspection"]["state"], "partial")
        _, found = inspect(request("http://user:secret@localhost/search?q=UNION+SELECT"))
        self.assertEqual(found[0]["path"], "/search")
        self.assertNotIn("secret", json.dumps(found))
        self.assertEqual(found[0]["rules"][0]["name"], "sql_union_select")

    def test_sql_comments_between_tokens(self):
        _, found = inspect(request("/?q=UNION%2F%2Anote%2A%2FSELECT"))
        self.assertEqual(found[0]["rules"][0]["name"], "sql_union_select")

    def test_segmented_body_and_request_produce_only_one_result(self):
        data = request("/login", body=b"name=user&pw=%27+OR+1%3D1--", content_type="application/x-www-form-urlencoded")
        stream = HTTPStream()
        stream.feed(100, b"", syn=True)
        found = []
        for index in range(0, len(data), 7):
            found.extend(stream.feed(101 + index, data[index:index+7]))
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["rules"]), 1)
        self.assertEqual(stream.feed(101, data), [])
        self.assertEqual(stream.status()["inspected_requests"], 1)

    def test_out_of_order_with_initial_syn(self):
        data = request("/?q=UNION+SELECT")
        stream = HTTPStream()
        stream.feed(100, b"", syn=True)
        self.assertEqual(stream.feed(121, data[20:40]), [])
        self.assertEqual(stream.feed(141, data[40:]), [])
        found = stream.feed(101, data[:20])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["rules"][0]["name"], "sql_union_select")

    def test_identical_pending_overlap_is_merged_and_conflicting_overlap_rejected(self):
        data = request("/?q=UNION+SELECT")
        stream = HTTPStream()
        stream.feed(100, b"", syn=True)
        stream.feed(111, data[10:30])
        stream.feed(121, data[20:])
        self.assertEqual(stream.status()["pending_segments"], 1)
        self.assertEqual(len(stream.feed(101, data[:15])), 1)
        stream.feed(101, b"POST")
        self.assertEqual(stream.status()["state"], "ambiguous")
        self.assertEqual(stream.status()["buffered_bytes"], 0)

    def test_conflicting_pending_overlap_stops_before_any_request(self):
        stream = HTTPStream()
        stream.feed(100, b"", syn=True)
        stream.feed(111, b"0123456789")
        self.assertEqual(stream.feed(116, b"XXXXX"), [])
        self.assertEqual(stream.status()["state"], "ambiguous")

    def test_tcp_sequence_wrap_and_syn_payload(self):
        data = request("/?q=UNION+SELECT")
        stream = HTTPStream()
        self.assertEqual(stream.feed(0xFFFFFFFE, data[:8], syn=True), [])
        self.assertEqual(len(stream.feed(7, data[8:])), 1)

    def test_pipelining_and_identical_requests_are_real_separate_requests(self):
        data = request("/first") + request("/second")
        _, found = inspect(data)
        self.assertEqual([x["path"] for x in found], ["/first", "/second"])
        _, found = inspect(request("/same") * 2)
        self.assertEqual(len(found), 2)

    def test_ambiguous_content_length_and_request_smuggling_framing_rejected(self):
        samples = [b"Content-Length: 0\r\nContent-Length: 1",
                   b"Content-Length: 0\r\nContent-Length: 0",
                   b"Content-Length: 0\r\nTransfer-Encoding: chunked",
                   b"Content-Length: 0, 1", b"Content-Length: -1",
                   b"Content-Length : 1", b" Folded: value", b"Bad: a\x00b"]
        for header in samples:
            with self.subTest(header=header):
                stream, found = inspect(b"POST / HTTP/1.1\r\n" + header + b"\r\n\r\n")
                self.assertEqual(found, [])
                self.assertEqual(stream.status()["state"], "ambiguous")

    def test_chunked_tls_http2_and_connect_are_explicitly_unsupported(self):
        samples = [b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                   b"\x16\x03\x03\x00\x2f", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                   b"CONNECT localhost:443 HTTP/1.1\r\n\r\n"]
        for data in samples:
            stream, found = inspect(data)
            self.assertEqual(found, [])
            self.assertEqual(stream.status()["state"], "unsupported")

    def test_test_id_is_only_valid_correlation_not_trust(self):
        correlation = str(uuid.uuid4())
        _, found = inspect(request(extra=(f"X-DSOF-Test-ID: {correlation}",)))
        self.assertEqual(found[0]["test_id"], correlation)
        self.assertNotIn("origin", found[0])
        self.assertNotIn("trusted", found[0])
        _, found = inspect(request(extra=("X-DSOF-Test-ID: trusted-live-attack",)))
        self.assertIsNone(found[0]["test_id"])
        stream, found = inspect(request(extra=(f"X-DSOF-Test-ID: {correlation}", f"X-DSOF-Test-ID: {correlation}")))
        self.assertEqual(found, [])
        self.assertEqual(stream.status()["state"], "ambiguous")

    def test_resource_limits_for_bytes_gaps_segments_requests_and_json(self):
        stream = HTTPStream(max_bytes=256)
        stream.feed(1, b"", syn=True)
        stream.feed(2, b"GET / HTTP/1.1\r\nContent-Length: 257\r\n\r\n")
        self.assertEqual(stream.status()["state"], "resource_limit")
        stream = HTTPStream()
        stream.feed(1, b"", syn=True)
        stream.feed(20000, b"A")
        self.assertEqual(stream.status()["state"], "resource_limit")
        stream = HTTPStream()
        stream.feed(1, b"", syn=True)
        for n in range(65):
            stream.feed(4 + n * 2, b"A")
        self.assertEqual(stream.status()["state"], "resource_limit")
        self.assertEqual(stream.status()["buffered_bytes"], 0)
        stream = HTTPStream(max_requests=1)
        found = stream.feed(1, request("/one") + request("/two"))
        self.assertEqual(len(found), 1)
        self.assertEqual(stream.status()["state"], "resource_limit")
        _, found = inspect(request(body=json.dumps(["x"] * 300).encode(), content_type="application/json"))
        self.assertEqual(found[0]["inspection"]["state"], "partial")

    def test_incomplete_body_waits_without_fabricating_request(self):
        stream, found = inspect(b"POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n<script>")
        self.assertEqual(found, [])
        self.assertIn("Waiting", stream.status()["reason"])

    def test_midstream_anchor_limit_is_reported(self):
        stream = HTTPStream()
        stream.feed(110, b"incomplete body bytes")
        self.assertEqual(stream.status()["state"], "unsupported")

    def test_configuration_and_input_validation(self):
        for kwargs in ({"max_bytes": -1}, {"max_requests": 0}, {"max_bytes": True}):
            with self.assertRaises(ValueError):
                HTTPStream(**kwargs)
        stream = HTTPStream()
        for seq, data in ((-1, b"x"), (True, b"x"), (1, "text")):
            with self.assertRaises(ValueError):
                stream.feed(seq, data)


if __name__ == "__main__":
    unittest.main()
