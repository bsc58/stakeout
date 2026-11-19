"""Tests for aw/parse_har.py. All HAR content here is synthetic."""
import base64
import gzip
import hashlib
import json
import os
import tempfile
import unittest

from aw.exchange import make_body
from aw.parse_har import parse_har

EXCHANGE_KEYS = {"source", "time", "protocol", "method", "scheme", "host", "path", "query",
                 "request", "response", "pid", "thread", "partial", "connection_host_tail"}
BODY_KEYS = set(make_body(b"x"))


def hdrs(*pairs):
    return [{"name": n, "value": v} for n, v in pairs]


def entry(url, started="2026-11-19T06:21:30.000+00:00", method="GET", version="HTTP/1.1",
          req_headers=(), post=None, body_size=0, response="default", **extra):
    req = {"method": method, "url": url, "httpVersion": version, "headers": hdrs(*req_headers),
           "queryString": [], "cookies": [], "headersSize": -1, "bodySize": body_size}
    if post is not None:
        req["postData"] = post
    if response == "default":
        response = resp(200)
    e = {"startedDateTime": started, "time": 12.5, "request": req, "cache": {}, "timings": {}}
    if response is not None:
        e["response"] = response
    e.update(extra)
    return e


def resp(status, headers=(), text=None, encoding=None, mime="", size=0, body_size=None):
    content = {"size": size, "mimeType": mime}
    if text is not None:
        content["text"] = text
    if encoding is not None:
        content["encoding"] = encoding
    return {"status": status, "statusText": "", "httpVersion": "HTTP/1.1", "headers": hdrs(*headers),
            "cookies": [], "content": content, "redirectURL": "", "headersSize": -1,
            "bodySize": size if body_size is None else body_size}


def har(entries, creator=("mitmproxy", "11.0")):
    log = {"version": "1.2", "pages": [], "entries": entries}
    if creator:
        log["creator"] = {"name": creator[0], "version": creator[1]}
    return {"log": log}


class HarCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def write(self, doc, name="t.har"):
        path = os.path.join(self._tmp.name, name)
        data = doc if isinstance(doc, bytes) else json.dumps(doc, ensure_ascii=False).encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def parse(self, entries, utc_offset="+0000", **kw):
        return parse_har(self.write(har(entries, **kw)), utc_offset)

    def one(self, e, utc_offset="+0000"):
        r = self.parse([e], utc_offset)
        self.assertEqual(len(r["exchanges"]), 1, r)
        return r["exchanges"][0]


class MitmproxyStyle(HarCase):
    """Shapes as mitmproxy's hardump writes them: UTC with +00:00 and microseconds,
    HTTP/2.0 version strings, decoded content, status 0 for flows without a response."""

    def test_gzip_already_removed_is_not_decoded_twice(self):
        text = '{"ok": true, "名": "值"}'
        wire = gzip.compress(text.encode())
        e = entry("https://edith.example.com/api/feed",
                  started="2026-11-19T06:21:30.123456+00:00", version="HTTP/2.0",
                  response=resp(200, [("content-type", "application/json; charset=utf-8"),
                                      ("content-encoding", "gzip")],
                                text=text, mime="application/json; charset=utf-8", size=len(wire)))
        r = self.parse([e], "-0500")
        self.assertEqual((r["creator"], r["entries"], r["skipped"]), ("mitmproxy 11.0", 1, 0))
        x = r["exchanges"][0]
        self.assertEqual(set(x), EXCHANGE_KEYS)
        self.assertEqual((x["source"], x["time"], x["protocol"], x["method"], x["scheme"], x["host"], x["path"]),
                         ("har", "2026-11-19 01:21:30.123", "h2", "GET", "https", "edith.example.com", "/api/feed"))
        self.assertIsNone(x["connection_host_tail"])
        body = x["response"]["body"]
        self.assertEqual((body["kind"], body["text"], body["decoded"], body["encoding"], body["encoding_detected"]),
                         ("json", text, True, None, False))
        self.assertEqual(body["size"], len(text.encode()))
        self.assertEqual(body["sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(x["response"]["status"], 200)
        self.assertTrue(x["response"]["complete"])
        self.assertIn(["content-encoding", "gzip"], x["response"]["headers"])
        self.assertEqual(x["partial"], [])
        self.assertEqual((x["pid"], x["thread"]), (None, None))
        json.dumps(r)

    def test_base64_response_content(self):
        raw = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256))
        e = entry("https://img.example.com/a.png",
                  response=resp(200, [("Content-Type", "image/png")], text=base64.b64encode(raw).decode(),
                                encoding="base64", mime="image/png", size=len(raw)))
        body = self.one(e)["response"]["body"]
        self.assertEqual((body["kind"], body["size"], body["text"]), ("binary", len(raw), None))
        self.assertEqual(body["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(body["preview_hex"], raw[:64].hex())

    def test_base64_text_content_is_decoded_by_charset(self):
        raw = "名=值".encode("gbk")
        e = entry("https://a.example.com/t",
                  response=resp(200, [("Content-Type", "text/plain; charset=gbk")],
                                text=base64.b64encode(raw).decode(), encoding="base64", size=len(raw)))
        body = self.one(e)["response"]["body"]
        self.assertEqual((body["kind"], body["text"], body["size"]), ("text", "名=值", len(raw)))

    def test_damaged_base64_is_not_decoded(self):
        e = entry("https://a.example.com/x",
                  response=resp(200, [("Content-Type", "image/png")], text="not base64!", encoding="base64", size=9))
        x = self.one(e)
        body = x["response"]["body"]
        self.assertEqual((body["decoded"], body["size"], body["text"], body["preview_hex"]), (False, None, None, None))
        self.assertEqual(set(body), BODY_KEYS)          # the same keys as make_body's BODY
        self.assertIs(body["encoding_detected"], False)
        self.assertEqual(x["partial"], ["body_not_decoded"])

    def test_form_post_with_text_and_params(self):
        form = "user=alice&remember=1&q=%E4%BD%A0"
        post = {"mimeType": "application/x-www-form-urlencoded", "text": form,
                "params": [{"name": "user", "value": "alice"}, {"name": "remember", "value": "1"}]}
        e = entry("https://api.example.com/v2/login", method="POST", post=post, body_size=len(form),
                  req_headers=[("Content-Type", "application/x-www-form-urlencoded")])
        x = self.one(e)
        body = x["request"]["body"]
        self.assertEqual((body["kind"], body["text"], body["size"]), ("form", form, len(form)))
        self.assertTrue(x["request"]["complete"])
        self.assertEqual(x["partial"], [])

    def test_json_post_without_charset_is_utf8(self):
        text = '{"标题": "测试"}'
        post = {"mimeType": "application/json", "text": text}
        x = self.one(entry("https://api.example.com/note", method="POST", post=post,
                           body_size=len(text.encode())))
        body = x["request"]["body"]
        self.assertEqual((body["kind"], body["text"], body["size"]), ("json", text, len(text.encode())))
        self.assertEqual(x["partial"], [])

    def test_binary_post_saved_as_latin1_text_is_not_decoded(self):
        # mitmproxy writes a body without a declared charset as Latin-1 text: the bytes are not certain
        sent = b"\x08\x96\x01\x12\x04\xe5\x90\x8d\xff"
        post = {"mimeType": "application/x-protobuf", "text": sent.decode("latin-1"), "params": []}
        x = self.one(entry("https://api.example.com/pb", method="POST", post=post, body_size=len(sent),
                           req_headers=[("content-type", "application/x-protobuf")]))
        body = x["request"]["body"]
        self.assertEqual((body["decoded"], body["kind"], body["size"], body["sha256"], body["text"]),
                         (False, "binary", None, None, None))
        self.assertEqual(x["partial"], ["body_not_decoded"])

    def test_non_ascii_text_without_charset_is_not_decoded(self):
        e = entry("https://a.example.com/t",
                  response=resp(200, [("Content-Type", "text/plain")], text="café", size=5))
        x = self.one(e)
        self.assertFalse(x["response"]["body"]["decoded"])
        self.assertEqual(x["partial"], ["body_not_decoded"])

    def test_replacement_character_is_not_decoded(self):
        e = entry("https://a.example.com/t",
                  response=resp(200, [("Content-Type", "text/plain; charset=utf-8")], text="ab�cd", size=5))
        self.assertEqual(self.one(e)["partial"], ["body_not_decoded"])

    def test_text_the_declared_charset_cannot_encode_is_not_decoded(self):
        e = entry("https://a.example.com/t",
                  response=resp(200, [("Content-Type", "text/plain; charset=iso-8859-1")], text="名", size=3))
        self.assertEqual(self.one(e)["partial"], ["body_not_decoded"])

    def test_entry_without_response(self):
        e = entry("https://a.example.com/slow", response=resp(0, size=-1, body_size=-1), _error="Connection killed.")
        x = self.one(e)
        self.assertIsNone(x["response"])
        self.assertEqual(x["partial"], ["response_not_matched"])

    def test_entry_with_no_response_object(self):
        x = self.one(entry("https://a.example.com/x", response=None))
        self.assertIsNone(x["response"])
        self.assertEqual(x["partial"], ["response_not_matched"])

    def test_body_left_out_of_the_har(self):
        # mitmproxy keeps postData only for POST/PUT/PATCH
        x = self.one(entry("https://a.example.com/item/7", method="DELETE", body_size=12,
                           response=resp(200, [("Content-Type", "text/plain")], size=40)))
        self.assertIsNone(x["request"]["body"])
        self.assertFalse(x["request"]["complete"])
        self.assertIsNone(x["response"]["body"])
        self.assertFalse(x["response"]["complete"])
        self.assertEqual(x["partial"], ["request_incomplete", "response_incomplete"])

    def test_non_utf8_header_bytes(self):
        # mitmproxy decodes header bytes with surrogateescape and writes json.dumps(ensure_ascii=True)
        sent = b"attachment; filename=\xc4\xe3.txt"
        e = entry("https://a.example.com/f",
                  response=resp(200, [("Content-Disposition", sent.decode("utf-8", "surrogateescape"))]))
        r = parse_har(self.write(json.dumps(har([e])).encode("ascii")))
        x = r["exchanges"][0]
        self.assertEqual(x["response"]["headers"], [["Content-Disposition", sent.decode("latin-1")]])
        self.assertEqual(x["response"]["headers"][0][1].encode("latin-1"), sent)
        json.dumps(r, ensure_ascii=False).encode("utf-8")       # what analyze writes to result.json

    def test_connect_entry_is_skipped(self):
        tunnel = entry("https://a.example.com:443/", method="CONNECT", response=resp(502))
        r = self.parse([tunnel, entry("https://a.example.com/x")])
        self.assertEqual((r["entries"], r["skipped"]), (2, 1))
        self.assertEqual([x["method"] for x in r["exchanges"]], ["GET"])

    def test_empty_bodies(self):
        x = self.one(entry("https://a.example.com/x", method="POST",
                           post={"mimeType": "", "text": "", "params": []},
                           response=resp(204)))
        self.assertIsNone(x["request"]["body"])
        self.assertIsNone(x["response"]["body"])
        self.assertTrue(x["request"]["complete"] and x["response"]["complete"])
        self.assertEqual(x["partial"], [])


class ChromeStyle(HarCase):
    """Shapes as Chrome DevTools writes them: Z times with milliseconds, lower-case version
    strings, pseudo-headers in the request headers, charset only in the Content-Type header."""

    def test_chrome_entry(self):
        html = "<p>中文</p>"
        e = entry("https://m.example.com/page?from=share",
                  started="2026-11-19T06:21:31.5Z", version="http/2.0",
                  req_headers=[(":authority", "m.example.com"), (":method", "GET"), (":path", "/page?from=share"),
                               (":scheme", "https"), ("accept", "text/html")],
                  response=resp(200, [("content-type", "text/html; charset=gbk")], text=html,
                                mime="text/html", size=len(html.encode("gbk")), body_size=30),
                  _initiator={"type": "other"}, _priority="VeryHigh", _resourceType="document")
        r = self.parse([e], "+0800", creator=("WebInspector", "537.36"))
        self.assertEqual(r["creator"], "WebInspector 537.36")
        x = r["exchanges"][0]
        self.assertEqual((x["time"], x["protocol"], x["host"], x["path"], x["query"]),
                         ("2026-11-19 14:21:31.500", "h2", "m.example.com", "/page", [["from", "share"]]))
        self.assertEqual(x["request"]["headers"][0], [":authority", "m.example.com"])
        body = x["response"]["body"]
        self.assertEqual((body["kind"], body["text"], body["size"]), ("text", html, len(html.encode("gbk"))))
        self.assertEqual(body["sha256"], hashlib.sha256(html.encode("gbk")).hexdigest())
        self.assertEqual(x["partial"], [])

    def test_utf16_text_is_not_decoded(self):
        # a browser keeps the decoded text; the UTF-16 bytes (byte order, BOM) are not in it
        e = entry("https://a.example.com/t",
                  response=resp(200, [("content-type", "text/plain; charset=utf-16")], text="ab", size=6))
        x = self.one(e)
        self.assertEqual((x["response"]["body"]["decoded"], x["response"]["body"]["text"]), (False, None))
        self.assertEqual(x["partial"], ["body_not_decoded"])

    def test_failed_request_and_cache_hit(self):
        failed = entry("https://a.example.com/blocked", response=resp(0, size=0, body_size=-1),
                       _error="net::ERR_CONNECTION_REFUSED")
        cached = entry("https://a.example.com/logo.svg", _fromCache="memory",
                       response=resp(200, [("content-type", "image/svg+xml")], text="<svg/>", size=6, body_size=0))
        r = self.parse([failed, cached], creator=("WebInspector", "537.36"))
        self.assertEqual((r["entries"], r["skipped"], len(r["exchanges"])), (2, 1, 1))
        self.assertIsNone(r["exchanges"][0]["response"])
        self.assertEqual(r["exchanges"][0]["path"], "/blocked")

    def test_postdata_with_params_only_is_not_rebuilt(self):
        post = {"mimeType": "application/x-www-form-urlencoded",
                "params": [{"name": "a", "value": "1"}, {"name": "b", "value": "x y"}]}
        x = self.one(entry("https://a.example.com/form", method="POST", post=post, body_size=9))
        body = x["request"]["body"]
        self.assertEqual((body["decoded"], body["size"], body["text"]), (False, None, None))
        self.assertTrue(x["request"]["complete"])
        self.assertEqual(x["partial"], ["body_not_decoded"])

    def test_protocol_versions(self):
        cases = {"HTTP/1.1": "http/1.1", "http/1.0": "http/1.0", "HTTP/2": "h2", "h2": "h2",
                 "h3": "h3", "HTTP/3.0": "h3", "": None, "unknown": None}
        for version, want in cases.items():
            self.assertEqual(self.one(entry("https://a.example.com/", version=version))["protocol"], want, version)


class Times(HarCase):
    def test_z_offset_and_fractions(self):
        cases = [("2026-11-19T06:21:30Z", "2026-11-19 01:21:30.000"),
                 ("2026-11-19T06:21:30.5Z", "2026-11-19 01:21:30.500"),
                 ("2026-11-19T06:21:30.123456789Z", "2026-11-19 01:21:30.123"),
                 ("2026-11-19T06:21:30.999999+00:00", "2026-11-19 01:21:30.999"),
                 ("2026-11-19T14:21:30.250+08:00", "2026-11-19 01:21:30.250"),
                 ("2026-11-19T01:21:30-0500", "2026-11-19 01:21:30.000"),
                 ("2026-11-19T00:21:30.000-06:00", "2026-11-19 01:21:30.000")]
        for started, want in cases:
            self.assertEqual(self.one(entry("https://a.example.com/", started=started), "-0500")["time"], want, started)

    def test_sorted_by_time_across_offsets(self):
        es = [entry("https://a.example.com/3", started="2026-11-19T06:21:33Z"),
              entry("https://a.example.com/1", started="2026-11-19T14:21:31+08:00"),
              entry("https://a.example.com/2", started="2026-11-19T01:21:32.000-05:00")]
        r = self.parse(es, "+0000")
        self.assertEqual([x["path"] for x in r["exchanges"]], ["/1", "/2", "/3"])
        self.assertEqual(r["exchanges"][0]["time"], "2026-11-19 06:21:31.000")

    def test_time_without_offset_or_unreadable_is_skipped(self):
        es = [entry("https://a.example.com/naive", started="2026-11-19T06:21:30.000"),
              entry("https://a.example.com/bad", started="yesterday"),
              entry("https://a.example.com/none", started=None),
              entry("https://a.example.com/ok")]
        r = self.parse(es)
        self.assertEqual((r["entries"], r["skipped"]), (4, 3))
        self.assertEqual([x["path"] for x in r["exchanges"]], ["/ok"])


class Urls(HarCase):
    def test_port_and_query(self):
        x = self.one(entry("https://API.Example.com:8443/v2/items?id=7&tag=a%20b&flag&empty=&x=1+2&k%3D=%E5%90%8D#frag"))
        self.assertEqual((x["scheme"], x["host"], x["path"]), ("https", "api.example.com:8443", "/v2/items"))
        self.assertEqual(x["query"], [["id", "7"], ["tag", "a b"], ["flag", ""], ["empty", ""], ["x", "1 2"],
                                      ["k=", "名"]])

    def test_default_ports_and_empty_path(self):
        self.assertEqual(self.one(entry("https://a.example.com:443?x=1"))["host"], "a.example.com")
        x = self.one(entry("https://a.example.com?x=1"))
        self.assertEqual((x["path"], x["query"]), ("/", [["x", "1"]]))
        x = self.one(entry("http://a.example.com:80/p"))
        self.assertEqual((x["scheme"], x["host"]), ("http", "a.example.com"))
        self.assertEqual(self.one(entry("http://a.example.com:443/p"))["host"], "a.example.com:443")
        self.assertEqual(self.one(entry("https://[2001:db8::1]:8443/p"))["host"], "[2001:db8::1]:8443")
        self.assertEqual(self.one(entry("wss://a.example.com/ws"))["scheme"], "https")

    def test_path_kept_as_sent_and_undecodable_query_kept_raw(self):
        x = self.one(entry("https://a.example.com/a%20b/c?v=%FF%FE&w=ok"))
        self.assertEqual(x["path"], "/a%20b/c")
        self.assertEqual(x["query"], [["v", "%FF%FE"], ["w", "ok"]])

    def test_unusable_requests_are_skipped(self):
        es = [entry("ftp://a.example.com/f"), entry("https://a.example.com:99999/"), entry("not a url"),
              entry("https://a.example.com/x", method=""), {"startedDateTime": "2026-11-19T06:21:30Z"}, "junk",
              entry("https://a.example.com/fine")]
        r = self.parse(es)
        self.assertEqual((r["entries"], r["skipped"]), (7, 6))
        self.assertEqual(r["exchanges"][0]["path"], "/fine")

    def test_headers_that_are_not_a_list(self):
        e = entry("https://a.example.com/x", response=resp(200))
        e["request"]["headers"], e["response"]["headers"] = 5, "x"
        x = self.one(e)
        self.assertEqual((x["request"]["headers"], x["response"]["headers"]), ([], []))


class NotHar(HarCase):
    def test_not_har(self):
        for content in (b"hello", b'{"foo": 1}', b'{"log": {"entries": {}}}', b"[1, 2]", b"\x1f\x8b\x08\x00\xff"):
            path = self.write(content, "x.json")
            with self.assertRaises(ValueError) as cm:
                parse_har(path)
            self.assertIn("不是 HAR 文件", str(cm.exception))

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            parse_har(os.path.join(self._tmp.name, "absent.har"))

    def test_empty_har_without_creator_and_with_bom(self):
        path = self.write(b"\xef\xbb\xbf" + json.dumps(har([], creator=None)).encode())
        self.assertEqual(parse_har(path), {"creator": None, "entries": 0, "skipped": 0, "exchanges": []})


if __name__ == "__main__":
    unittest.main()
