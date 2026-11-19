import gzip
import hashlib
import unittest

from aw.exchange import (BODY_TEXT_MAX, decode_content, header, is_sensitive, make_body, mask, mask_cut, mask_form,
                         mask_json, mask_path, mask_text, mask_value)


class ExchangeHelpers(unittest.TestCase):
    def test_sensitive_names(self):
        for name in ("Cookie", "set-cookie", "Authorization", "x-auth-token", "web_session", "sid",
                     "access_token", "Proxy-Authorization", "password", "accessToken", "idToken",
                     "x-mini-sig", "sign", "X-Signature", "deviceId", "device_id", "did", "x-mini-gid",
                     "android_id", "IMEI", "oaid", "userId", "xhs-real-ip", "X-Xhs-Client-ip",
                     "x-forwarded-for", "client_ip"):
            self.assertTrue(is_sensitive(name), name)
        for name in ("User-Agent", "x-t", "content-type", "sidebar", "tokenizer", "x-b3-traceid", "design",
                     "zip", "valid", "launch_id", "x-mini-mua", "platform", "author", ""):
            self.assertFalse(is_sensitive(name), name)

    def test_sensitive_values(self):
        jwt = "eyJhbGciOiJub25lIn0.eyJhIjoxLCJiIjoyfQ."
        for value in (jwt, jwt + "c2lnbmF0dXJl", "0123456789abcdef0123456789abcdef",
                      "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3OA==", "550e8400-e29b-41d4-a716-446655440000"):
            self.assertTrue(is_sensitive("x-unknown", value), value)
        for value in ("application/x-www-form-urlencoded", "0123456789abcdef", "gzip, deflate",
                      "Dalvik/2.1.0 (Linux; U; Android 15)", "https://example.com/a/b/c/d/e/f/g/h/i/j/k",
                      "1" * 40, "a" * 40, "com.example.app.release.build", "",
                      "apm-native.xiaohongshu.example", "/api/sns/v6/homefeed/categories/list/items"):
            self.assertFalse(is_sensitive("x-unknown", value), value)

    def test_mask_json(self):
        secret = "0123456789abcdef0123456789abcdef"
        self.assertEqual(mask_json('{"a": 1, "b": "x"}'), '{"a": 1, "b": "x"}')
        self.assertEqual(mask_json('{"token":"abc","n":2}'), '{"token":"〈已隐藏，3 个字符〉","n":2}')
        self.assertEqual(mask_json('{"uid": 12345}'), '{"uid": 〈已隐藏，5 个字符〉}')     # in place, as sent
        self.assertEqual(mask_json('{"k": "%s"}' % secret), '{"k": "〈已隐藏，32 个字符〉"}')
        self.assertEqual(mask_json('["%s", "plain"]' % secret), '["〈已隐藏，32 个字符〉", "plain"]')
        # a value written with JSON escapes is judged by what it stands for
        self.assertNotIn("QUJD", mask_json(r'{"k": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3OA\u003d\u003d"}'))
        # JSON carried in a string value
        out = mask_json(r'{"data": "{\"deviceId\": \"abc\", \"x\": 1}"}')
        self.assertNotIn("abc", out)
        self.assertIn("deviceId", out)
        self.assertIn(r'\"x\": 1', out)
        # cut-off text: the string left open at the end is not shown, and says so; pairs before it are handled
        out = mask_json('{"sid": "s1", "note": "ok", "msg": "abcdefgh')
        self.assertEqual(out, '{"sid": "〈已隐藏，2 个字符〉", "note": "ok", "msg": "〈没有记录完整，不显示，8 个字符〉')
        self.assertEqual(mask_json('{"a": "ab', cut=False), '{"a": "ab')

    def test_mask_json_lone_strings_after_a_name(self):
        secret = "0123456789abcdef0123456789abcdef"
        self.assertEqual(mask_json('{"a":1,"l":["%s"]}' % secret), '{"a":1,"l":["〈已隐藏，32 个字符〉"]}')
        self.assertEqual(mask_json('{"l":["x","%s"],"k":"v"}' % secret), '{"l":["x","〈已隐藏，32 个字符〉"],"k":"v"}')

    def test_mask_json_arrays_and_objects_under_a_sensitive_name(self):
        found = set()
        out = mask_json('{"deviceId": ["d-1", "d-22222222"], "auth": {"access": "k-1", "n": 2}, "x": [1]}', found=found)
        self.assertEqual(out, '{"deviceId": 〈已隐藏，21 个字符〉, "auth": 〈已隐藏，25 个字符〉, "x": [1]}')
        self.assertTrue({"d-1", "d-22222222", "k-1", "2"} <= found)      # every value inside, never a name
        self.assertNotIn("access", found)
        # cut off inside it: hidden to the end
        self.assertEqual(mask_json('{"token": {"v": "ab'), '{"token": 〈没有记录完整，不显示，9 个字符〉')
        # true, false and null under a sensitive name are values too
        self.assertEqual(mask_json('{"sid": null}'), '{"sid": 〈已隐藏，4 个字符〉}')

    def test_mask_json_urls_and_pairs_inside_strings(self):
        self.assertEqual(mask_json('{"url": "https://c.example/i?sign=s-1&t=1"}'),
                         '{"url": "https://c.example/i?sign=〈已隐藏，3 个字符〉&t=1"}')
        self.assertEqual(mask_json('{"n": "next=https%3A%2F%2Fa.example%2Fp%3Ftoken%3Dt-1"}'),
                         '{"n": "next=https%3A%2F%2Fa.example%2Fp%3Ftoken%3D〈已隐藏，3 个字符〉"}')     # as sent
        self.assertEqual(mask_json('["a=1&sid=s-2"]'), '["a=1&sid=〈已隐藏，3 个字符〉"]')

    def test_mask_value(self):
        m = mask("s-1")
        for value, shown in ((f"platform=android; deviceId=s-1", f"platform=android; deviceId={m}"),
                             ("a=1;sid=s-1", f"a=1;sid={m}"), ("did=s-1, os=android", f"did={m}, os=android"),
                             ("x=1#token=s-1", f"x=1#token={m}"),
                             ("https://a.example/cb#access_token=s-1&state=ok", f"https://a.example/cb#access_token={m}&state=ok"),
                             ("/p?x=1#token=s-1", f"/p?x=1#token={m}"),
                             ("/feed;sessionid=s-1;v=2/x?sign=s-1", f"/feed;sessionid={m};v=2/x?sign={m}"),
                             ('{"deviceId": "s-1"}', f'{{"deviceId": "{m}"}}'),
                             ("/a&token=b/c", "/a&token=b/c"), ("gzip, deflate", "gzip, deflate"),
                             ("text/plain; charset=utf-8", "text/plain; charset=utf-8")):
            self.assertEqual(mask_value(value), shown, value)
        self.assertEqual(mask_path("/feed;sessionid=s-1/a&token=b"), f"/feed;sessionid={m}/a&token=b")
        # a part without a name is hidden when it has the shape of a token
        self.assertEqual(mask_value("v1, 0123456789abcdef0123456789abcdef"), "v1, 〈已隐藏，32 个字符〉")

    def test_mask_text(self):
        m = mask("s-1")
        self.assertEqual(mask_text('cb({"token": "s-1"})'), f'cb({{"token": "{m}"}})')
        self.assertEqual(mask_text("token=s-1&x=1"), f"token={m}&x=1")
        self.assertEqual(mask_text("free 0123456789abcdef0123456789abcdef sid=s-1."),
                         f"free {mask('0123456789abcdef0123456789abcdef')} sid={mask('s-1.')}")
        self.assertEqual(mask_text("a=1&token=s-", cut=True), "a=1&token=〈没有记录完整，不显示，2 个字符〉")
        multi = ('--B\r\nContent-Disposition: form-data; name="token"\r\n\r\ns-1\r\n'
                 '--B\r\nContent-Disposition: form-data; name="n"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n')
        self.assertEqual(mask_text(multi), multi.replace("\r\ns-1\r\n", f"\r\n{m}\r\n"))
        self.assertEqual(mask_form("n=2&trace=ab", cut=True), "n=2&trace=〈没有记录完整，不显示，2 个字符〉")
        found = set()
        mask_text('{"sid": "s-1", "u": "/x?token=t%2B1"}', found=found)
        self.assertEqual(found, {"s-1", "t+1"})       # decoded, whatever form they were written in

    # Made-up values for the cases below: none comes from a capture.
    V = "Qx9fakeVal01"
    OPAQUE = "Zq7fakeOpaque0042Zq7fakeOpaque0042Zq7f"          # 38 letters and digits: the shape of a token
    JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.Zq7fakeSigZq7fakeSig"

    def test_form_bodies(self):
        m = mask(self.V)
        # JSON sent with a form content type is examined as JSON; fields on separate lines are fields
        self.assertEqual(mask_form(f'{{"uid":"{self.V}","a":1}}'), f'{{"uid":"{m}","a":1}}')
        self.assertEqual(mask_form(f"a=1\nsid={self.V}"), f"a=1\nsid={m}")
        self.assertEqual(mask_form(f"a=1&sid={self.V}\r\n"), f"a=1&sid={m}\r\n")
        # a form value runs to "&", whatever it holds
        self.assertEqual(mask_form("password=my pass(1)&x=1"), f"password={mask('my pass(1)')}&x=1")
        self.assertEqual(mask_form("n=2&b=", cut=True), "n=2&b=")                    # nothing to hide

    def test_quoted_values(self):
        m = mask(self.V)
        for text, shown in ((f'cfg sid="{self.V}" ok', f'cfg sid="{m}" ok'),
                            (f'<div data-uid="{self.V}">', f'<div data-uid="{m}">'),
                            (f"token='{self.V}'", f"token='{m}'"),
                            (f'he said "hi. {{"sid":"{self.V}"}}', f'he said "hi. {{"sid":"{m}"}}'),     # a stray quote
                            (f"sid = {self.V}", f"sid = {m}")):
            self.assertEqual(mask_text(text), shown, text)
        found = set()
        self.assertEqual(mask_value(f'sid="{self.V}" ;a=1, b = 2; uid = {self.V} ', found),
                         f'sid="{m}" ;a=1, b = 2; uid = {m} ')
        self.assertEqual(found, {self.V})                   # without the quotes and spaces around it

    def test_values_with_no_name(self):
        for text in (self.JWT, self.OPAQUE, self.OPAQUE + "\n", f"word\n{self.OPAQUE}", f"code {self.OPAQUE}.",
                     f"[{self.OPAQUE}]"):
            shown = mask_text(text)
            self.assertNotIn(self.OPAQUE, shown, text)
            self.assertNotIn(self.JWT, shown, text)
            self.assertIn("〈已隐藏，", shown, text)
        self.assertEqual(mask_text(f"code {self.OPAQUE}."), f"code {mask(self.OPAQUE)}.")
        self.assertEqual(mask_value(f"Bearer {self.OPAQUE}"), f"Bearer {mask(self.OPAQUE)}")
        self.assertEqual(mask_json(f'{{"m": "your code {self.OPAQUE} now"}}'), f'{{"m": "your code {mask(self.OPAQUE)} now"}}')
        self.assertEqual(mask_text("plain words, short-ids 12345 and a/b/c."), "plain words, short-ids 12345 and a/b/c.")
        # cut: the last run of token characters may be part of a token
        self.assertEqual(mask_text(f"ok {self.OPAQUE[:12]}", cut=True), f"ok {mask_cut(self.OPAQUE[:12])}")

    def test_fields_separated_by_line_breaks_and_tabs(self):
        m = mask(self.V)
        self.assertEqual(mask_json(f'{{"m":"os=a\\nsid={self.V}\\tx=1"}}'), f'{{"m":"os=a\\nsid={m}\\tx=1"}}')
        deeper = f'{{"a":"{{\\"b\\":\\"x=1\\\\nuid={self.V}\\"}}"}}'
        self.assertEqual(mask_json(deeper), deeper.replace(self.V, m))
        self.assertEqual(mask_value(f"a=1 uid={self.V}"), f"a=1 uid={m}")

    def test_json_inside_a_field_value(self):
        m = mask(self.V)
        self.assertEqual(mask_value(f'data={{"a":1,"uid":"{self.V}"}}, x=2'), f'data={{"a":1,"uid":"{m}"}}, x=2')
        text = f'{{"q":"data={{\\"a\\":1,\\"uid\\":\\"{self.V}\\"}}"}}'
        self.assertEqual(mask_json(text), text.replace(self.V, m))

    def test_encoded_values_are_judged_decoded_and_shown_as_sent(self):
        m = mask(self.V)
        for value in (f"a%3D1%26sid%3D{self.V}",                            # a header value
                      f"next=https%253A%252F%252Fx.example%252Fq%253Fsid%253D{self.V}&k=1"):     # encoded twice
            self.assertEqual(mask_value(value), value.replace(self.V, m), value)
        text = f'{{"link":"https%3A%2F%2Fx.example%2Fp%3Fsid%3D{self.V}","u":"\\/p?token\\u003d{self.V}"}}'
        self.assertEqual(mask_json(text), text.replace(self.V, m))
        text = f'<div data-state="{{&quot;userId&quot;:&quot;{self.V}&quot;}}">'
        self.assertEqual(mask_text(text), text.replace(self.V, m))
        # pairs whose values are shown as sent, apart from the hidden one; a number under a sensitive name in place
        self.assertEqual(mask_path(f"/p?geo=a%3D1%26sid%3D{self.V}&k=2"), f"/p?geo=a%3D1%26sid%3D{m}&k=2")
        found = set()
        mask_value(f"x=1&sid={self.V}%2F1", found)
        self.assertEqual(found, {self.V + "/1"})

    def test_tokens_with_plus(self):
        token = "Zq7fake+Opaque0042+Zq7fakeOpaque0042/Zq7"
        m = mask(token)
        self.assertEqual(mask_value(f"a=1&t={token}"), f"a=1&t={m}")
        self.assertEqual(mask_path(f"/p#t={token}"), f"/p#t={m}")
        self.assertEqual(mask_text(f"t={token} ok"), f"t={m} ok")
        self.assertEqual(mask_json(f'{{"q":"a=1&t={token}"}}'), f'{{"q":"a=1&t={m}"}}')
        found = set()
        mask_path(f"/p?t={token}", found)
        self.assertIn(token.replace("+", " "), found)           # as the query table shows it

    def test_multipart_bodies(self):
        m = mask(self.V)

        def part(name, value, b="b"):
            return f"--{b}\r\nContent-Disposition: form-data; name={name}\r\n\r\n{value}\r\n"
        for text in ("\r\n" + part('"sid"', self.V) + "--b--\r\n",              # a line break before the first boundary
                     part("sid", self.V) + "--b--",                              # the name without quotes
                     part('"note"', f"x=1 uid={self.V}") + "--b--"):             # a field examined as text
            self.assertEqual(mask_text(text), text.replace(self.V, m), text)
        early = f"x\r\n--{self.V}"                       # a value with "--" after a line break, not the boundary
        self.assertEqual(mask_text(part('"token"', early) + "--b--"), part('"token"', mask(early)) + "--b--")
        self.assertEqual(mask_text(part('"n"', "1") + part('"note"', self.V[:5])[:-2], cut=True),
                         part('"n"', "1") + part('"note"', mask_cut(self.V[:5]))[:-2])

    def test_fragments_and_matrix_parameters_of_paths(self):
        m = mask(self.V)
        self.assertEqual(mask_path(f"/p#sid={self.V}"), f"/p#sid={m}")
        self.assertEqual(mask_path(f"/a;sid={self.V}/b?x=1#token={self.V}&s=ok"), f"/a;sid={m}/b?x=1#token={m}&s=ok")
        self.assertEqual(mask_path(f"/u/{self.V}/x"), f"/u/{self.V}/x")         # plain segments are not judged

    def test_mask_keeps_only_the_length(self):
        self.assertEqual(mask("abcdef"), "〈已隐藏，6 个字符〉")

    def test_decode_content(self):
        raw = b'{"a": 1}'
        self.assertEqual(decode_content(raw, None), (raw, True))
        self.assertEqual(decode_content(gzip.compress(raw), "gzip"), (raw, True))
        self.assertEqual(decode_content(gzip.compress(raw)[:10], "gzip"), (gzip.compress(raw)[:10], False))
        self.assertEqual(decode_content(raw, "br"), (raw, False))

    def test_make_body(self):
        self.assertIsNone(make_body(b""))
        raw = gzip.compress('{"名": "值"}'.encode())
        b = make_body(raw, "application/json; charset=utf-8", "gzip")
        self.assertEqual((b["kind"], b["text"], b["decoded"], b["encoding"]), ("json", '{"名": "值"}', True, "gzip"))
        self.assertEqual(b["size"], len(raw))
        self.assertEqual(b["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(make_body(b"k=v&aw=1", "application/x-www-form-urlencoded")["kind"], "form")
        self.assertEqual(make_body(b"[1, 2]", "text/plain")["kind"], "json")
        self.assertEqual(make_body(b"hello", None)["kind"], "text")
        b = make_body(b"\x00\x01\x02\xff", "application/octet-stream")
        self.assertEqual((b["kind"], b["text"], b["preview_hex"]), ("binary", None, "000102ff"))
        b = make_body(b"x" * 10, None, "br")
        self.assertEqual((b["kind"], b["decoded"]), ("binary", False))
        self.assertFalse(make_body(b"hello", None)["encoding_detected"])
        b = make_body(b"a" * (BODY_TEXT_MAX + 5), "text/plain")
        self.assertTrue(b["truncated"])
        self.assertEqual(len(b["text"]), BODY_TEXT_MAX)

    def test_make_body_when_the_encoding_header_could_not_be_read(self):
        raw = gzip.compress('{"名": "值"}'.encode())
        b = make_body(raw, None, None, encoding_known=False)
        self.assertEqual((b["kind"], b["text"], b["decoded"], b["encoding"], b["encoding_detected"]),
                         ("json", '{"名": "值"}', True, "gzip", True))
        self.assertEqual((b["size"], b["sha256"]), (len(raw), hashlib.sha256(raw).hexdigest()))
        # gzip start but a wrong checksum, cut off, or with bytes after the member: left as sent
        for bad in (raw[:-8] + b"\x00" * 8, raw[:-3], raw + b"x"):
            b = make_body(bad, None, None, encoding_known=False)
            self.assertEqual((b["kind"], b["decoded"], b["encoding"], b["encoding_detected"], b["text"]),
                             ("binary", False, None, False, None))
            self.assertTrue(b["preview_hex"].startswith("1f8b"))
        b = make_body(b"k=v", None, None, encoding_known=False)
        self.assertEqual((b["kind"], b["text"], b["decoded"], b["encoding"]), ("text", "k=v", True, None))
        # a header that is known wins: nothing is guessed from the bytes
        b = make_body(raw, "application/octet-stream", None)
        self.assertEqual((b["kind"], b["decoded"], b["encoding"], b["encoding_detected"]),
                         ("binary", True, None, False))

    def test_header_lookup(self):
        self.assertEqual(header([["Host", "a"], ["host", "b"]], "HOST"), "a")
        self.assertIsNone(header([], "x"))


if __name__ == "__main__":
    unittest.main()
