import unittest

from aw import h2
from aw.h2 import Decoder, FrameError, FrameReader, HpackError


def hx(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


def frame(ftype, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + sid.to_bytes(4, "big") + payload


def table(d):
    return [(n.decode(), v.decode(), s) for n, v, s in d.entries]


REQ1 = [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")]
REQ2 = REQ1 + [("cache-control", "no-cache")]
REQ3 = [(":method", "GET"), (":scheme", "https"), (":path", "/index.html"),
        (":authority", "www.example.com"), ("custom-key", "custom-value")]
RESP1 = [(":status", "302"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
         ("location", "https://www.example.com")]
RESP2 = [(":status", "307")] + RESP1[1:]
RESP3 = [(":status", "200"), ("cache-control", "private"), ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
         ("location", "https://www.example.com"), ("content-encoding", "gzip"),
         ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1")]
REQ_TABLES = [
    [(":authority", "www.example.com", 57)],
    [("cache-control", "no-cache", 53), (":authority", "www.example.com", 57)],
    [("custom-key", "custom-value", 54), ("cache-control", "no-cache", 53), (":authority", "www.example.com", 57)],
]
RESP_TABLES = [
    [("location", "https://www.example.com", 63), ("date", "Mon, 21 Oct 2013 20:13:21 GMT", 65),
     ("cache-control", "private", 52), (":status", "302", 42)],
    [(":status", "307", 42), ("location", "https://www.example.com", 63),
     ("date", "Mon, 21 Oct 2013 20:13:21 GMT", 65), ("cache-control", "private", 52)],
    [("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", 98),
     ("content-encoding", "gzip", 52), ("date", "Mon, 21 Oct 2013 20:13:22 GMT", 65)],
]


class Primitives(unittest.TestCase):
    def test_integers_c1(self):
        self.assertEqual(h2.decode_integer(bytes([0b01010]), 0, 5), (10, 1))
        self.assertEqual(h2.decode_integer(hx("1f9a0a"), 0, 5), (1337, 3))
        self.assertEqual(h2.decode_integer(bytes([42]), 0, 8), (42, 1))
        with self.assertRaises(HpackError):
            h2.decode_integer(hx("1f9a"), 0, 5)          # continuation byte missing
        with self.assertRaises(HpackError):
            h2.decode_integer(hx("1fffffffffff01"), 0, 5)  # absurdly large

    def test_huffman_code_is_the_rfc_code(self):
        L, C = h2.HUFFMAN_LENGTHS, h2.HUFFMAN_CODES
        self.assertEqual(len(L), 257)
        self.assertEqual(sum(2.0 ** -l for l in L), 1.0)      # complete prefix code
        # codes as printed in RFC 7541 appendix B
        for sym, code, length in [(0, 0x1ff8, 13), (1, 0x7fffd8, 23), (9, 0xffffea, 24),
                                  (10, 0x3ffffffc, 30), (ord(" "), 0x14, 6), (ord("!"), 0x3f8, 10),
                                  (ord("0"), 0x0, 5), (ord(":"), 0x5c, 7), (ord("<"), 0x7ffc, 15),
                                  (ord("\\"), 0x7fff0, 19), (ord("a"), 0x3, 5), (ord("z"), 0x7b, 7),
                                  (ord("~"), 0x1ffd, 13), (127, 0xffffffc, 28), (128, 0xfffe6, 20),
                                  (153, 0x1fffdc, 21), (192, 0x3ffffe0, 26), (199, 0x1ffffec, 25),
                                  (203, 0x7ffffde, 27), (254, 0x7fffff0, 27), (255, 0x3ffffee, 26),
                                  (256, 0x3fffffff, 30)]:
            self.assertEqual((C[sym], L[sym]), (code, length), sym)

    def test_huffman_strings(self):
        self.assertEqual(h2.huffman_decode(hx("f1e3 c2e5 f23a 6ba0 ab90 f4ff")), b"www.example.com")
        self.assertEqual(h2.huffman_decode(hx("a8eb 1064 9cbf")), b"no-cache")
        self.assertEqual(h2.huffman_decode(b""), b"")
        with self.assertRaises(HpackError):
            h2.huffman_decode(hx("f1e3 c2e5 f23a 6ba0 ab90 f4ff ff"))   # 8 bits of padding
        with self.assertRaises(HpackError):
            h2.huffman_decode(hx("00"))                                 # padding not all ones
        with self.assertRaises(HpackError):
            h2.huffman_decode(hx("ffff fffc"))                          # EOS inside the string

    def test_every_byte_round_trips(self):
        # encode all 256 bytes with the table, decode them back
        bits = "".join(format(h2.HUFFMAN_CODES[b], f"0{h2.HUFFMAN_LENGTHS[b]}b") for b in range(256))
        bits += "1" * (-len(bits) % 8)
        data = int(bits, 2).to_bytes(len(bits) // 8, "big")
        self.assertEqual(h2.huffman_decode(data), bytes(range(256)))


class AppendixC(unittest.TestCase):
    def test_c2_single_fields(self):
        d = Decoder()
        self.assertEqual(d.decode(hx("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572")),
                         [("custom-key", "custom-header")])
        self.assertEqual(table(d), [("custom-key", "custom-header", 55)])
        d = Decoder()
        self.assertEqual(d.decode(hx("040c 2f73 616d 706c 652f 7061 7468")), [(":path", "/sample/path")])
        self.assertEqual(d.entries, [])
        d = Decoder()
        self.assertEqual(d.decode(hx("1008 7061 7373 776f 7264 0673 6563 7265 74")), [("password", "secret")])
        self.assertEqual(d.entries, [])
        d = Decoder()
        self.assertEqual(d.decode(hx("82")), [(":method", "GET")])
        self.assertEqual(d.entries, [])

    def _run(self, blocks, expected, tables, max_size=4096):
        d = Decoder(max_size=max_size)
        for block, want, tab in zip(blocks, expected, tables):
            self.assertEqual(d.decode(hx(block)), want)
            self.assertEqual(table(d), tab)
            self.assertEqual(d.size, sum(s for _, _, s in tab))

    def test_c3_requests(self):
        self._run(["8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
                   "8286 84be 5808 6e6f 2d63 6163 6865",
                   "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"],
                  [REQ1, REQ2, REQ3], REQ_TABLES)

    def test_c4_requests_huffman(self):
        self._run(["8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
                   "8286 84be 5886 a8eb 1064 9cbf",
                   "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"],
                  [REQ1, REQ2, REQ3], REQ_TABLES)

    def test_c5_responses_eviction(self):
        self._run(["4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133"
                   " 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70"
                   " 6c65 2e63 6f6d",
                   "4803 3330 37c1 c0bf",
                   "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d"
                   " 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049"
                   " 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e"
                   " 3d31"],
                  [RESP1, RESP2, RESP3], RESP_TABLES, max_size=256)

    def test_c6_responses_huffman_eviction(self):
        self._run(["4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6"
                   " 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
                   "4883 640e ffc1 c0bf",
                   "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab"
                   " 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f"
                   " 9587 3160 65c0 03ed 4ee5 b106 3d50 07"],
                  [RESP1, RESP2, RESP3], RESP_TABLES, max_size=256)


class DecoderRules(unittest.TestCase):
    def test_errors(self):
        for block in ("80",            # index 0
                      "be",            # index 62 on an empty table
                      "8220",          # size update after a field
                      "410f7777",      # string past the end
                      "c0"):           # dynamic index past the table
            with self.assertRaises(HpackError, msg=block):
                Decoder().decode(hx(block))
        self.assertEqual(Decoder(size_limit=4096).decode(hx("3fe11f")), [])   # update to 4096
        with self.assertRaises(HpackError):
            Decoder(size_limit=4096).decode(hx("3fe21f"))   # update to 4097: above the limit

    def test_size_update_evicts(self):
        d = Decoder()
        d.decode(hx("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
        self.assertEqual(d.decode(hx("20")), [])
        self.assertEqual(d.entries, [])
        self.assertEqual(d.max_size, 0)

    def test_tolerant_decoder_marks_what_it_cannot_know(self):
        d = Decoder(start_known=False)
        # 0xbe: unknown entry; 0x7e + literal value: literal with indexing, name unknown;
        # 0x40 literal name + value; then 0xbe refers to that new entry
        block = hx("be") + hx("7e") + b"\x03abc" + hx("40") + b"\x01x\x01y" + hx("be") + hx("82")
        self.assertEqual(d.decode(block), [(None, None), (None, "abc"), ("x", "y"), ("x", "y"), (":method", "GET")])
        self.assertEqual(d.unknown, 2)
        # in later blocks the two inserted entries are known by position, older ones are not
        self.assertEqual(d.decode(hx("bebfc0")), [("x", "y"), (None, "abc"), (None, None)])
        self.assertEqual(d.unknown, 2)


class Frames(unittest.TestCase):
    def test_split_across_and_within_chunks(self):
        body = bytes(range(256)) * 80                   # 20480 bytes: two DATA frames
        wire = (h2.PREFACE + frame(h2.SETTINGS, 0, 0, b"\x00\x04\x00\x01\x00\x00")
                + frame(h2.HEADERS, h2.END_HEADERS, 3, b"\x82") + frame(h2.DATA, 0, 3, body[:16384])
                + frame(h2.DATA, h2.END_STREAM, 3, body[16384:]))
        r = FrameReader(allow_preface=True)
        frames = []
        chunks = [wire[:5], wire[5:40], wire[40:8192], wire[8192:8201], wire[8201:]]
        for i, c in enumerate(chunks):
            frames += r.feed(c, i)
        self.assertTrue(r.at_boundary)
        self.assertEqual([f.type for f in frames], [h2.PREFACE_TYPE, h2.SETTINGS, h2.HEADERS, h2.DATA, h2.DATA])
        self.assertEqual(b"".join(h2.fragment(f) for f in frames if f.type == h2.DATA), body)
        self.assertEqual(frames[0].parts, [(0, 5), (1, 19)])
        self.assertEqual(sum(f.size for f in frames), len(wire))
        self.assertEqual(h2.settings(frames[1]), [(4, 65536)])

    def test_padding_and_priority_removed(self):
        f = FrameReader().feed(frame(h2.HEADERS, h2.END_HEADERS | h2.PADDED | h2.PRIORITY_FLAG, 1,
                                     b"\x02" + b"\x00\x00\x00\x00\x10" + b"\x82\x84" + b"\x00\x00"))[0]
        self.assertEqual(h2.fragment(f), b"\x82\x84")
        f = FrameReader().feed(frame(h2.DATA, h2.PADDED, 1, b"\x03abc\x00\x00\x00"))[0]
        self.assertEqual(h2.fragment(f), b"abc")
        with self.assertRaises(FrameError):
            FrameReader().feed(frame(h2.DATA, h2.PADDED, 1, b"\x09abc"))

    def test_invalid_headers(self):
        for bad in (frame(h2.DATA, 0, 0, b"x"),             # DATA on stream 0
                    frame(h2.SETTINGS, 0, 1),                # SETTINGS on a stream
                    frame(h2.PING, 0, 0, b"1234"),           # PING not 8 bytes
                    frame(h2.DATA, 0x2, 1, b"x"),            # undefined flag
                    frame(0x20, 0, 1),                       # unknown type
                    b"\x01\x00\x00" + bytes([0, 0]) + b"\x00\x00\x00\x01",   # 65536 > max size
                    b"\x00\x00\x00\x00\x00\x80\x00\x00\x01",                  # reserved bit
                    frame(h2.CONTINUATION, h2.END_HEADERS, 1, b"\x82")):      # no header block open
            with self.assertRaises(FrameError, msg=bad[:9].hex()):
                FrameReader().feed(bad)
        with self.assertRaises(FrameError):                  # preface only where allowed
            FrameReader().feed(h2.PREFACE)
        with self.assertRaises(FrameError):                  # header block interrupted
            FrameReader().feed(frame(h2.HEADERS, 0, 1, b"\x82") + frame(h2.DATA, 0, 1, b"x"))

    def test_strict_stream_rules(self):
        r = FrameReader(strict_streams=True)
        r.feed(frame(h2.HEADERS, h2.END_HEADERS, 1, b"\x88") + frame(h2.DATA, h2.END_STREAM, 1, b"x"))
        with self.assertRaises(FrameError):
            r.clone().feed(frame(h2.DATA, 0, 1, b"y"))
        r = FrameReader(strict_streams=True)
        r.feed(frame(h2.DATA, 0, 5, b"x"))
        with self.assertRaises(FrameError):
            r.feed(frame(h2.HEADERS, h2.END_HEADERS, 5, b"\x88"))

    def test_clone_and_state(self):
        r = FrameReader()
        r.feed(frame(h2.DATA, 0, 1, b"abcdef")[:12])
        c = r.clone()
        self.assertEqual(c.state_key(), r.state_key())
        self.assertFalse(c.at_boundary)
        self.assertEqual(h2.fragment(c.feed(b"def")[0]), b"abcdef")
        self.assertFalse(r.at_boundary)


if __name__ == "__main__":
    unittest.main()
