"""HTTP/2 frame reading (RFC 9113) and HPACK header decoding (RFC 7541) for parse_tls.

The HPACK decoder can start on a connection whose beginning was not seen ("tolerant" mode):
it then knows only the dynamic-table entries inserted by the blocks it has decoded itself.
Those entries sit at known positions whatever happened before (the table always holds the
most recent insertions, newest first), so a reference to one of them is certain; a reference
past them yields an unknown field (None) instead of a guess."""

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, \
    CONTINUATION = range(10)
PREFACE_TYPE = -1            # pseudo frame type FrameReader uses for the client connection preface
TYPE_NAMES = {DATA: "DATA", HEADERS: "HEADERS", PRIORITY: "PRIORITY", RST_STREAM: "RST_STREAM",
              SETTINGS: "SETTINGS", PUSH_PROMISE: "PUSH_PROMISE", PING: "PING", GOAWAY: "GOAWAY",
              WINDOW_UPDATE: "WINDOW_UPDATE", CONTINUATION: "CONTINUATION", PREFACE_TYPE: "PREFACE"}
EXTENSION_TYPES = (0x0a, 0x0c, 0x10)     # ALTSVC, ORIGIN, PRIORITY_UPDATE: carried, never decoded

END_STREAM = 0x1
ACK = 0x1
END_HEADERS = 0x4
PADDED = 0x8
PRIORITY_FLAG = 0x20

DEFAULT_MAX_FRAME_SIZE = 16384
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_MAX_FRAME_SIZE = 0x5

# flags a sender may set per type (RFC 9113 section 4.1: undefined flags MUST be left unset)
_ALLOWED_FLAGS = {DATA: END_STREAM | PADDED, HEADERS: END_STREAM | END_HEADERS | PADDED | PRIORITY_FLAG,
                  PRIORITY: 0, RST_STREAM: 0, SETTINGS: ACK, PUSH_PROMISE: END_HEADERS | PADDED,
                  PING: ACK, GOAWAY: 0, WINDOW_UPDATE: 0, CONTINUATION: END_HEADERS}
_STREAM_TYPES = (DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION)
_CONNECTION_TYPES = (SETTINGS, PING, GOAWAY)
_FIXED_LENGTH = {PRIORITY: 5, RST_STREAM: 4, PING: 8, WINDOW_UPDATE: 4}


class FrameError(ValueError):
    """Bytes that cannot be the HTTP/2 frame expected at this position."""


class HpackError(ValueError):
    """A header block that is malformed or contradicts the decoder's table."""


class Frame:
    """One complete frame. parts: [(tag, nbytes), ...], which input chunks its bytes came from."""
    __slots__ = ("type", "flags", "stream_id", "payload", "parts")

    def __init__(self, ftype, flags, stream_id, payload, parts):
        self.type, self.flags, self.stream_id, self.payload, self.parts = ftype, flags, stream_id, payload, parts

    @property
    def size(self):
        return sum(n for _, n in self.parts)

    def __repr__(self):
        return (f"Frame({TYPE_NAMES.get(self.type, self.type)}, flags={self.flags:#x}, "
                f"sid={self.stream_id}, len={len(self.payload)})")


def parse_header(b: bytes):
    """The 9-byte frame header: (length, type, flags, stream_id, reserved_bit)."""
    if len(b) < 9:
        raise FrameError("short frame header")
    return (int.from_bytes(b[0:3], "big"), b[3], b[4],
            int.from_bytes(b[5:9], "big") & 0x7FFFFFFF, b[5] >> 7)


def check_header(length, ftype, flags, sid, reserved, max_size=DEFAULT_MAX_FRAME_SIZE):
    """Raise FrameError unless a compliant sender could have written this frame header."""
    if reserved:
        raise FrameError("reserved bit set")
    if length > max_size:
        raise FrameError("frame larger than the maximum frame size")
    if ftype in EXTENSION_TYPES:
        return
    if ftype not in _ALLOWED_FLAGS:
        raise FrameError("unknown frame type")
    if flags & ~_ALLOWED_FLAGS[ftype]:
        raise FrameError("undefined flags set")
    if ftype in _STREAM_TYPES and sid == 0:
        raise FrameError("stream frame on stream 0")
    if ftype in _CONNECTION_TYPES and sid != 0:
        raise FrameError("connection frame on a stream")
    if ftype in _FIXED_LENGTH and length != _FIXED_LENGTH[ftype]:
        raise FrameError("wrong frame length")
    if ftype == SETTINGS and (length % 6 or (flags & ACK and length)):
        raise FrameError("wrong SETTINGS length")
    if ftype == GOAWAY and length < 8:
        raise FrameError("short GOAWAY")
    if ftype == PUSH_PROMISE and length < 4:
        raise FrameError("short PUSH_PROMISE")


def fragment(frame: Frame) -> bytes:
    """DATA: the data; HEADERS / PUSH_PROMISE / CONTINUATION: the header block fragment.
    Padding, priority fields and the promised stream id are removed."""
    p = frame.payload
    if frame.type not in (DATA, HEADERS, PUSH_PROMISE):
        return p
    start, end = 0, len(p)
    if frame.flags & PADDED:
        if not p:
            raise FrameError("padded frame without pad length")
        start, end = 1, len(p) - p[0]
    if frame.type == HEADERS and frame.flags & PRIORITY_FLAG:
        start += 5
    if frame.type == PUSH_PROMISE:
        start += 4
    if end < start:
        raise FrameError("padding longer than the frame")
    return p[start:end]


def settings(frame: Frame) -> list:
    """[(identifier, value), ...] of a SETTINGS frame."""
    p = frame.payload
    return [(int.from_bytes(p[i:i + 2], "big"), int.from_bytes(p[i + 2:i + 6], "big"))
            for i in range(0, len(p) - 5, 6)]


class FrameReader:
    """Splits one direction of one HTTP/2 connection (or of one writer thread) into frames.

    feed(data, tag) returns the frames completed by data. A client-side reader
    (allow_preface) also accepts the connection preface wherever a frame may start and returns
    it as a Frame of type PREFACE_TYPE. Invalid bytes raise FrameError; the reader is then
    unusable. With strict_streams the reader also rejects frame sequences no endpoint may send
    on one connection (data or headers after END_STREAM, headers without END_STREAM after data,
    CONTINUATION out of place); the stream state is reset at a preface."""

    def __init__(self, allow_preface=False, max_size=DEFAULT_MAX_FRAME_SIZE, strict_streams=False):
        self.allow_preface = allow_preface
        self.max_size = max_size
        self.strict = strict_streams
        self.buf = b""
        self.parts = []          # [(tag, n)] for the bytes in buf
        self.need = None         # total length of the frame in buf once its header is known
        self.continuation = None  # stream id whose header block awaits CONTINUATION
        self.ended = set()       # strict: streams that saw END_STREAM
        self.had_data = set()    # strict: streams that saw DATA

    @property
    def at_boundary(self):
        return not self.buf

    def clone(self):
        c = FrameReader(self.allow_preface, self.max_size, self.strict)
        c.buf, c.parts, c.need, c.continuation = self.buf, list(self.parts), self.need, self.continuation
        c.ended, c.had_data = set(self.ended), set(self.had_data)
        return c

    def state_key(self):
        """Equal for two readers that will treat any further input the same way."""
        return (self.buf, self.need, self.continuation, frozenset(self.ended), frozenset(self.had_data))

    def feed(self, data: bytes, tag=None) -> list:
        """On FrameError the exception carries .frames (completed before the error),
        .bad_parts (the parts of the offending bytes) and .unread (bytes of data not read)."""
        frames = []
        self._pos = 0
        try:
            self._feed(data, tag, frames)
        except FrameError as e:
            e.frames, e.unread = frames, len(data) - self._pos
            if not hasattr(e, "bad_parts"):
                e.bad_parts = list(self.parts)
            raise
        return frames

    def _take(self, data, want, tag):
        take = min(want - len(self.buf), len(data) - self._pos)
        self._add(data[self._pos:self._pos + take], tag)
        self._pos += take
        return len(self.buf) == want

    def _feed(self, data, tag, frames):
        while self._pos < len(data):
            if self.need is None:
                # the preface cannot be a frame header (its first bytes give a length > 2^22)
                head = (self.buf + data[self._pos:self._pos + 24])[:24]
                want = 24 if self.allow_preface and PREFACE.startswith(head) else 9
                if len(self.buf) > want:
                    raise FrameError("broken preface")
                if not self._take(data, want, tag):
                    return
                if want == 24:
                    frames.append(self._emit(PREFACE_TYPE, 0, 0, b""))
                    if self.strict:
                        self.ended.clear()
                        self.had_data.clear()
                    continue
                length, ftype, flags, sid, reserved = parse_header(self.buf)
                check_header(length, ftype, flags, sid, reserved, self.max_size)
                self.need = 9 + length
            if self._take(data, self.need, tag):
                length, ftype, flags, sid, _ = parse_header(self.buf)
                frame = self._emit(ftype, flags, sid, self.buf[9:])
                try:
                    self._check_sequence(frame)
                except FrameError as e:
                    e.bad_parts = frame.parts
                    raise
                frames.append(frame)

    def _add(self, chunk, tag):
        if not chunk:
            return
        self.buf += chunk
        if self.parts and self.parts[-1][0] == tag:
            self.parts[-1] = (tag, self.parts[-1][1] + len(chunk))
        else:
            self.parts.append((tag, len(chunk)))

    def _emit(self, ftype, flags, sid, payload):
        frame = Frame(ftype, flags, sid, payload, self.parts)
        self.buf, self.parts, self.need = b"", [], None
        return frame

    def _check_sequence(self, f):
        if self.continuation is not None:
            if f.type != CONTINUATION or f.stream_id != self.continuation:
                raise FrameError("header block interrupted")
        elif f.type == CONTINUATION:
            raise FrameError("CONTINUATION without a header block")
        if f.type in (HEADERS, PUSH_PROMISE, CONTINUATION):
            self.continuation = None if f.flags & END_HEADERS else f.stream_id
        if f.type in (DATA, HEADERS, PUSH_PROMISE):
            fragment(f)          # padding must fit
        if not self.strict or f.type not in (DATA, HEADERS):
            return
        sid = f.stream_id
        if sid in self.ended:
            raise FrameError("frame after END_STREAM")
        if f.type == HEADERS and sid in self.had_data and not f.flags & END_STREAM:
            raise FrameError("headers after data without END_STREAM")
        if f.type == DATA:
            self.had_data.add(sid)
        if f.flags & END_STREAM:
            self.ended.add(sid)


# ---------------------------------------------------------------------------- HPACK

STATIC_TABLE = (
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
)
_STATIC_BYTES = tuple((n.encode(), v.encode()) for n, v in STATIC_TABLE)

# Code lengths of symbols 0..256 (256 = EOS), RFC 7541 appendix B. The code is canonical: codes
# of one length are consecutive in symbol order, so the lengths determine every code.
HUFFMAN_LENGTHS = (
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
)
EOS = 256


def _canonical_codes(lengths):
    codes = [0] * len(lengths)
    code, prev = 0, 0
    for length, sym in sorted((l, s) for s, l in enumerate(lengths)):
        code <<= length - prev
        codes[sym], prev = code, length
        code += 1
    return codes


HUFFMAN_CODES = tuple(_canonical_codes(HUFFMAN_LENGTHS))
_HUFFMAN_DECODE = {(HUFFMAN_LENGTHS[s], HUFFMAN_CODES[s]): s for s in range(257)}


def huffman_decode(data: bytes) -> bytes:
    """Decode a Huffman-coded string. Padding must be at most 7 bits, all ones; EOS is an error."""
    out = bytearray()
    code = length = 0
    for byte in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((byte >> shift) & 1)
            length += 1
            sym = _HUFFMAN_DECODE.get((length, code))
            if sym is not None:
                if sym == EOS:
                    raise HpackError("EOS in a Huffman string")
                out.append(sym)
                code = length = 0
            elif length >= 30:
                raise HpackError("invalid Huffman code")
    if length > 7 or code != (1 << length) - 1:
        raise HpackError("invalid Huffman padding")
    return bytes(out)


def decode_integer(data: bytes, pos: int, prefix_bits: int):
    """RFC 7541 section 5.1. Returns (value, next position)."""
    if pos >= len(data):
        raise HpackError("integer past the end of the block")
    limit = (1 << prefix_bits) - 1
    value = data[pos] & limit
    pos += 1
    if value < limit:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise HpackError("integer past the end of the block")
        b = data[pos]
        pos += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, pos
        if shift > 28:
            raise HpackError("integer too large")


def decode_string(data: bytes, pos: int):
    """RFC 7541 section 5.2. Returns (bytes, next position)."""
    if pos >= len(data):
        raise HpackError("string past the end of the block")
    huffman = data[pos] & 0x80
    length, pos = decode_integer(data, pos, 7)
    if pos + length > len(data):
        raise HpackError("string past the end of the block")
    raw = data[pos:pos + length]
    return (huffman_decode(raw) if huffman else raw), pos + length


def text(b: bytes) -> str:
    """Header bytes as str: UTF-8 when valid, else Latin-1 (both keep every byte)."""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("latin-1")


class Decoder:
    """HPACK decoder for one direction of one connection.

    start_known: the decoder saw the connection from its start (empty dynamic table). Then a
    reference past the table is an error. Otherwise ("tolerant") such a reference, and a
    literal whose name is such a reference, gives None for what cannot be known.
    max_size: the initial maximum table size (SETTINGS_HEADER_TABLE_SIZE, default 4096);
    size_limit: the largest size a dynamic table size update may set (None: no limit)."""

    def __init__(self, max_size=4096, start_known=True, size_limit=None):
        self.start_known = start_known
        self.max_size = max_size
        self.size_limit = size_limit
        self.entries = []        # newest first: (name, value, size) as bytes; name None when unknown
        self.size = 0
        self.unknown = 0         # fields left unknown by the last decode()

    def _lookup(self, index):
        if index == 0:
            raise HpackError("index 0")
        if index <= len(_STATIC_BYTES):
            return _STATIC_BYTES[index - 1]
        i = index - len(_STATIC_BYTES) - 1
        if i < len(self.entries):
            return self.entries[i][:2]
        if self.start_known:
            raise HpackError("index past the dynamic table")
        return None, None

    def _insert(self, name, value):
        # an entry whose name is unknown counts as small as it can be, so that no known entry
        # is dropped while the encoder may still reference it
        size = 32 + len(value) + (len(name) if name is not None else 0)
        self.entries.insert(0, (name, value, size))
        self.size += size
        self._evict()

    def _evict(self):
        while self.size > self.max_size and self.entries:
            self.size -= self.entries.pop()[2]

    def decode(self, block: bytes) -> list:
        """The header list of one complete header block, as [(name, value), ...] in order.
        In tolerant mode a field that cannot be known is (None, None) or (None, value)."""
        headers = []
        pos = 0
        self.unknown = 0
        fields_seen = False
        while pos < len(block):
            b = block[pos]
            if b & 0x80:                                   # indexed field
                index, pos = decode_integer(block, pos, 7)
                name, value = self._lookup(index)
                headers.append((name, value))
                fields_seen = True
            elif b & 0xE0 == 0x20:                         # dynamic table size update
                if fields_seen:
                    raise HpackError("table size update after a field")
                size, pos = decode_integer(block, pos, 5)
                if self.size_limit is not None and size > self.size_limit:
                    raise HpackError("table size update above the limit")
                self.max_size = size
                self._evict()
            else:                                          # literal field
                indexing = b & 0xC0 == 0x40
                index, pos = decode_integer(block, pos, 6 if indexing else 4)
                if index:
                    name = self._lookup(index)[0]
                else:
                    name, pos = decode_string(block, pos)
                value, pos = decode_string(block, pos)
                if indexing:
                    self._insert(name, value)
                headers.append((name, value))
                fields_seen = True
        self.unknown = sum(1 for n, v in headers if n is None or v is None)
        return [(None if n is None else text(n), None if v is None else text(v)) for n, v in headers]
