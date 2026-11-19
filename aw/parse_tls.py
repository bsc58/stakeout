"""Exchanges from an eCapture hook-mode events file (tls_events.log). The file format, the
exchange record and the reason codes are in docs/CONTRACT_DECRYPT.md.

How the records become exchanges:

* Records are read by byte count and grouped by thread and direction. When the file has no
  backward time step (eCapture ran with --perf-reorder) the file order is the order of the
  calls. Otherwise records of one thread with the same millisecond may be swapped; their order
  is rebuilt from HTTP/2 frame structure where only one order is possible, and content whose
  order stays open is left out (record_order_unknown).
* HTTP/1.1 is parsed per thread: a blocking client writes a request and reads its response on
  the same thread, so responses pair with that thread's requests in order (keep-alive and
  pipelining included). A new request written while a response is still being read ends that
  response as incomplete (its remaining bytes were never seen). Requests still waiting for a
  response when the thread reads 0 bytes (connection closed) get none: a later response on the
  thread comes from another connection.
* HTTP/2 reading side: the frames a thread reads until a read of 0 bytes (connection closed)
  are one reader connection (a "segment"). A server SETTINGS frame after other frames starts a
  new segment whose start is not known (a new connection on a reused thread whose close was not
  recorded, or new settings on the same one). Only a thread named like OkHttp's reader ("OkHttp
  <host>", kept tail) reads one connection; an OkHttp reader that shows only its close is a
  connection too. Any other reading thread may read several connections: nothing it shows rules
  it out, and once one of its reads ends inside a frame, that frame and everything the thread
  reads afterwards is left out (connection_unknown).
* A connection opened in the capture: an OkHttp reader segment whose first frame is the server's
  SETTINGS, paired with a preface in the file. Nothing names the preface's connection, so a
  preface and such a reader are paired only when each is the last one left that fits the other,
  in both directions (as if every such reader's preface were in the file, and as if every
  preface's reader showed in the file). A preface fits a reader read after it that its first
  request can be on (shown streams, GOAWAY, close) and that is named after that request's host
  (OkHttp names the reader after the call that opened the connection). That first request (the
  next stream frame the preface's thread writes, stream 3, or 1) is the connection's first.
* A request (HEADERS written) is attached to a reader connection only when the data leaves no
  other choice, repeated until nothing changes (each attachment tells when that connection
  opened that stream):
  1. a connection opened in the capture: the request is the only one with that stream id the
     connection can have carried (needs every request in the file, below);
  2. any other connection: it is the only reader connection not ruled out for the request, it
     shows a response with the request's stream id after the request, and no other request can
     take that response. Such a connection cannot be told apart from one that shows nothing in
     the capture: the exchange gets connection_start_not_captured.
  A reader connection is ruled out for a request (stream s, written at t) when it closed or read
  a GOAWAY in a millisecond before t; its GOAWAY's last stream id is below s; its preface was
  written after t; it shows a frame of a stream >= s before t; or a request attached to it has
  stream s, a higher one written before t, or a lower one written after t. Two more tests need
  every request in the file (no written byte left unread, no rebuilt order that changes a frame's
  type or stream id, no connection opened in the capture showing a stream that no request in the
  file can have opened): OkHttp's stream ids grow by 2, so from a point on which the
  connection's history is in the file (its preface, or a request attached to it) every stream
  between that point and s needs a request written in between; and on a connection opened in
  the capture whose request-side table is known, the next stream's header block must decode
  against that table into a well-formed request (RFC 9113 section 8.3).
  Anything else stays unattached: response None, response_not_matched, header block decoded on
  its own. A request's :authority is not compared with the reader's name: OkHttp coalesces
  connections, so one connection can carry requests for several hosts.
* Header blocks of a connection's attached requests are decoded in stream-id order (the order
  HPACK saw them); the table carries over only between consecutive stream ids (+2) of attached
  requests on an OkHttp reader's connection, from its first request when it was opened in the
  capture; otherwise nothing from it is assumed. Fields that cannot be known are left out and the
  exchange is marked hpack_state_unknown.
* A body whose Content-Encoding field was not restored (its header block has fields that could
  not be decoded) is described with make_body(..., encoding_known=False).

Reason codes added to the contract's list. Exchange "partial": record_order_unknown,
connection_start_not_captured. Undecoded records: h2_control (preface and control frames),
connection_closed (a read of 0 bytes), empty (a write of 0 bytes), response_without_request,
stream_start_not_captured, server_push, not_http, incomplete_at_end, stream_conflict,
record_order_unknown, connection_unknown."""
import collections
import itertools
import re
import urllib.parse
from datetime import datetime, timedelta

from aw import h2
from aw.exchange import header, make_body

_RECORD = re.compile(rb"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\] PID:(\d+) TID:(\d+) Comm:(.*?) "
                     rb"FD:(-?\d+) (READ|WRITE) \((\d+) bytes\):\n")
_REQUEST_LINE = re.compile(rb"[A-Z][A-Z_-]{0,19} \S+ HTTP/1\.[01]\r\n")
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] \d{3}[ \r]")
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_MAX_HEAD = 256 * 1024          # an HTTP/1.1 header section larger than this is not parsed
_MAX_TIE_GROUP = 6              # same-millisecond records whose orders are tried exhaustively
_CONTENT_TYPES = (h2.DATA, h2.HEADERS, h2.CONTINUATION, h2.PUSH_PROMISE, h2.PREFACE_TYPE)


class _Rec:
    __slots__ = ("idx", "utc", "pid", "tid", "comm", "write", "data")

    def __init__(self, idx, utc, pid, tid, comm, write, data):
        self.idx, self.utc, self.pid, self.tid, self.comm, self.write, self.data = \
            idx, utc, pid, tid, comm, write, data


def _read_records(path):
    with open(path, "rb") as f:
        data = f.read()
    recs, pos, cut = [], 0, False
    while pos < len(data):
        m = _RECORD.match(data, pos)
        if not m or not _valid_time(m.group(1)):
            # not a record header here (or one with an impossible time): skip to the next one
            m = next((x for x in _RECORD.finditer(data, pos + 1) if _valid_time(x.group(1))), None)
            if not m:
                cut = bool(data[pos:].strip())      # a header line cut off at the end
                break
        n = int(m.group(7))
        start = m.end()
        payload = data[start:start + n]
        if len(payload) < n:
            cut = True
        recs.append(_Rec(len(recs), m.group(1).decode(), int(m.group(2)), int(m.group(3)),
                         m.group(4).decode("utf-8", "backslashreplace"), m.group(6) == b"WRITE", payload))
        pos = start + len(payload)
        # eCapture adds "\n" after a payload that does not end with one (not after an empty one)
        if payload and not payload.endswith(b"\n") and data[pos:pos + 1] == b"\n":
            pos += 1
    return recs, cut


def _valid_time(b):
    try:
        datetime.strptime(b.decode(), "%Y-%m-%d %H:%M:%S.%f")
        return True
    except ValueError:
        return False


def _local(utc, offset):
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", (offset or "+0000").strip())
    delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3))) if m else timedelta(0)
    if m and m.group(1) == "-":
        delta = -delta
    t = datetime.strptime(utc, "%Y-%m-%d %H:%M:%S.%f") + delta
    return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def _is_h1_start(rec):
    return bool((_REQUEST_LINE if rec.write else _STATUS_LINE).match(rec.data))


# ---------------------------------------------------------------- record order

def _max_frame_sizes(recs):
    """SETTINGS_MAX_FRAME_SIZE values advertised anywhere: what each side may send at most."""
    sizes = {True: h2.DEFAULT_MAX_FRAME_SIZE, False: h2.DEFAULT_MAX_FRAME_SIZE}
    streams = collections.defaultdict(list)
    for r in recs:
        streams[(r.pid, r.tid, r.write)].append(r)
    for (_, _, write), lst in streams.items():
        reader = h2.FrameReader(allow_preface=write, max_size=(1 << 24) - 1)
        try:
            for r in lst:
                for f in reader.feed(r.data):
                    if f.type == h2.SETTINGS and not f.flags & h2.ACK:
                        for ident, value in h2.settings(f):
                            if ident == h2.SETTINGS_MAX_FRAME_SIZE and value < (1 << 24):
                                # what one side advertises bounds what the other side sends
                                sizes[not write] = max(sizes[not write], value)
        except h2.FrameError:
            continue
    return sizes


def _resolve_ties(recs, write, max_size):
    """recs: one thread's records of one direction in (time, file) order, from a file whose
    order is not trusted. Returns (order, uncertain record ids, ids of those among them whose
    frame types or stream ids differ between the possible orders, first record id whose
    position is lost or None)."""
    reader = h2.FrameReader(allow_preface=write, max_size=max_size)
    order, uncertain, shaky = [], set(), set()
    groups = [list(g) for _, g in itertools.groupby(recs, key=lambda r: r.utc)]
    for gi, group in enumerate(groups):
        if len(group) == 1:
            try:
                reader, _ = _feed_all(reader, group, write)
            except h2.FrameError:
                # a record alone in its millisecond is in place: the bytes themselves are wrong
                return order + [r for g in groups[gi:] for r in g], uncertain, shaky, None
            order += group
            continue
        if len(group) > _MAX_TIE_GROUP:
            return order + [r for g in groups[gi:] for r in g], uncertain, shaky, group[0].idx
        base = reader.clone()
        base.strict, base.ended, base.had_data = True, set(), set()
        outcomes = []
        for perm in itertools.permutations(group):
            try:
                r, proj = _feed_all(base.clone(), perm, write)
            except h2.FrameError:
                continue
            outcomes.append((perm, proj, r))
        if not outcomes or len({o[2].state_key() for o in outcomes}) > 1:
            return order + [r for g in groups[gi:] for r in g], uncertain, shaky, group[0].idx
        perm, proj, r = outcomes[0]
        if len({o[1] for o in outcomes}) > 1:
            uncertain.update(rec.idx for rec in group)
            if len({tuple(p[:3] for p in o[1]) for o in outcomes}) > 1:
                shaky.update(rec.idx for rec in group)
        r.strict = False
        reader = r
        order += perm
    return order, uncertain, shaky, None


def _feed_all(reader, recs, write):
    """Feed records in this order. An empty read (the connection closed) starts a new reader,
    as in the parse itself. Returns (reader, content frames and closes, in order)."""
    proj = []
    for rec in recs:
        if not rec.data:
            if not write:
                proj.append(("closed", reader.state_key()))
                reader = h2.FrameReader(allow_preface=write, max_size=reader.max_size,
                                        strict_streams=reader.strict)
            continue
        for f in reader.feed(rec.data):
            if f.type in _CONTENT_TYPES:
                proj.append((f.type, f.flags, f.stream_id, f.payload))
    return reader, tuple(proj)


def _order_threads(recs, trusted, max_sizes):
    """{(pid, tid): records in processing order}, uncertain record ids, lost record ids, ids of
    uncertain records whose frame structure is open too."""
    threads = collections.defaultdict(list)
    for r in recs:
        threads[(r.pid, r.tid)].append(r)
    if trusted:
        return threads, set(), set(), set()
    uncertain, lost, shaky = set(), set(), set()
    ordered = {}
    for key, lst in threads.items():
        lst = sorted(lst, key=lambda r: (r.utc, r.idx))
        if any(_is_h1_start(r) for r in lst):
            # HTTP/1.1 message boundaries do not show in the bytes: same-millisecond records
            # of such a thread are not used, nor what follows them in their direction
            for _, g in itertools.groupby(lst, key=lambda r: r.utc):
                g = list(g)
                if len(g) > 1:
                    lost.update(r.idx for r in g)
            ordered[key] = lst
            continue
        merged = []
        for write in (True, False):
            part = [r for r in lst if r.write == write]
            order, unc, sh, lost_from = _resolve_ties(part, write, max_sizes[write])
            uncertain |= unc
            shaky |= sh
            if lost_from is not None:
                pos = [r.idx for r in order].index(lost_from)
                lost.update(r.idx for r in order[pos:])
            merged += [(r.utc, write, k, r) for k, r in enumerate(order)]
        ordered[key] = [r for _, _, _, r in sorted(merged, key=lambda x: (x[0], x[2], x[1]))]
    return ordered, uncertain, lost, shaky


# ---------------------------------------------------------------- HTTP/1.1

class _H1Msg:
    """One HTTP/1.1 message being read from a byte stream."""

    def __init__(self, is_request, rec, req_method=None):
        self.is_request = is_request
        self.rec = rec
        self.req_method = req_method
        self.buf = bytearray()
        self.parts = []
        self.head = None            # (start line fields, headers)
        self.body_start = None
        self.framing = None         # "none" | "length" | "chunked" | "close"
        self.length = 0
        self.body = bytearray()
        self.trailers = []
        self.cursor = 0
        self.chunk_state, self.chunk_left = "size", 0
        self.complete = False
        self.registered = False     # a request waiting for its response

    def feed(self, chunk, rec):
        """Returns how many bytes of chunk belong to this message; sets complete."""
        before = len(self.buf)
        self.buf += chunk
        end = self._advance()
        used = len(chunk) if end is None else end - before
        if end is not None:
            del self.buf[end:]
            self.complete = True
        if used:
            self.parts.append((rec.idx, used))
        return used

    def finish_at_close(self):
        if self.framing == "close":
            self.body = bytearray(self.buf[self.body_start:])
            self.complete = True

    def _advance(self):
        if self.head is None:
            i = self.buf.find(b"\r\n\r\n")
            if i < 0:
                if len(self.buf) > _MAX_HEAD:
                    raise ValueError("header section too large")
                return None
            self._parse_head(bytes(self.buf[:i]))
            self.body_start = self.cursor = i + 4
        if self.framing == "none":
            return self.body_start
        if self.framing == "length":
            have = len(self.buf) - self.body_start
            self.body = bytearray(self.buf[self.body_start:self.body_start + min(have, self.length)])
            return self.body_start + self.length if have >= self.length else None
        if self.framing == "close":
            self.body = bytearray(self.buf[self.body_start:])
            return None
        return self._advance_chunked()

    def _advance_chunked(self):
        buf = self.buf
        while True:
            if self.chunk_state in ("size", "trailer"):
                i = buf.find(b"\r\n", self.cursor)
                if i < 0:
                    if len(buf) - self.cursor > _MAX_HEAD:
                        raise ValueError("chunk line too long")
                    return None
                line = bytes(buf[self.cursor:i])
                self.cursor = i + 2
                if self.chunk_state == "trailer":
                    if not line:
                        return self.cursor
                    self.trailers.append(_header_line(line))
                    continue
                size = line.split(b";", 1)[0].strip()
                if not re.fullmatch(rb"[0-9A-Fa-f]{1,15}", size):
                    raise ValueError("bad chunk size")
                self.chunk_left = int(size, 16)
                self.chunk_state = "data" if self.chunk_left else "trailer"
            elif self.chunk_state == "data":
                take = min(self.chunk_left, len(buf) - self.cursor)
                self.body += buf[self.cursor:self.cursor + take]
                self.cursor += take
                self.chunk_left -= take
                if self.chunk_left:
                    return None
                self.chunk_state = "crlf"
            else:
                if len(buf) - self.cursor < 2:
                    return None
                if buf[self.cursor:self.cursor + 2] != b"\r\n":
                    raise ValueError("chunk not followed by CRLF")
                self.cursor += 2
                self.chunk_state = "size"

    def _parse_head(self, head):
        lines = head.split(b"\r\n")
        if self.is_request:
            m = re.fullmatch(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+) (\S+) (HTTP/1\.[01])", lines[0])
        else:
            m = re.fullmatch(rb"(HTTP/1\.[01]) (\d{3})(?: (.*))?", lines[0])
        if not m:
            raise ValueError("bad start line")
        headers = [_header_line(l) for l in lines[1:]]
        self.head = (m.groups(), headers)
        te = header(headers, "transfer-encoding")
        cl = [v for k, v in headers if k.lower() == "content-length"]
        if cl and (len(set(cl)) > 1 or not re.fullmatch(r"\d{1,15}", cl[0].strip())):
            raise ValueError("bad Content-Length")
        if self.is_request:
            if te:
                if te.lower().replace(" ", "").split(",")[-1] != "chunked":
                    raise ValueError("request body without a length")
                self.framing = "chunked"
            else:
                self.framing, self.length = ("length", int(cl[0])) if cl else ("none", 0)
            return
        status = int(m.group(2))
        if (self.req_method or "").upper() == "HEAD" or 100 <= status < 200 or status in (204, 304):
            self.framing = "none"
        elif te:
            self.framing = "chunked" if te.lower().replace(" ", "").split(",")[-1] == "chunked" else "close"
        elif cl:
            self.framing, self.length = "length", int(cl[0])
        else:
            self.framing = "close"


def _header_line(line):
    name, sep, value = line.partition(b":")
    if not sep or not _TOKEN.fullmatch(name):
        raise ValueError("bad header line")
    return [h2.text(name), h2.text(value.strip(b" \t"))]


# ---------------------------------------------------------------- HTTP/2 pieces

class _Block:
    """A header block (HEADERS + CONTINUATION) or DATA collected for one stream."""

    def __init__(self, rec):
        self.rec = rec
        self.parts = []
        self.data = bytearray()
        self.uncertain = False


class _Req:
    def __init__(self, sid, rec, fresh):
        self.sid, self.rec = sid, rec
        self.fresh = fresh          # the preface its thread wrote just before: first request on it
        self.head = None            # _Block
        self.trailers = []          # [_Block]
        self.body = _Block(rec)
        self.ended = False
        self.headers = None         # decoded [(name, value)] or None: not decodable
        self.unknown = 0
        self.seg = None             # the reader connection it is attached to
        self.resp = None            # its response on that connection


class _Resp:
    def __init__(self, sid, rec):
        self.sid, self.rec = sid, rec
        self.blocks = []            # [(_Block, decoded headers or None, unknown count)]
        self.body = _Block(rec)
        self.ended = False
        self.reset = False
        self.uncertain = False
        self.matched = False


class _Seg:
    """The read side of one HTTP/2 connection: one reading thread until the connection closed
    (one connection only on an OkHttp reader thread, see stateful)."""

    def __init__(self, rec, split=False):
        self.rec = rec
        self.frames = []            # [(frame, first record, uncertain)]
        self.resps = {}
        self.known_start = False if split else None   # first frame is the server's SETTINGS
        self.preface = None         # the paired preface {"rec", "seg", "q0"}: start in the capture
        self.stateful = True        # one connection (OkHttp reader, no stream conflict)
        self.closed = None          # record of the read of 0 bytes that ended it
        self.goaways = []           # [(record, last stream id)]
        self.seen = {}              # odd stream id -> first record of the server's first frame on it
        self.attached = []          # requests attached to it
        self.table = None           # (len(attached), request-side table state) cache, see _table_after

    @property
    def start(self):
        return self.preface is not None


class _Parser:
    def __init__(self, recs, uncertain, lost, shaky, max_sizes, utc_offset, trusted):
        self.recs = recs
        self.uncertain = uncertain
        self.lost = lost
        self.shaky = shaky
        self.max_sizes = max_sizes
        self.offset = utc_offset
        self.trusted = trusted                                   # file order is the order of the calls
        self.use = collections.defaultdict(collections.Counter)   # record id -> {reason: bytes}
        self.exchanges = []
        self.write_frames = collections.defaultdict(list)        # (pid, tid) -> [(frame, rec, uncertain)]
        self.segments = []
        self.complete = False       # every request written is in the file (set in http2)
        self.by_sid = {}            # stream id -> [requests]

    def account(self, parts, reason):
        for rid, n in parts:
            self.use[rid][reason] += n

    # ---------------------------------------------------------- per thread

    def thread(self, recs):
        dirs = {True: self._new_dir(True), False: self._new_dir(False)}
        items = []                          # HTTP/1.1 requests of this thread, in order
        pending = collections.deque()       # those still waiting for their response
        seg = None
        shared_split = False                # see connection_unknown below
        for rec in recs:
            d = dirs[rec.write]
            if not rec.data:
                # SSL_read returning 0: the peer closed the connection; the thread may read
                # another connection afterwards
                self.use[rec.idx]["empty" if rec.write else "connection_closed"] += 0
                if not rec.write:
                    self._end_response(d, pending, closed=True)
                    # requests still waiting were sent on the closed connection: a response
                    # read later on this thread comes from another connection
                    pending.clear()
                    self.account(d["frames"].parts, "incomplete_at_end")
                    dirs[False] = self._new_dir(False)
                    if shared_split:
                        dirs[False]["dead"] = "connection_unknown"
                    if seg is None and not items and _okhttp_reader_name(rec.comm):
                        # an HTTP/2 connection that showed nothing but its close
                        seg = _Seg(rec)
                        self.segments.append(seg)
                    if seg is not None:
                        seg.closed = rec
                    seg = None
                continue
            if rec.idx in self.lost and d["dead"] is None:
                self._abandon(d, pending, rec.write)
                self.account(d["frames"].parts, "record_order_unknown")
                d["frames"] = self._new_dir(rec.write)["frames"]
                d["dead"] = "record_order_unknown"
            if d["dead"]:
                self.account([(rec.idx, len(rec.data))], d["dead"])
                continue
            if (not rec.write and d["h1"] is None and not d["frames"].at_boundary
                    and not _okhttp_reader_name(rec.comm)):
                # The previous read ended inside a frame, and this thread is not known to read
                # only one connection: this record may belong to another connection, so neither
                # that frame nor anything this thread reads later can be split with certainty.
                self.account(d["frames"].parts + [(rec.idx, len(rec.data))], "connection_unknown")
                d["frames"] = self._new_dir(False)["frames"]
                d["dead"] = "connection_unknown"
                shared_split = True
                continue
            data, pos = rec.data, 0
            while pos < len(data):
                if d["h1"] is not None:
                    pos += self._feed_h1(d, data[pos:], rec, pending, items, dirs)
                    continue
                if d["frames"].at_boundary and (_REQUEST_LINE if rec.write else _STATUS_LINE).match(data, pos):
                    if rec.write:
                        self._end_response(dirs[False], pending, closed=False)
                        d["h1"] = _H1Msg(True, rec)
                    else:
                        method = pending[0]["req"].head[0][0].decode() if pending else None
                        d["h1"] = _H1Msg(False, rec, method)
                    continue
                try:
                    frames = d["frames"].feed(data[pos:], rec.idx)
                except h2.FrameError as e:
                    frames = e.frames
                    self.account(e.bad_parts + [(rec.idx, e.unread)], "not_http")
                    d["frames"] = self._new_dir(rec.write)["frames"]
                    d["dead"] = "not_http"
                pos = len(data)
                for f in frames:
                    first = self.recs[f.parts[0][0]]
                    unc = any(rid in self.uncertain for rid, _ in f.parts)
                    if rec.write:
                        self.write_frames[(rec.pid, rec.tid)].append((f, first, unc))
                    else:
                        if seg is None:
                            seg = _Seg(first)
                            self.segments.append(seg)
                        elif seg.frames and f.type == h2.SETTINGS and not f.flags & h2.ACK:
                            # a new connection on a reused thread whose close was not recorded,
                            # or new settings on the same one: from here on another segment,
                            # whose start is not known
                            seg = _Seg(first, split=True)
                            self.segments.append(seg)
                        seg.frames.append((f, first, unc))
        for write, d in dirs.items():
            if d["h1"] is not None:
                if write:
                    self._finish_request(d)
                else:
                    self._end_response(d, pending, closed=False)
            if not d["frames"].at_boundary:
                self.account(d["frames"].parts, "incomplete_at_end")
        for item in items:
            self._h1_exchange(item)

    def _new_dir(self, write):
        return {"frames": h2.FrameReader(allow_preface=write, max_size=self.max_sizes[write]),
                "h1": None, "dead": None}

    def _feed_h1(self, d, chunk, rec, pending, items, dirs):
        msg = d["h1"]
        try:
            used = msg.feed(chunk, rec)
            error = False
        except ValueError:
            used, error = len(chunk), True
        if msg.is_request and msg.head is not None and not msg.registered:
            # a response may come before the request body is written (100-continue, errors)
            msg.registered = True
            item = {"req": msg, "resp": None, "extra": []}
            items.append(item)
            pending.append(item)
        if error:
            self.account([(rec.idx, len(chunk))], "not_http")
            d["dead"] = "not_http"
            if msg.is_request:
                self._finish_request(d)
            else:
                self._end_response(d, pending, closed=False)
            return used
        if msg.complete:
            d["h1"] = None
            if not msg.is_request:
                self._finish_response(msg, pending, dirs)
        return used

    def _finish_request(self, d):
        """The request being written ends unfinished (end of capture, or its stream is lost)."""
        msg, d["h1"] = d["h1"], None
        if msg.head is None:
            self.account(msg.parts, "incomplete_at_end")

    def _end_response(self, d, pending, closed):
        """The response being read ends: at a close of the connection, at a new request on the
        thread, or at the end of the capture."""
        msg = d["h1"]
        if msg is None:
            return
        d["h1"] = None
        if closed:
            msg.finish_at_close()
        if msg.head is None:
            self.account(msg.parts, "incomplete_at_end")
            return
        self._finish_response(msg, pending, None)

    def _abandon(self, d, pending, write):
        if d["h1"] is not None:
            if write:
                self._finish_request(d)
            else:
                self._end_response(d, pending, closed=False)

    def _finish_response(self, msg, pending, dirs):
        status = int(msg.head[0][1])
        if not pending:
            self.account(msg.parts, "response_without_request")
        elif 100 <= status < 200 and status != 101:
            pending[0]["extra"] += msg.parts
            return
        else:
            pending.popleft()["resp"] = msg
        if status == 101 and dirs is not None:
            for d in dirs.values():
                d["dead"] = "not_http"

    def _h1_exchange(self, item):
        req, resp = item["req"], item["resp"]
        (method, target, _), headers = req.head
        method, target = method.decode(), h2.text(target)
        host = header(headers, "host")
        path, query = _split_target(target, method)
        partial = []
        if method == "CONNECT":
            host = target
        ex = self._exchange("http/1.1", req.rec, method, "https", host, path, query,
                            headers + req.trailers, _h1_body(req), req.complete)
        if not req.complete:
            partial.append("request_incomplete")
        parts = req.parts + item["extra"]
        if resp is None:
            partial.append("response_not_matched")
        else:
            _, rheaders = resp.head
            ex["response"] = {"status": int(resp.head[0][1]), "headers": rheaders + resp.trailers,
                              "body": _h1_body(resp), "complete": resp.complete}
            if not resp.complete:
                partial.append("response_incomplete")
            parts += resp.parts
        ex["partial"] = _partial(ex, partial)
        self.account(parts, "exchange")
        self.exchanges.append((req.rec.idx, ex))

    # ---------------------------------------------------------- HTTP/2

    def http2(self):
        # Every request written is in the file when no written byte was left unread (not HTTP,
        # order lost, cut off) and no rebuilt record order changes a frame's type or stream id.
        # The rules that need a connection's whole history depend on it.
        gaps = ("not_http", "record_order_unknown", "incomplete_at_end")
        self.complete = not any(r.write and (r.idx in self.shaky or any(self.use[r.idx][g] for g in gaps))
                                for r in self.recs)
        prefaces, requests = self._write_side()
        self.requests = requests
        for q in requests:
            self.by_sid.setdefault(q.sid, []).append(q)
        for seg in self.segments:
            self._read_side(seg)
        self._pair_prefaces(prefaces)
        self._assign(requests)
        for seg in self.segments:
            for resp in seg.resps.values():
                if not resp.matched:
                    self._account_resp(resp, "response_without_request")
        for q in requests:
            self._h2_exchange(q)

    def _write_side(self):
        prefaces, requests = [], []
        for key, frames in self.write_frames.items():
            open_reqs = {}
            block = None            # (request, _Block) whose header block awaits CONTINUATION
            fresh = None            # preface of this thread not yet followed by a stream frame
            for f, rec, unc in frames:
                if f.type == h2.PREFACE_TYPE:
                    fresh = {"rec": rec, "seg": None, "q0": None}
                    prefaces.append(fresh)
                    self.account(f.parts, "h2_control")
                    continue
                start_fresh = fresh
                if f.stream_id:
                    fresh = None
                if f.type == h2.HEADERS:
                    q = open_reqs.get(f.stream_id)
                    b = _Block(rec)
                    # trailers: END_STREAM after the request's data (RFC 9113 section 8.1)
                    if q is not None and not q.ended and q.body.parts and f.flags & h2.END_STREAM:
                        q.trailers.append(b)
                    else:
                        # OkHttp writes a new connection's preface and its first request (stream 3;
                        # 1 is the lowest a client can use) on the calling thread
                        first = start_fresh if start_fresh is not None and f.stream_id in (1, 3) else None
                        q = _Req(f.stream_id, rec, first)
                        if first is not None:
                            first["q0"] = q
                        q.head = b
                        open_reqs[f.stream_id] = q
                        requests.append(q)
                    self._add_fragment(b, f, unc)
                    if f.flags & h2.END_STREAM:
                        q.ended = True
                    block = None if f.flags & h2.END_HEADERS else b
                elif f.type == h2.CONTINUATION:
                    if block is None:               # continues a PUSH_PROMISE
                        self.account(f.parts, "not_http")
                        continue
                    self._add_fragment(block, f, unc)
                    if f.flags & h2.END_HEADERS:
                        block = None
                elif f.type == h2.DATA:
                    q = open_reqs.get(f.stream_id)
                    if q is None or q.ended:
                        self.account(f.parts, "stream_start_not_captured")
                        continue
                    self._add_fragment(q.body, f, unc)
                    if f.flags & h2.END_STREAM:
                        q.ended = True
                elif f.type == h2.PUSH_PROMISE:
                    self.account(f.parts, "not_http")     # a client never sends PUSH_PROMISE
                    block = None
                else:
                    self.account(f.parts, "h2_control")
        return prefaces, requests

    @staticmethod
    def _add_fragment(b, f, unc):
        b.data += h2.fragment(f)
        b.parts += f.parts
        b.uncertain = b.uncertain or unc

    def _read_side(self, seg):
        # The header table carries over between blocks only when the reading thread is known
        # to read one connection (OkHttp's reader). Any other reading thread may read several
        # connections, so each of its blocks is decoded on its own.
        stateful = _okhttp_reader_name(seg.rec.comm)
        dec = h2.Decoder(start_known=False)
        block, block_sid, pushed = None, None, set()
        for f, rec, unc in seg.frames:
            if seg.known_start is None:
                seg.known_start = f.type == h2.SETTINGS and not f.flags & h2.ACK
            sid = f.stream_id
            # what the connection shows about its streams, for telling connections apart
            # (frames whose record order is open are not used for that)
            if not unc and sid % 2:
                seg.seen.setdefault(sid, rec)
            if not unc and f.type == h2.GOAWAY:
                seg.goaways.append((rec, int.from_bytes(f.payload[:4], "big") & 0x7FFFFFFF))
            if f.type in (h2.HEADERS, h2.DATA) and sid in seg.resps and seg.resps[sid].ended:
                # impossible on one connection: records are missing or the thread reads more
                # than one connection; the table is not used from here on
                self.account(f.parts, "stream_conflict")
                stateful = False
                if f.type == h2.HEADERS and not f.flags & h2.END_HEADERS:
                    block, block_sid = _Block(rec), None
                    block.kind, block.end_stream = None, False
                continue
            if f.type == h2.CONTINUATION and block_sid is None:
                self.account(f.parts, "stream_conflict")
                continue
            if not stateful:
                dec = h2.Decoder(start_known=False)
            if f.type in (h2.HEADERS, h2.PUSH_PROMISE):
                block, block_sid = _Block(rec), sid
                block.kind = f.type
                block.end_stream = bool(f.flags & h2.END_STREAM)
                if f.type == h2.PUSH_PROMISE:
                    pushed.add(int.from_bytes(f.payload[1 if f.flags & h2.PADDED else 0:][:4], "big") & 0x7FFFFFFF)
            if f.type in (h2.HEADERS, h2.PUSH_PROMISE, h2.CONTINUATION):
                self._add_fragment(block, f, unc)
                if not f.flags & h2.END_HEADERS:
                    continue
                if block.uncertain:
                    headers, unknown, dec = None, 0, h2.Decoder(start_known=False)
                else:
                    try:
                        headers, unknown = dec.decode(bytes(block.data)), dec.unknown
                    except h2.HpackError:
                        headers, unknown, dec = None, 0, h2.Decoder(start_known=False)
                if block.kind == h2.PUSH_PROMISE or block_sid in pushed:
                    self.account(block.parts, "server_push")
                    continue
                resp = seg.resps.get(block_sid)
                if resp is None:
                    resp = seg.resps[block_sid] = _Resp(block_sid, block.rec)
                resp.blocks.append((block, headers, unknown))
                resp.uncertain = resp.uncertain or block.uncertain
                if block.end_stream:
                    resp.ended = True
            elif f.type == h2.DATA:
                resp = seg.resps.get(sid)
                if sid in pushed:
                    self.account(f.parts, "server_push")
                elif resp is None:
                    self.account(f.parts, "stream_start_not_captured")
                else:
                    self._add_fragment(resp.body, f, unc)
                    if f.flags & h2.END_STREAM:
                        resp.ended = True
            elif f.type == h2.RST_STREAM and sid in seg.resps and not seg.resps[sid].ended:
                seg.resps[sid].reset = True
                self.account(f.parts, "h2_control")
            else:
                self.account(f.parts, "h2_control")
        seg.stateful = stateful

    # ---------------------------------------------------------- which connection

    def _before(self, a, b):
        """Record a was certainly made before record b: an earlier millisecond, or the same one
        in a file whose order is the order of the calls."""
        return a.utc < b.utc or (self.trusted and a.utc == b.utc and a.idx < b.idx)

    def _pair_prefaces(self, prefaces):
        """A connection opened inside the capture: on an OkHttp reader thread, the first frame of
        the connection is the server's SETTINGS, and its preface is in the file. Nothing names
        the preface, so a reader and a preface are paired only when each is the last one left
        that fits the other, both ways: as if every such reader's preface were in the file, and
        as if every preface's reader showed in the file. The first request after the preface is
        then that connection's first stream."""
        for p in prefaces:
            q0 = p["q0"]
            if q0 is None:
                continue
            if q0.sid == 3 and any(not self._before(r.rec, p["rec"]) and not self._before(q0.rec, r.rec)
                                   for r in self.by_sid.get(1, ())):
                p["q0"] = q0.fresh = None       # stream 1 may have come first on that connection
                continue
            self._decode_request(q0, h2.Decoder(start_known=False))
        readers = [s for s in self.segments if s.known_start and s.stateful]

        def fits(p, s):
            if self._before(s.rec, p["rec"]):
                return False
            q0 = p["q0"]
            if q0 is None:
                return True
            # OkHttp opens a connection for the call that writes its preface, and names the
            # reader thread after that call's host
            host = _authority(q0.headers)
            return not self._excluded(s, q0) and not (host and _okhttp_tail(host) != s.rec.comm)

        by_reader = _forced(readers, prefaces, lambda s, p: fits(p, s))
        by_preface = _forced(prefaces, readers, fits)
        for s in readers:
            p = by_reader.get(id(s))
            if p is not None and by_preface.get(id(p)) is s:
                s.preface, p["seg"] = p, s
                if p["q0"] is not None:
                    self._attach(p["q0"], s)
        for s in readers:
            if not s.start:
                continue
            for x, seen in s.seen.items():
                # a connection opened in the capture shows stream x: x and, ids growing by 2,
                # every stream from 3 up to it were opened by requests written after the preface
                # and before that frame. Otherwise requests are missing from the file.
                if (x - 1) // 2 > len(self.requests) or not all(
                        any(not self._before(r.rec, s.preface["rec"]) and not self._before(seen, r.rec)
                            for r in self.by_sid.get(y, ())) for y in {x, *range(3, x, 2)}):
                    self.complete = False

    def _assign(self, requests):
        """Attach requests to reader connections where nothing else is possible, repeating: each
        request attached tells when its connection opened that stream, which can rule the
        connection out for other requests."""
        changed = True
        while changed:
            changed = False
            for q in requests:
                if q.seg is None:
                    seg = self._only_request_for(q) or self._only_connection_for(q)
                    if seg is not None:
                        self._attach(q, seg)
                        changed = True
        for seg in self.segments:
            self._decode_connection(seg)
        for q in requests:
            if q.seg is None:
                self._decode_request(q, h2.Decoder(start_known=False))

    def _attach(self, q, seg):
        q.seg = seg
        seg.attached.append(q)
        q.resp = self._response(seg, q)
        if q.resp is not None:
            q.resp.matched = True

    def _response(self, seg, q):
        """seg's response with q's stream id, if it is free and not read before q was written."""
        resp = seg.resps.get(q.sid)
        if resp is None or resp.matched or self._before(resp.rec, q.rec):
            return None
        return resp

    def _only_request_for(self, q):
        """A connection opened in the capture whose stream q.sid can only be q: every request it
        carried is in the file, and no other request with that stream id fits it."""
        if not self.complete:
            return None
        found = []
        for seg in self.segments:
            if not seg.start or self._excluded(seg, q):
                continue
            resp = self._response(seg, q)
            if resp is not None and not any(
                    r is not q and r.seg is None and not self._before(resp.rec, r.rec) and not self._excluded(seg, r)
                    for r in self.by_sid[q.sid]):
                found.append(seg)
        return found[0] if len(found) == 1 else None

    def _only_connection_for(self, q):
        """The reader connection with a response for q's stream id, when it is the only reader
        connection that q can have been written on and no other request can take that response.
        A connection opened in the capture is left to _only_request_for: its pairings are
        certain or not made."""
        candidates = [s for s in self.segments if not self._excluded(s, q)]
        if len(candidates) != 1 or candidates[0].start:
            return None
        seg = candidates[0]
        resp = self._response(seg, q)
        if resp is None or any(r is not q and r.seg is None and not self._before(resp.rec, r.rec)
                               and not self._excluded(seg, r) for r in self.by_sid[q.sid]):
            return None
        return seg

    def _excluded(self, seg, q):
        """True when what seg shows rules out that q was written on its connection: it closed,
        read a GOAWAY or opened (preface) before q; its GOAWAY's last stream id is below q's; it
        shows a stream >= q's before q; a request attached to it contradicts the order of stream
        ids; or its history from a known point on is in the file and lacks a stream between."""
        if not seg.stateful:
            return False        # the thread may read several connections: nothing rules it out
        t = q.rec
        if seg.closed is not None and seg.closed.utc < t.utc:
            return True
        if seg.start and self._before(t, seg.preface["rec"]):
            return True
        if any(last < q.sid or g.utc < t.utc for g, last in seg.goaways):
            return True
        if any(x >= q.sid and self._before(r, t) for x, r in seg.seen.items()):
            return True
        for o in seg.attached:
            if o is not q and (o.sid == q.sid or (o.sid > q.sid and self._before(o.rec, t))
                               or (o.sid < q.sid and self._before(t, o.rec))):
                return True
        return self.complete and (self._table_rules_out(seg, q) or not self._chain_possible(seg, q))

    def _chain_possible(self, seg, q):
        """OkHttp numbers a connection's streams 3, 5, 7, ... From a point on which the
        connection's history is in the file (its preface, or a request attached to it), every
        stream between that point and q's needs a request written in between."""
        anchor = (1, seg.preface["rec"]) if seg.start else None
        for o in seg.attached:
            if o.sid < q.sid and self._before(o.rec, q.rec) and (anchor is None or o.sid > anchor[0]):
                anchor = (o.sid, o.rec)
        if anchor is None:
            return True
        low, since = anchor
        if (q.sid - low) // 2 - 1 > len(self.requests):
            return False
        return all(any(not self._before(r.rec, since) and not self._before(q.rec, r.rec)
                       and not self._table_rules_out(seg, r) for r in self.by_sid.get(x, ()))
                   for x in range(low + 2, q.sid, 2))

    def _table_after(self, seg):
        """(decoder, next stream id) for a connection opened in the capture: its request-side
        header table after the attached requests from its first stream on, as long as they
        follow each other (+2) and decode fully. None when that state is not known."""
        if seg.table is not None and seg.table[0] == len(seg.attached):
            return seg.table[1]
        state = None
        q0 = seg.preface["q0"] if seg.start and seg.stateful else None
        if q0 is not None and q0.seg is seg:
            by = {q.sid: q for q in seg.attached}
            dec, sid = h2.Decoder(start_known=True), q0.sid
            while sid in by and not by[sid].head.uncertain and not by[sid].trailers:
                try:
                    dec.decode(bytes(by[sid].head.data))
                except h2.HpackError:
                    break
                sid += 2
            else:
                state = (dec, sid)
        seg.table = (len(seg.attached), state)
        return state

    def _table_rules_out(self, seg, q):
        """q cannot be the next stream on a connection whose request-side table is known when
        its header block does not decode against that table into a well-formed request."""
        state = self._table_after(seg)
        if state is None or q.sid != state[1] or q.head.uncertain:
            return False
        dec = h2.Decoder(max_size=state[0].max_size, start_known=True)
        dec.entries, dec.size = list(state[0].entries), state[0].size
        try:
            return not _well_formed_request(dec.decode(bytes(q.head.data)))
        except h2.HpackError:
            return True

    # ---------------------------------------------------------- header blocks and exchanges

    def _decode_connection(self, seg):
        """Header blocks of the requests attached to one connection, in stream-id order (the
        order its encoder saw them). The table carries over only from one stream id to the next
        (+2) on a connection known to be one, from the first request on it; any other block is
        decoded knowing nothing of the table."""
        dec, prev = None, None
        for q in sorted(seg.attached, key=lambda q: q.sid):
            if dec is None or prev is None or q.sid != prev + 2 or not seg.stateful:
                dec = h2.Decoder(start_known=False)
            prev = q.sid
            if not self._decode_request(q, dec):
                dec = None

    def _decode_request(self, q, dec):
        """Decode q's header blocks with dec. False when dec cannot be used afterwards."""
        q.headers, q.unknown = None, 0
        if q.head.uncertain:
            return False
        try:
            q.headers = dec.decode(bytes(q.head.data))
            q.unknown = dec.unknown
        except h2.HpackError:
            return False
        for t in q.trailers:
            # trailers come after later requests' headers: their place in HPACK order is unknown
            t.headers = self._context_free(t)
        return not q.trailers

    @staticmethod
    def _context_free(block):
        if block.uncertain:
            return None
        try:
            return h2.Decoder(start_known=False).decode(bytes(block.data))
        except h2.HpackError:
            return None

    def _account_resp(self, resp, reason):
        for b, _, _ in resp.blocks:
            self.account(b.parts, reason)
        self.account(resp.body.parts, reason)

    def _h2_exchange(self, q):
        partial = []
        fields = q.headers or []
        known = [[n, v] for n, v in fields if n is not None and v is not None]
        for t in q.trailers:
            th = getattr(t, "headers", None)
            if th is None:
                partial.append("hpack_state_unknown")
            else:
                known += [[n, v] for n, v in th if n is not None and v is not None]
                if any(n is None or v is None for n, v in th):
                    partial.append("hpack_state_unknown")
        if not q.head.uncertain and (q.headers is None or q.unknown):
            partial.append("hpack_state_unknown")
        if q.head.uncertain or q.body.uncertain:
            partial.append("record_order_unknown")
        if q.seg is not None and not q.seg.start and q.fresh is None:
            # attached by elimination among the connections that show in the file: one whose
            # start is not in it cannot be told apart from one that shows nothing
            partial.append("connection_start_not_captured")
        pseudo = {n: v for n, v in known if n.startswith(":")}
        method = pseudo.get(":method")
        path, query = _split_target(pseudo[":path"], method) if ":path" in pseudo else (None, [])
        host = pseudo.get(":authority") or header([kv for kv in known if not kv[0].startswith(":")], "host")
        restored = q.headers is not None and not q.unknown
        body = None if q.body.uncertain else _body(bytes(q.body.data), known, restored)
        complete = q.ended and not q.body.uncertain and not q.head.uncertain
        ex = self._exchange("h2", q.rec, method, pseudo.get(":scheme", "https"), host, path, query,
                            known, body, complete)
        if q.seg is not None and _okhttp_reader_name(q.seg.rec.comm):
            ex["connection_host_tail"] = _host_tail(q.seg.rec.comm)
        if not complete:
            partial.append("request_incomplete")
        blocks = [q.head, q.body] + q.trailers
        if q.resp is None:
            partial.append("response_not_matched")
        else:
            ex["response"] = self._h2_response(q.resp, partial)
            blocks += [b for b, _, _ in q.resp.blocks] + [q.resp.body]
        for b in blocks:
            # content left out because its record order is open is not part of the exchange
            self.account(b.parts, "record_order_unknown" if b.uncertain else "exchange")
        ex["partial"] = _partial(ex, partial)
        self.exchanges.append((q.rec.idx, ex))

    def _h2_response(self, resp, partial):
        headers, status, restored = [], None, True
        for b, fields, unknown in resp.blocks:
            if fields is None:
                restored = False
                if not b.uncertain:
                    partial.append("hpack_state_unknown")
                continue
            if unknown:
                restored = False
                partial.append("hpack_state_unknown")
            known = [[n, v] for n, v in fields if n is not None and v is not None]
            st = dict(known).get(":status")
            if st is not None and st.isdigit() and 100 <= int(st) < 200:
                continue                    # informational response
            if st is not None and st.isdigit():
                status = int(st)
            headers += known
        if resp.uncertain or resp.body.uncertain:
            partial.append("record_order_unknown")
        complete = resp.ended and not resp.reset and not resp.uncertain and not resp.body.uncertain
        if not complete:
            partial.append("response_incomplete")
        body = None if resp.body.uncertain else _body(bytes(resp.body.data), headers, restored)
        return {"status": status, "headers": headers, "body": body, "complete": complete}

    # ---------------------------------------------------------- shared

    def _exchange(self, protocol, rec, method, scheme, host, path, query, headers, body, complete):
        if host and host.endswith(":443"):
            host = host[:-4]
        return {"source": "ecapture", "time": _local(rec.utc, self.offset), "protocol": protocol,
                "method": method, "scheme": scheme, "host": host or None, "path": path, "query": query,
                "request": {"headers": headers, "body": body, "complete": complete},
                "response": None, "pid": rec.pid, "thread": rec.comm, "partial": [],
                "connection_host_tail": None}


def _forced(items, options, fits):
    """{id(item): option} for each item left with exactly one fitting option not yet taken,
    repeated while options get taken."""
    pairs, taken = {}, set()
    changed = True
    while changed:
        changed = False
        for x in items:
            if id(x) in pairs:
                continue
            fit = [o for o in options if id(o) not in taken and fits(x, o)]
            if len(fit) == 1:
                pairs[id(x)] = fit[0]
                taken.add(id(fit[0]))
                changed = True
    return pairs


def _well_formed_request(fields):
    """RFC 9113 section 8.3: request pseudo-header fields only, each at most once, all before the
    regular fields; :method, and unless CONNECT also :scheme and :path."""
    pseudo, regular = {}, False
    for name, value in fields:
        if name.startswith(":"):
            if regular or name in pseudo or name not in (":method", ":scheme", ":authority", ":path", ":protocol"):
                return False
            pseudo[name] = value
        else:
            regular = True
    return ":method" in pseudo and (pseudo[":method"] == "CONNECT" or (":scheme" in pseudo and ":path" in pseudo))


def _authority(headers):
    for n, v in headers or []:
        if n == ":authority" and v:
            return v[:-4] if v.endswith(":443") else v
    return None


def _okhttp_tail(host):
    return ("OkHttp " + re.sub(r":\d+$", "", host))[-15:]


_HOST = r"[a-z0-9-]+(?:\.[a-z0-9-]+)+"          # OkHttp keeps host names in lower case
_HOST_TAIL = r"[a-z0-9-]*(?:\.[a-z0-9-]+)+"


def _okhttp_reader_name(comm):
    """True for the name OkHttp gives the thread that reads one connection, "OkHttp <host>", as
    the kernel keeps it: Android keeps a dotted name of 15 characters or more as its last 15
    characters, a shorter one whole."""
    if re.fullmatch("OkHttp " + _HOST, comm):
        return True
    if len(comm) != 15:
        return False
    return bool(re.fullmatch(_HOST_TAIL, comm)) or any(
        comm.startswith(p) and re.fullmatch(_HOST, comm[len(p):])
        for p in ("kHttp ", "Http ", "ttp ", "tp ", "p ", " "))


def _host_tail(comm):
    """The host part of an OkHttp reader thread's name: what is left of "OkHttp <host>" without
    the remainder of "OkHttp "."""
    for p in ("OkHttp ", "kHttp ", "Http ", "ttp ", "tp ", "p ", " "):
        if comm.startswith(p):
            return comm[len(p):]
    return comm


def _split_target(target, method):
    if method == "CONNECT" or target == "*":
        return (None if method == "CONNECT" else target), []
    if "://" in target.split("?")[0]:
        parts = urllib.parse.urlsplit(target)
        return parts.path or "/", _query(parts.query)
    path, _, qs = target.partition("?")
    return path, _query(qs)


def _query(qs):
    if not qs:
        return []
    try:
        pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True, encoding="latin-1")
    return [[k, v] for k, v in pairs]


def _body(raw, headers, restored=True):
    """restored: every field of the header block is known, so a missing Content-Encoding field
    means there is none. Otherwise the encoding is told from the bytes only (make_body)."""
    encoding = header(headers, "content-encoding")
    return make_body(raw, header(headers, "content-type"), encoding,
                     encoding_known=restored or encoding is not None)


def _h1_body(msg):
    if msg.head is None:
        return None
    return _body(bytes(msg.body), msg.head[1])


def _partial(ex, reasons):
    for part in (ex["request"], ex["response"]):
        if part and part["body"] and not part["body"]["decoded"]:
            reasons.append("body_not_decoded")
    return list(dict.fromkeys(reasons))


def parse_tls_events(path, utc_offset="+0000") -> dict:
    recs, cut = _read_records(path)
    out_of_order = sum(1 for a, b in zip(recs, recs[1:]) if b.utc < a.utc)
    max_sizes = _max_frame_sizes(recs)
    threads, uncertain, lost, shaky = _order_threads(recs, out_of_order == 0, max_sizes)
    p = _Parser(recs, uncertain, lost, shaky, max_sizes, utc_offset, out_of_order == 0)
    for key in threads:
        p.thread(threads[key])
    p.http2()

    total = sum(len(r.data) for r in recs)
    in_exchange = sum(p.use[r.idx]["exchange"] for r in recs)
    reasons = collections.Counter()
    undecoded_records = 0
    for r in recs:
        use = p.use[r.idx]
        if use["exchange"]:
            continue
        undecoded_records += 1
        others = {k: v for k, v in use.items() if k != "exchange"}
        reasons[max(others, key=lambda k: others[k]) if others else "not_http"] += 1
    info = {}
    for r in recs:
        t = info.setdefault((r.pid, r.tid), {"pid": r.pid, "tid": r.tid, "comm": r.comm, "reads": 0, "writes": 0})
        t["writes" if r.write else "reads"] += 1
    times = [r.utc for r in recs]
    return {
        "records": len(recs),
        "bytes": total,
        "first_time": _local(min(times), utc_offset) if times else None,
        "last_time": _local(max(times), utc_offset) if times else None,
        "out_of_order": out_of_order,
        "cut_off": cut,
        "threads": list(info.values()),
        "exchanges": [ex for _, ex in sorted(p.exchanges, key=lambda x: (x[1]["time"], x[0]))],
        "undecoded": {"records": undecoded_records, "bytes": total - in_exchange,
                      "reasons": dict(sorted(reasons.items()))},
    }
