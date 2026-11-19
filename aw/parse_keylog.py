"""Exchanges from a packet capture decrypted with TLS keys (net.pcap + tls_keys.log). The
result, the connection record and the reason codes are in docs/CONTRACT_KEYLOG.md; the
exchange record is that of docs/CONTRACT_DECRYPT.md with source "keylog".

How the bytes become exchanges:

* One tshark run over the whole capture prints every TCP packet in capture order: its TCP
  stream (one connection), addresses, flags, the TLS handshake fields it carries and each
  application-data record tshark decrypted (data.data, hex). With TCP reassembly the
  decrypted records come out in stream order, so the records of one connection and direction,
  joined, are that direction's byte stream from the handshake on. Decryption follows the
  record sequence (AEAD): after a record that is missing, or once tshark has lost the record
  boundaries (seen after a run of retransmissions), nothing more of that direction decrypts,
  so a stream can end early but has no hole.
* The client is the side that sent the SYN, else the ClientHello, else the side that received
  the ServerHello, else the side with the higher port. ALPN is the server's choice (ServerHello
  or, TLS 1.3, EncryptedExtensions), the version the ServerHello's.
* What the bytes are decides the protocol: the HTTP/2 preface first in the client's stream is
  h2, an HTTP/1.x request line is http/1.1; anything else is not HTTP (all of it not_http).
* HTTP/1.1: requests are read one after another from the client's stream, responses from the
  server's. A response belongs to the oldest unanswered request whose first byte came in an
  earlier packet; interim (1xx) responses are part of that exchange; after 101 the rest of both
  streams is not HTTP. A body that runs until the connection closes is complete only when the
  server's FIN is in the capture and tshark saw no missing segment from the server.
* HTTP/2: one frame reader and one HPACK decoder per direction, from the preface on, so every
  header block is decoded against the complete table. An exchange is one stream id: request
  HEADERS (+ CONTINUATION, DATA, trailers) from the client, response from the server.
  END_STREAM makes a side complete; a reset or the end of the data leaves it incomplete. A
  header block that does not decode leaves the table unknown for that direction: from then on
  blocks are decoded as far as certain (aw.h2's tolerant mode) and the exchanges marked
  hpack_state_unknown.
* Bytes that are in no exchange are counted in "undecoded" by reason: h2_control (preface and
  control frames), not_http (not HTTP, or after bytes that break the protocol),
  response_without_request, server_push, incomplete_at_end (a frame or message head cut off by
  the end of the data).
"""
import bisect
import collections
import re
import subprocess
import types
from datetime import datetime, timedelta

from aw import device, h2
from aw.exchange import header
from aw.parse_tls import _H1Msg, _REQUEST_LINE, _body, _h1_body, _local, _partial, _split_target


class KeylogError(Exception):
    """tshark could not be found, run, or it failed. The message is for the user (Chinese)."""


_FIELDS = ("frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst",
           "tcp.dstport", "tcp.flags", "tcp.analysis.lost_segment", "tls.record.version",
           "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
           "tls.handshake.extensions.supported_version", "tls.handshake.version", "tls.handshake.random",
           "data.data")
_TLS13_LABELS = {"CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                 "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET", "EARLY_EXPORTER_SECRET"}
_EPOCH = datetime(1970, 1, 1)
_MAX_FRAME = (1 << 24) - 1      # frame lengths are not checked against SETTINGS_MAX_FRAME_SIZE
_AT = types.SimpleNamespace(idx=0)     # _H1Msg wants a record; positions are tracked here instead
_FIN, _SYN, _ACK = 0x01, 0x02, 0x10


# ---------------------------------------------------------------- tshark

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True)
    except OSError as e:
        raise KeylogError(f"无法运行 tshark（{cmd[0]}）：{e.strerror or e}。") from e


def _tshark_lines(tshark, pcap, keys):
    cmd = [tshark, "-r", str(pcap), "-o", f"tls.keylog_file:{keys}", "-o", "tcp.reassemble_out_of_order:TRUE",
           "--only-protocols", "sll,ip,ipv6,tcp,tls,data", "-Y", "tcp", "-T", "fields"]
    for f in _FIELDS:
        cmd += ["-e", f]
    p = _run(cmd)
    err = p.stderr.decode("utf-8", "replace")
    # a capture cut off inside its last packet (tcpdump stopped mid-write): tshark reads every
    # packet before it and then exits with an error; that is content, not a failure
    if p.returncode and "cut short in the middle of a packet" not in err:
        line = next((l.strip() for l in err.splitlines() if l.strip()), "")
        raise KeylogError(f"tshark 读取抓包时出错（退出码 {p.returncode}）：{line}")
    return p.stdout.decode("utf-8", "replace").splitlines()


def _version(tshark):
    p = _run([tshark, "--version"])
    if p.returncode:
        raise KeylogError(f"tshark 无法运行（退出码 {p.returncode}）：{tshark}")
    return p.stdout.decode("utf-8", "replace").splitlines()[0].strip()


def _read_keys(path):
    """(the "keys" counts, the client randoms the file has keys for)"""
    labels = collections.defaultdict(set)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3 and re.fullmatch(r"[0-9A-Fa-f]{64}", parts[1]):
                labels[parts[1].lower()].add(parts[0])
    return ({"sessions": len(labels),
             "tls13": sum(1 for s in labels.values() if s & _TLS13_LABELS),
             "tls12": sum(1 for s in labels.values() if "CLIENT_RANDOM" in s)}, set(labels))


def _time(epoch, offset):
    sec, _, frac = epoch.partition(".")
    utc = (_EPOCH + timedelta(seconds=int(sec))).strftime("%Y-%m-%d %H:%M:%S")
    return _local(f"{utc}.{(frac + '000')[:3]}", offset)


def _ipport(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


# ---------------------------------------------------------------- connections

class _Dir:
    """One direction of one connection: the decrypted bytes, and for each packet that brought
    some, where its bytes begin, its time and its place in the capture."""

    def __init__(self):
        self.buf = bytearray()
        self.starts, self.times, self.seqs = [], [], []
        self.fin = self.lost = False

    def add(self, data, t, seq):
        self.starts.append(len(self.buf))
        self.times.append(t)
        self.seqs.append(seq)
        self.buf += data

    def _packet(self, pos):
        return bisect.bisect_right(self.starts, pos) - 1

    def time_at(self, pos):
        return self.times[self._packet(pos)]

    def seq_at(self, pos):
        return self.seqs[self._packet(pos)]


class _Conn:
    def __init__(self, sid, t, src, dst):
        self.id, self.time, self.ends = sid, t, (src, dst)
        self.syn = self.hello = self.shello = self.random = None
        self.tls = False
        self.sni = self.alpn = self.version = None
        self.alpns, self.server_hellos = [], []     # (sender, value) until the client is known
        self.dirs = collections.defaultdict(_Dir)

    def finish(self):
        a, b = self.ends
        if self.syn or self.hello:
            self.client = self.syn or self.hello
        elif self.shello:
            self.client = b if self.shello == a else a
        else:
            self.client = a if int(a.rsplit(":", 1)[1]) > int(b.rsplit(":", 1)[1]) else b
        self.server = b if self.client == a else a
        self.alpn = next((v for s, v in self.alpns if s == self.server), None)
        for s, (sup, ver) in self.server_hellos:
            if s == self.server:
                self.version = "1.3" if "0x0304" in sup.split(",") else "1.2" if ver == "0x0303" else None
                break
        self.c, self.s = self.dirs[self.client], self.dirs[self.server]


def _connections(lines, offset):
    conns = {}
    for seq, line in enumerate(lines):
        f = line.split("\t")
        if len(f) != len(_FIELDS) or not f[1]:
            continue
        (epoch, stream, ip4s, ip6s, sport, ip4d, ip6d, dport, flags, lost, recver, hstype, sni, alpn,
         supver, hsver, random, data) = f
        src, dst = _ipport(ip4s or ip6s, sport), _ipport(ip4d or ip6d, dport)
        c = conns.get(stream)
        if c is None:
            c = conns[stream] = _Conn(int(stream), _time(epoch, offset), src, dst)
        flags = int(flags, 16) if flags else 0
        if flags & (_SYN | _ACK) == _SYN and c.syn is None:
            c.syn = src
        d = c.dirs[src]
        if flags & _FIN:
            d.fin = True
        if lost:
            d.lost = True
        if recver:
            c.tls = True
        hs = hstype.split(",") if hstype else []
        if "1" in hs and c.hello is None:
            c.hello, c.sni = src, (sni.split(",")[0] or None)
            c.random = random.split(",")[0].lower() or None
        if "2" in hs:
            c.shello = c.shello or src
            c.server_hellos.append((src, (supver, hsver)))
        if alpn and ("2" in hs or "8" in hs):
            c.alpns.append((src, alpn))
        if data and recver:
            d.add(b"".join(bytes.fromhex(x) for x in data.split(",")), _time(epoch, offset), seq)
    out = [c for c in conns.values() if c.tls]
    for c in out:
        c.finish()
    return sorted(out, key=lambda c: c.id)


# ---------------------------------------------------------------- parsing one connection

class _Parser:
    def __init__(self, conn):
        self.conn = conn
        self.exchanges = []         # (time, position, exchange)
        self.undecoded = collections.Counter()

    def run(self):
        c = self.conn
        cbuf = bytes(c.c.buf)
        if cbuf.startswith(h2.PREFACE):
            self.protocol = "h2"
            self.http2()
        elif _REQUEST_LINE.match(cbuf):
            self.protocol = "http/1.1"
            self.http1()
        else:
            self.protocol = None
            self.undecoded["not_http"] += len(c.c.buf) + len(c.s.buf)

    # ---------------------------------------------------------- HTTP/1.1

    def http1(self):
        c = self.conn
        cbuf, sbuf = bytes(c.c.buf), bytes(c.s.buf)
        requests, pos, rest = [], 0, None       # rest: why the client's bytes after the requests are not used
        while pos < len(cbuf):
            msg, used, rest = self._h1_message(True, cbuf[pos:], None)
            if rest:
                break
            requests.append({"msg": msg, "pos": pos, "end": pos + used, "resp": None})
            pos += used
            if not msg.complete:
                break
        cend = pos
        pos, nxt = 0, 0
        while pos < len(sbuf):
            # a response belongs to the oldest unanswered request that began in an earlier packet
            req = None
            if nxt < len(requests) and c.c.seq_at(requests[nxt]["pos"]) < c.s.seq_at(pos):
                req = requests[nxt]
            msg, used, reason = self._h1_message(False, sbuf[pos:], req["msg"].head[0][0].decode() if req else None)
            if reason:
                self.undecoded[reason] += len(sbuf) - pos
                break
            if not msg.complete and c.s.fin and not c.s.lost:
                msg.finish_at_close()           # a body that ends with the connection
            status = int(msg.head[0][1])
            pos += used
            if req is None:
                self.undecoded["response_without_request"] += used
            elif not (100 <= status < 200 and status != 101):
                req["resp"] = msg
                nxt += 1
            if status == 101 and req is not None:
                # from here on both streams carry another protocol
                del requests[nxt:]
                cend, rest = req["end"], "not_http"
                self.undecoded["not_http"] += len(sbuf) - pos
                break
            if not msg.complete:
                break
        if cend < len(cbuf):
            self.undecoded[rest or "not_http"] += len(cbuf) - cend
        for r in requests:
            self._h1_exchange(r)

    def _h1_message(self, is_request, data, method):
        """(message, bytes used, None) or (None, 0, reason) when no message head can be read."""
        msg = _H1Msg(is_request, _AT, method)
        try:
            used = msg.feed(data, _AT)
        except ValueError:
            return None, 0, "not_http"
        if msg.head is None:
            return None, 0, "incomplete_at_end"
        return msg, used, None

    def _h1_exchange(self, r):
        c = self.conn
        req, resp = r["msg"], r["resp"]
        (method, target, version), headers = req.head
        method, target = method.decode(), h2.text(target)
        path, query = _split_target(target, method)
        host = target if method == "CONNECT" else header(headers, "host")
        ex = self._exchange(version.decode().lower(), c.c.time_at(r["pos"]), method, "https", host, path, query,
                            headers + req.trailers, _h1_body(req), req.complete)
        partial = [] if req.complete else ["request_incomplete"]
        if resp is None:
            partial.append("response_not_matched")
        else:
            ex["response"] = {"status": int(resp.head[0][1]), "headers": resp.head[1] + resp.trailers,
                              "body": _h1_body(resp), "complete": resp.complete}
            if not resp.complete:
                partial.append("response_incomplete")
        ex["partial"] = _partial(ex, partial)
        self.exchanges.append((ex["time"], r["pos"], ex))

    # ---------------------------------------------------------- HTTP/2

    def http2(self):
        c = self.conn
        streams = {}                    # stream id -> _Stream, opened by the client
        dec = h2.Decoder()
        for kind, f, pos, n, block in self._h2_units(c.c.buf, True):
            sid = f.stream_id
            st = streams.get(sid)
            if kind == "block":
                headers, unknown, dec = _decode(dec, block)
                if f.type == h2.HEADERS and st is None and sid % 2:
                    st = streams[sid] = _Stream(sid, pos)
                    st.req = (headers, unknown)
                elif f.type == h2.HEADERS and st is not None and not st.req_ended:
                    st.req_trailers.append((headers, unknown))
                else:
                    self.undecoded["not_http"] += n
                    continue
                if f.flags & h2.END_STREAM:
                    st.req_ended = True
            elif f.type == h2.DATA:
                if st is None or st.req_ended:
                    self.undecoded["not_http"] += n
                    continue
                st.req_body += h2.fragment(f)
                if f.flags & h2.END_STREAM:
                    st.req_ended = True
            else:
                self.undecoded["h2_control"] += n
        dec, pushed = h2.Decoder(), set()
        for kind, f, pos, n, block in self._h2_units(c.s.buf, False):
            sid = f.stream_id
            st = streams.get(sid)
            if kind == "block":
                # every block is decoded, used or not: each one changes the table
                headers, unknown, dec = _decode(dec, block)
                if f.type == h2.PUSH_PROMISE:
                    pushed.add(int.from_bytes(f.payload[1 if f.flags & h2.PADDED else 0:][:4], "big") & 0x7FFFFFFF)
                    self.undecoded["server_push"] += n
                elif sid in pushed:
                    self.undecoded["server_push"] += n
                elif st is None:
                    self.undecoded["response_without_request"] += n
                elif st.resp_ended:
                    self.undecoded["not_http"] += n
                else:
                    st.resp.append((headers, unknown))
                    if f.flags & h2.END_STREAM:
                        st.resp_ended = True
            elif f.type == h2.DATA:
                if sid in pushed:
                    self.undecoded["server_push"] += n
                elif st is None:
                    self.undecoded["response_without_request"] += n
                elif not st.resp or st.resp_ended:
                    self.undecoded["not_http"] += n
                else:
                    st.resp_body += h2.fragment(f)
                    if f.flags & h2.END_STREAM:
                        st.resp_ended = True
            else:
                self.undecoded["h2_control"] += n
        for st in streams.values():
            self._h2_exchange(st)

    def _h2_units(self, buf, client):
        """One direction's frames: ("block", first frame, position, bytes, header block) for a
        HEADERS or PUSH_PROMISE frame with its CONTINUATION frames, ("frame", frame, position,
        bytes, None) for any other. What does not parse as frames goes to undecoded."""
        reader = h2.FrameReader(allow_preface=client, max_size=_MAX_FRAME)
        try:
            frames = reader.feed(bytes(buf))
            bad = 0
        except h2.FrameError as e:
            frames, bad = e.frames, 1
        pos, out, block = 0, [], None
        for f in frames:
            if f.type in (h2.HEADERS, h2.PUSH_PROMISE):
                block = [f, pos, f.size, bytearray(h2.fragment(f))]
            elif f.type == h2.CONTINUATION:
                block[2] += f.size
                block[3] += f.payload
            else:
                out.append(("frame", f, pos, f.size, None))
            if block is not None and f.flags & h2.END_HEADERS:
                out.append(("block", *block))
                block = None
            pos += f.size
        if block is not None:               # a header block the data ends inside
            self.undecoded["incomplete_at_end"] += block[2]
        if pos < len(buf):
            self.undecoded["not_http" if bad else "incomplete_at_end"] += len(buf) - pos
        return out

    def _h2_exchange(self, st):
        c = self.conn
        partial, known, restored = [], [], True
        for fields, unknown in [st.req] + st.req_trailers:
            if fields is None or unknown:
                restored = False
            known += [[n, v] for n, v in fields or [] if n is not None and v is not None]
        if not restored:
            partial.append("hpack_state_unknown")
        pseudo = {n: v for n, v in known if n.startswith(":")}
        method = pseudo.get(":method")
        path, query = _split_target(pseudo[":path"], method) if ":path" in pseudo else (None, [])
        host = pseudo.get(":authority") or header([kv for kv in known if not kv[0].startswith(":")], "host")
        ex = self._exchange("h2", c.c.time_at(st.pos), method, pseudo.get(":scheme", "https"), host, path, query,
                            known, _body(bytes(st.req_body), known, restored), st.req_ended)
        if not st.req_ended:
            partial.append("request_incomplete")
        if not st.resp:
            partial.append("response_not_matched")
        else:
            ex["response"] = self._h2_response(st, partial)
        ex["partial"] = _partial(ex, partial)
        self.exchanges.append((ex["time"], st.pos, ex))

    @staticmethod
    def _h2_response(st, partial):
        headers, status, restored = [], None, True
        for fields, unknown in st.resp:
            if fields is None or unknown:
                restored = False
                partial.append("hpack_state_unknown")
            known = [[n, v] for n, v in fields or [] if n is not None and v is not None]
            code = dict(known).get(":status")
            if code is not None and code.isdigit() and 100 <= int(code) < 200:
                continue                    # informational response
            if code is not None and code.isdigit():
                status = int(code)
            headers += known
        if not st.resp_ended:
            partial.append("response_incomplete")
        return {"status": status, "headers": headers, "body": _body(bytes(st.resp_body), headers, restored),
                "complete": st.resp_ended}

    # ---------------------------------------------------------- shared

    def _exchange(self, protocol, time, method, scheme, host, path, query, headers, body, complete):
        if host:
            host = host.lower()
            default = {"https": ":443", "http": ":80"}.get(scheme)
            if default and host.endswith(default):
                host = host[:-len(default)]
        return {"source": "keylog", "time": time, "protocol": protocol,
                "method": method, "scheme": scheme, "host": host or None, "path": path, "query": query,
                "request": {"headers": headers, "body": body, "complete": complete},
                "response": None, "pid": None, "thread": None, "partial": [],
                "connection_host_tail": None, "connection": self.conn.id, "server": self.conn.server}


class _Stream:
    """One HTTP/2 stream the client opened. req and each entry of resp: (headers or None, unknown)."""

    def __init__(self, sid, pos):
        self.sid, self.pos = sid, pos
        self.req, self.req_trailers = None, []
        self.req_body, self.req_ended = bytearray(), False
        self.resp, self.resp_body, self.resp_ended = [], bytearray(), False


def _decode(dec, block):
    """(headers or None, unknown fields, decoder to use next). A block that does not decode leaves
    the table unknown: later blocks are decoded only as far as certain."""
    try:
        return dec.decode(bytes(block)), dec.unknown, dec
    except h2.HpackError:
        return None, 0, h2.Decoder(start_known=False)


def parse_keylog(pcap_path, keys_path, utc_offset="+0000", tshark=None) -> dict:
    keys, randoms = _read_keys(keys_path)
    with open(pcap_path, "rb"):
        pass                                # a missing capture is FileNotFoundError, as for every parser
    exe = device.find_tshark(tshark)
    if exe is None:
        raise KeylogError("找不到 tshark：请安装 Wireshark，或用环境变量 AW_TSHARK 指定 tshark 的路径。")
    version = _version(exe)
    return {"tshark": version, "keys": keys,
            **_build(_tshark_lines(exe, pcap_path, keys_path), utc_offset, randoms)}


def _build(lines, utc_offset, randoms=frozenset()):
    """connections, exchanges and undecoded from tshark's output lines; randoms: the client randoms the
    key file has keys for (a connection's "key")."""
    conns = _connections(lines, utc_offset)
    out_conns, exchanges, undecoded = [], [], collections.Counter()
    for c in conns:
        decrypted = bool(c.c.buf or c.s.buf)
        protocol, n = None, 0
        if decrypted:
            p = _Parser(c)
            p.run()
            protocol, n = p.protocol, len(p.exchanges)
            exchanges += [(t, c.id, pos, ex) for t, pos, ex in p.exchanges]
            undecoded.update(p.undecoded)
        out_conns.append({"id": c.id, "time": c.time, "client": c.client, "server": c.server,
                          "sni": c.sni, "alpn": c.alpn, "tls": c.version, "handshake_seen": c.hello is not None,
                          # the key file has the ClientHello's client random: a connection can have its key
                          # and still decrypt nothing (fixtures/live_xhs_keylog_1119: closed after the handshake)
                          "key": c.random is not None and c.random in randoms,
                          "decrypted": decrypted, "sent": len(c.c.buf), "received": len(c.s.buf),
                          "protocol": protocol, "exchanges": n})
    exchanges.sort(key=lambda x: x[:3])
    reasons = {k: v for k, v in sorted(undecoded.items()) if v}
    return {"connections": out_conns, "exchanges": [x[3] for x in exchanges],
            "undecoded": {"bytes": sum(reasons.values()), "reasons": reasons}}
