"""Parse net.pcap: per-endpoint traffic, TLS SNI, DNS answers, join with poll sockets.

Pure-Python reader for classic pcap (either byte order, microsecond or
nanosecond timestamps) with link types LINUX_SLL2 (276), LINUX_SLL (113) and
Ethernet (1); IPv4 and IPv6; TCP and UDP.

Which side of a packet is the remote one:

- SLL2 / SLL carry the kernel packet type. OUTGOING (4): the destination is
  remote. HOST (0): the source is remote. BROADCAST / MULTICAST / OTHERHOST
  (1/2/3) are frames the interface received that this phone did not ask for
  (other LAN devices' mDNS, router adverts); they are left out of the endpoint
  accounting. Loopback devices (ARPHRD_LOOPBACK) carry only on-device traffic,
  including packets a transparent proxy diverts to itself before relaying them
  on the real interface, so they are left out too: counting them would count
  the same flow twice.
- Ethernet has no packet type. The phone's MAC is taken to be the source MAC
  that sent the most TCP SYNs (ties: the most distinct destination IPs); frames
  from it are outgoing, frames to it incoming, the rest are skipped.
- With every link type, packets with a loopback address are skipped.

Each endpoint (keyed by the remote side) lists its `flows`, one per local
ip:port, which in practice is one per connection:
{"local", "sni", "bytes_out", "bytes_in", "first_epoch", "last_epoch"}, ordered
by first packet. A flow's `sni` is the server_name of the first ClientHello it
sent, None when it sent none in the capture (it began earlier, or is not TLS
over TCP). One server address can serve several names, also of different apps
(43.109.9.9:443 in xhs_1004 got www.xiaohongshu.com and a Douyin API host), so
names belong to flows. The top-level `sni` map gives per server ip:port the
name whose flows carried the most bytes (ties: the name seen first).

SNI and DNS answers are read from every packet, loopback included. Byte counts
are IP lengths (header + payload).
"""
import functools
import ipaddress
import struct

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
_ARPHRD_LOOPBACK = 772
_PACKET_HOST = 0
_PACKET_OUTGOING = 4
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
_IPV6_EXT = (0, 43, 44, 60)          # hop-by-hop, routing, fragment, destination options
_PROTO = {6: "tcp", 17: "udp"}


@functools.lru_cache(maxsize=65536)
def _ipstr(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def _is_loopback(raw: bytes) -> bool:
    return raw[0] == 127 if len(raw) == 4 else raw == b"\0" * 15 + b"\1"


def _ipport(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _link(linktype: int, d: bytes):
    """-> (ethertype, l3 bytes, hint, ifindex). hint: "out", "in", None (not ours),
    "lo" (loopback device) or (src_mac, dst_mac) for Ethernet."""
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(d) < 20:
            return None
        etype, ifindex, hatype, ptype = struct.unpack(">H2xIHB", d[:11])
        return etype, d[20:], _hint(hatype, ptype), ifindex
    if linktype == LINKTYPE_LINUX_SLL:
        if len(d) < 16:
            return None
        ptype, hatype = struct.unpack(">HH", d[:4])
        etype = struct.unpack(">H", d[14:16])[0]
        return etype, d[16:], _hint(hatype, ptype), None
    if linktype == LINKTYPE_ETHERNET:
        if len(d) < 14:
            return None
        etype, off = struct.unpack(">H", d[12:14])[0], 14
        while etype in _VLAN_TYPES and len(d) >= off + 4:
            etype, off = struct.unpack(">H", d[off + 2:off + 4])[0], off + 4
        return etype, d[off:], (d[6:12], d[0:6]), None
    return None


def _hint(hatype: int, ptype: int):
    if hatype == _ARPHRD_LOOPBACK:
        return "lo"
    if ptype == _PACKET_OUTGOING:
        return "out"
    if ptype == _PACKET_HOST:
        return "in"
    return None


def _ip(etype: int, l3: bytes):
    """-> (proto, src, dst, ip_len, l4 bytes) or None for non-IP / non-first fragments."""
    if etype == 0x0800:
        if len(l3) < 20 or l3[0] >> 4 != 4:
            return None
        if struct.unpack(">H", l3[6:8])[0] & 0x1FFF:
            return None
        total = struct.unpack(">H", l3[2:4])[0] or len(l3)
        return l3[9], l3[12:16], l3[16:20], total, l3[(l3[0] & 15) * 4:total]
    if etype == 0x86DD:
        if len(l3) < 40 or l3[0] >> 4 != 6:
            return None
        plen = struct.unpack(">H", l3[4:6])[0]
        total = 40 + plen if plen else len(l3)
        proto, off = l3[6], 40
        while proto in _IPV6_EXT:
            if len(l3) < off + 8:
                return None
            if proto == 44:
                if struct.unpack(">H", l3[off + 2:off + 4])[0] & 0xFFF8:
                    return None
                proto, off = l3[off], off + 8
            else:
                proto, off = l3[off], off + (l3[off + 1] + 1) * 8
        return proto, l3[8:24], l3[24:40], total, l3[off:total]
    return None


def _sni(p: bytes):
    """server_name of a TLS ClientHello starting at p (p may be cut off), or None."""
    if len(p) < 44 or p[0] != 0x16 or p[1] != 3 or p[5] != 1:
        return None
    try:
        i = 43                                       # record 5 + handshake 4 + version 2 + random 32
        i += 1 + p[i]                                # session id
        i += 2 + int.from_bytes(p[i:i + 2])          # cipher suites
        i += 1 + p[i]                                # compression methods
        end = min(len(p), i + 2 + int.from_bytes(p[i:i + 2]))
        i += 2
        while i + 4 <= end:
            etype, elen = int.from_bytes(p[i:i + 2]), int.from_bytes(p[i + 2:i + 4])
            i += 4
            if etype == 0:                           # server_name: list len, type, name len, name
                if p[i + 2] != 0:
                    return None
                nlen = int.from_bytes(p[i + 3:i + 5])
                name = p[i + 5:i + 5 + nlen]
                if len(name) < nlen or not nlen:
                    return None
                return name.decode("ascii", "replace").lower().rstrip(".")
            i += elen
    except IndexError:
        return None
    return None


def _dns_name(m: bytes, i: int):
    labels, end, hops = [], None, 0
    while True:
        n = m[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = i + 2
            hops += 1
            if hops > 30:
                raise ValueError("DNS name pointer loop")
            i = ((n & 0x3F) << 8) | m[i + 1]
            continue
        labels.append(m[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels).lower(), (i if end is None else end)


def _dns_answers(m: bytes):
    """[(ip, name)] from the A/AAAA answers of a DNS response. name is the queried
    name (what the client asked for), not the end of a CNAME chain."""
    out = []
    try:
        flags, qdcount, ancount = struct.unpack(">2xHHH", m[:8])
        if not flags & 0x8000:
            return out
        i, qname = 12, None
        for _ in range(qdcount):
            name, i = _dns_name(m, i)
            i += 4
            qname = qname or name
        for _ in range(ancount):
            name, i = _dns_name(m, i)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", m[i:i + 10])
            rdata = m[i + 10:i + 10 + rdlen]
            i += 10 + rdlen
            if (rtype == 1 and len(rdata) == 4) or (rtype == 28 and len(rdata) == 16):
                out.append((_ipstr(rdata), qname or name))
    except (IndexError, ValueError, struct.error):
        pass
    return out


def _top_name(flows, names=()):
    """The server_name whose flows carried the most bytes; ties: first in `names`, then in `flows`."""
    weight = dict.fromkeys(names, 0)
    for fl in flows:
        if fl["sni"]:
            weight[fl["sni"]] = weight.get(fl["sni"], 0) + fl["bytes_out"] + fl["bytes_in"]
    return max(weight, key=weight.get) if weight else None


def parse_pcap(path) -> dict:
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24 and any(m.startswith(hdr[:4]) for m in _MAGIC):
            # empty, or cut off inside the 24-byte file header: a capture with no packets
            return {"packets": 0, "linktype": None, "first_epoch": None, "last_epoch": None,
                    "sni": {}, "dns": {}, "endpoints": {}}
        if len(hdr) < 24 or hdr[:4] not in _MAGIC:
            raise ValueError(f"not a classic pcap file: {path}")
        endian, unit = _MAGIC[hdr[:4]]
        linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0xFFFF
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
            raise ValueError(f"unsupported pcap link type {linktype}: {path}")
        rec = struct.Struct(endian + "IIII")
        packets, first, last = 0, None, None
        hellos: dict[tuple, str] = {}                # (client ip, port, server ip, port) -> first server_name
        dns: dict[str, list[str]] = {}
        flows: dict[tuple, list] = {}                # (hint, proto, src, sport, dst, dport) -> [bytes, first, last]
        syns: dict[bytes, int] = {}                  # Ethernet: TCP SYNs sent, per source MAC
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            sec, frac, incl, _orig = rec.unpack(ph)
            d = f.read(incl)
            if len(d) < incl:                        # cut off mid-record
                break
            ts = round(sec + frac * unit, 6)
            packets += 1
            if first is None:
                first = ts
            last = ts
            link = _link(linktype, d)
            if link is None:
                continue
            etype, l3, hint, _ifindex = link
            ip = _ip(etype, l3)
            if ip is None or ip[0] not in _PROTO:
                continue
            proto, src, dst, ip_len, l4 = ip
            if len(l4) < (20 if proto == 6 else 8):
                continue
            sport, dport = struct.unpack(">HH", l4[:4])
            payload = l4[(l4[12] >> 4) * 4:] if proto == 6 else l4[8:]
            if proto == 6 and payload:
                name = _sni(payload)
                if name:
                    hellos.setdefault((src, sport, dst, dport), name)
            if sport == 53 and payload:
                msg = payload[2:2 + int.from_bytes(payload[:2])] if proto == 6 else payload
                for addr, name in _dns_answers(msg):
                    names = dns.setdefault(addr, [])
                    if name not in names:
                        names.append(name)
            if hint is None or hint == "lo" or _is_loopback(src) or _is_loopback(dst):
                continue
            if linktype == LINKTYPE_ETHERNET and proto == 6 and l4[13] & 0x12 == 0x02:
                syns[hint[0]] = syns.get(hint[0], 0) + 1
            k = (hint, proto, src, sport, dst, dport)
            fl = flows.get(k)
            if fl is None:
                flows[k] = [ip_len, ts, ts]
            else:
                fl[0] += ip_len
                fl[2] = ts

    local_mac = None
    if linktype == LINKTYPE_ETHERNET:
        # Every unicast frame of a phone on Wi-Fi is between the phone and the access
        # point, so frame counts cannot tell the two apart. The phone is the client:
        # it sends the TCP SYNs, and sends to many destination IPs.
        dsts: dict[bytes, set] = {}
        for (hint, _p, _s, _sp, dst, _dp) in flows:
            if not hint[0][0] & 1:                   # unicast source MAC
                dsts.setdefault(hint[0], set()).add(dst)
        if dsts:
            local_mac = max(dsts, key=lambda m: (syns.get(m, 0), len(dsts[m])))

    conns: dict[tuple, dict] = {}                    # (proto, local ip, port, remote ip, port) -> flow
    for (hint, proto, src, sport, dst, dport), (nbytes, f_ts, l_ts) in flows.items():
        if isinstance(hint, tuple):
            hint = "out" if hint[0] == local_mac else "in" if hint[1] == local_mac else None
            if hint is None:
                continue
        k = (proto, src, sport, dst, dport) if hint == "out" else (proto, dst, dport, src, sport)
        c = conns.get(k)
        if c is None:
            c = conns[k] = {"local": _ipport(_ipstr(k[1]), k[2]),
                            "sni": hellos.get(k[1:]) if proto == 6 else None,
                            "bytes_out": 0, "bytes_in": 0, "first_epoch": f_ts, "last_epoch": l_ts}
        c["bytes_out" if hint == "out" else "bytes_in"] += nbytes
        c["first_epoch"] = min(c["first_epoch"], f_ts)
        c["last_epoch"] = max(c["last_epoch"], l_ts)

    endpoints: dict[str, dict] = {}
    for (proto, _l, _lp, rip, rport), c in sorted(conns.items(),
                                                   key=lambda kv: (kv[1]["first_epoch"], kv[1]["local"])):
        key = f"{_PROTO[proto]} {_ipport(_ipstr(rip), rport)}"
        e = endpoints.get(key)
        if e is None:
            e = endpoints[key] = {"bytes_out": 0, "bytes_in": 0, "first_epoch": c["first_epoch"],
                                  "last_epoch": c["last_epoch"], "flows": []}
        e["bytes_out"] += c["bytes_out"]
        e["bytes_in"] += c["bytes_in"]
        e["last_epoch"] = max(e["last_epoch"], c["last_epoch"])
        e["flows"].append(c)

    names: dict[str, list[str]] = {}                 # server ip:port -> names in order first seen
    for (_c, _cp, dst, dport), name in hellos.items():
        seen = names.setdefault(_ipport(_ipstr(dst), dport), [])
        if name not in seen:
            seen.append(name)
    sni = {k: _top_name(endpoints.get(f"tcp {k}", {}).get("flows", []), v) for k, v in names.items()}
    return {"packets": packets, "linktype": linktype, "first_epoch": first, "last_epoch": last,
            "sni": sni, "dns": dns, "endpoints": endpoints}


def _norm_ip(ip) -> str:
    s = str(ip).strip().strip("[]").split("%", 1)[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return s
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(a)


def _norm_ipport(s) -> str:
    ip, _, port = str(s).strip().rpartition(":")
    return _ipport(_norm_ip(ip), int(port))


def _host(pcap: dict, ip: str, port: int):
    name = pcap.get("sni", {}).get(_ipport(ip, port))
    if name:
        return name, "sni"
    names = pcap.get("dns", {}).get(ip)
    if names:
        return names[0], "dns"
    return None, None


def attribute(pcap: dict, sockets: list[dict]) -> list[dict]:
    """One record per remote endpoint of the app's sockets, with host name and pcap bytes.

    A socket may carry `locals`: the local "ip:port" values of its S lines. Then only
    those flows are counted, and the host is the name their own ClientHello sent.
    Without `locals`, the bytes are those of every flow to that server ip:port in the
    capture, whichever app made it, and the host is the server address's main name.
    IPv4-mapped IPv6 addresses (dual-stack sockets) are matched as IPv4."""
    merged: dict[tuple, dict] = {}
    for s in sockets:
        key = (str(s["proto"]).lower(), _norm_ip(s["ip"]), int(s["port"]))
        m = merged.get(key)
        if m is None:
            m = merged[key] = {"first_seen": s.get("first_seen"), "last_seen": s.get("last_seen"),
                               "locals": set()}
        else:
            seen = [t for t in (m["first_seen"], s.get("first_seen")) if t]
            m["first_seen"] = min(seen) if seen else None
            seen = [t for t in (m["last_seen"], s.get("last_seen")) if t]
            m["last_seen"] = max(seen) if seen else None
        m["locals"].update(_norm_ipport(x) for x in s.get("locals") or ())
    out = []
    for (proto, ip, port), m in merged.items():
        flows = pcap.get("endpoints", {}).get(f"{proto} {_ipport(ip, port)}", {}).get("flows", [])
        if m["locals"]:
            flows = [fl for fl in flows if fl["local"] in m["locals"]]
        name = _top_name(flows)
        host, source = (name, "sni") if name else _host(pcap, ip, port)
        out.append({"proto": proto, "ip": ip, "port": port, "host": host, "host_source": source,
                    "first_seen": m["first_seen"], "last_seen": m["last_seen"],
                    "bytes_out": sum(fl["bytes_out"] for fl in flows),
                    "bytes_in": sum(fl["bytes_in"] for fl in flows),
                    "plaintext": None})
    out.sort(key=lambda r: (-(r["bytes_out"] + r["bytes_in"]), r["proto"], r["ip"], r["port"]))
    return out


def hosts_unattributed(pcap: dict) -> list[dict]:
    """System-wide traffic per (host, port). Each flow counts under the name its own
    ClientHello sent; a flow without one falls back to the server address's name
    (SNI, then DNS), then to the IP."""
    agg: dict[tuple, list] = {}
    for key, e in pcap.get("endpoints", {}).items():
        ipport = key.split(" ", 1)[1]
        ip, port = ipport.rsplit(":", 1)
        ip, port = ip.strip("[]"), int(port)
        fallback = _host(pcap, ip, port)
        for fl in e["flows"]:
            host, source = (fl["sni"], "sni") if fl["sni"] else fallback
            a = agg.setdefault((host or ip, port), [0, None])
            a[0] += fl["bytes_out"] + fl["bytes_in"]
            if source == "sni" or (source == "dns" and a[1] is None):
                a[1] = source
    rows = [{"host": h, "port": p, "bytes": b, "host_source": s} for (h, p), (b, s) in agg.items()]
    rows.sort(key=lambda r: (-r["bytes"], r["host"], r["port"]))
    return rows
