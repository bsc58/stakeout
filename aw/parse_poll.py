"""Parse poll.txt, the once-per-second blocks written by aw/phone/aw_poll.sh."""
import bisect
import ipaddress
import re
from datetime import datetime, timedelta

from aw.parse_appops import parse_duration_ms

_FMT = "%Y-%m-%d %H:%M:%S"
_EPOCH = datetime(1970, 1, 1)

_BLOCK_RE = re.compile(r"^=== (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*$")
_TOP_RE = re.compile(r"topResumedActivity=ActivityRecord\{\S+ u\d+ ([^\s/{}]+)/([^\s{}]+)(?: t(-?\d+))?")
_P_RE = re.compile(r"^P (\d+) ([^|]*)\|([^|]*)(?:\|(.*))?$")
_KV_RE = re.compile(r"(\w+)=(\S*)")
_IO_RE = re.compile(r"(\w+): (\d+)")
_FD_RE = re.compile(r"^\s*FD -> (.+?)\s*$")
_S_RE = re.compile(r"^S (tcp|udp) (.*)$")
_OT_RE = re.compile(r"^OT (\d+)\s*$")
_O_RE = re.compile(r"^O (Uid mode: )?([A-Z][A-Z0-9_]*): (.*)$")
_AGO_RE = re.compile(r"^(time|rejectTime)=(\S+) ago\b")

# Samples of one op occurrence scatter because the query time is only known to
# the second (block header or OT) and, without OT, the query runs some time
# after the header. Without OT (xhs_1004) the scatter is at most 1.06 s while
# two real FINE_LOCATION accesses 3 s apart must stay separate. With OT
# (live_aweme_2118) it is at most 0.73 s: whole-second truncation plus a little
# query latency, while two GET_USAGE_STATS rejects 1.49 s apart must stay separate.
# The same values bound how early a sample can be, so an occurrence's front state is
# only given when it is the same from its latest sample to its earliest sample + this.
_SAME_EVENT_S_OT = 1.1
_SAME_EVENT_S_NO_OT = 2.0
# Derived event times are early by up to about a second (see above), so an
# occurrence up to 1 s before the window start may still lie inside it.
_WINDOW_SLACK_S = 1.0


def _fmt(dt: datetime) -> str:
    return dt.strftime(_FMT)


def _int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def _endpoint(token: str):
    """'1.2.3.4:443' | '[2001:db8::1]:443' | '[fe80::1]%wlan0:5353' -> (ip, port) or None."""
    host, sep, port = token.rpartition(":")
    if not sep or not port.isdigit():
        return None  # '*' port: listening / unconnected
    host = host.split("%", 1)[0]   # ss appends %iface after the (bracketed) address
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip, int(port)


def _ipport(ip, port) -> str:
    return f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"


def _read_lines(path) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = text.split("\n")
    if not text.endswith("\n"):
        lines.pop()  # capture cut off mid-line
    return lines


def _read_blocks(path) -> list[dict]:
    blocks = []
    b = None
    proc = None
    for line in _read_lines(path):
        m = _BLOCK_RE.match(line)
        if m:
            b = {"time": datetime.strptime(m.group(1), _FMT), "top": None, "ot": None,
                 "procs": [], "sockets": [], "ops": [], "uid_modes": {}, "o_package": False}
            blocks.append(b)
            proc = None
            continue
        if b is None:
            continue
        if "topResumedActivity=" in line:
            m = _TOP_RE.search(line)
            if m:
                pkg, act = m.group(1), m.group(2)
                b["top"] = (f"{pkg}/{act}", pkg, _int(m.group(3)))
            continue
        m = _P_RE.match(line)
        if m:
            cmdline = m.group(2).strip()
            kv = dict(_KV_RE.findall(m.group(3)))
            io = dict(_IO_RE.findall(m.group(4) or ""))
            ut, st = _int(kv.get("ut")), _int(kv.get("st"))
            if not cmdline and ut is None:
                proc = None  # pgrep listed it, but it was gone when /proc was read
                continue
            proc = {"pid": int(m.group(1)), "cmdline": cmdline,
                    "ppid": _int(kv.get("ppid")), "adj": _int(kv.get("adj")),
                    "ticks": ut + st if ut is not None and st is not None else None,
                    "read_bytes": _int(io.get("read_bytes")), "fds": []}
            b["procs"].append(proc)
            continue
        m = _FD_RE.match(line)
        if m:
            if proc is not None:
                proc["fds"].append(m.group(1))
            continue
        m = _S_RE.match(line)
        if m:
            tokens = m.group(2).split()
            i = next((k for k, t in enumerate(tokens) if t.startswith("uid:")), None)
            # Local and peer are the first two tokens with a ':' (state and queue
            # columns have none). Extended info such as 'timer:(on,204ms,0)' can
            # stand between the peer and 'uid:'.
            addrs = [t for t in tokens[:i] if ":" in t][:2] if i is not None else []
            if len(addrs) == 2:
                local, remote = _endpoint(addrs[0]), _endpoint(addrs[1])
                if local and remote and not remote[0].is_loopback and not remote[0].is_unspecified:
                    b["sockets"].append((m.group(1), str(remote[0]), remote[1], _ipport(*local)))
            continue
        m = _OT_RE.match(line)
        if m:
            b["ot"] = int(m.group(1))
            continue
        m = _O_RE.match(line)
        if m:
            uid_prefix, op, rest = m.groups()
            parts = [p.strip() for p in rest.split(";")]
            agos = {}
            has_time = False
            for p in parts[1:]:
                am = _AGO_RE.match(p)
                if am:
                    has_time = True
                    ms = parse_duration_ms(am.group(2))
                    if ms is not None:
                        agos[am.group(1)] = ms
            # `appops get` prints the uid modes ("Uid mode: " before the first
            # one), then the package ops, both in op order. The package section
            # starts at the first line with a time or at an op already listed as
            # a uid mode; its mode-only lines are package ops without accesses.
            if uid_prefix:
                b["o_package"] = False
            elif has_time or op in b["uid_modes"]:
                b["o_package"] = True
            if b["o_package"]:
                b["ops"].append((op, parts[0], agos.get("time"), agos.get("rejectTime")))
            else:
                b["uid_modes"][op] = parts[0]
            continue
        # anything else (dumpsys / shell error noise) is skipped
    return blocks


def _query_time(b: dict) -> datetime:
    """Local time of the appops query: OT (epoch) if present, else the block header."""
    if b["ot"] is None:
        return b["time"]
    # The header is local time, OT is epoch; both were taken within the same
    # second, so their difference gives the UTC offset (to the quarter hour).
    offset = round(((b["time"] - _EPOCH).total_seconds() - b["ot"]) / 900) * 900
    return _EPOCH + timedelta(seconds=b["ot"] + offset)


def _top_over(times, tops, first, last):
    """Whether the package was in front over [first, last] (a block's state lasts until the next
    block); None when that changes within the span or the span begins before the first block."""
    i = bisect.bisect_right(times, first) - 1
    j = bisect.bisect_right(times, last) - 1
    if i < 0:
        return None
    states = set(tops[i:j + 1])
    return states.pop() if len(states) == 1 else None


def parse_poll(path, package: str, start: str | None = None, end: str | None = None) -> dict:
    """Parse poll.txt.

    start / end ("YYYY-MM-DD HH:MM:SS", the capture window, normally
    meta.start_time / meta.end_time) bound the reconstructed op occurrences;
    they default to the first / last block.
    """
    blocks = _read_blocks(path)
    times = [b["time"] for b in blocks]
    tops = [bool(b["top"]) and b["top"][1] == package for b in blocks]

    # front activity, consecutive equal blocks merged; no topResumedActivity line -> None
    top = []
    for b in blocks:
        comp, pkg, task = b["top"] or (None, None, None)
        if top and top[-1]["component"] == comp and top[-1]["task"] == task:
            top[-1]["end"] = _fmt(b["time"])
        else:
            top.append({"start": _fmt(b["time"]), "end": _fmt(b["time"]),
                        "component": comp, "package": pkg, "task": task})

    # processes and per-block CPU
    procs: dict[str, dict] = {}
    last_ticks: dict[int, int] = {}
    last_rb: dict[int, int] = {}
    cpu = []
    fds: dict[tuple, dict] = {}
    for i, b in enumerate(blocks):
        t = _fmt(b["time"])
        block_ticks = 0
        for p in b["procs"]:
            pid = p["pid"]
            rec = procs.get(str(pid))
            if rec is None:
                rec = procs[str(pid)] = {"cmdline": p["cmdline"], "first_seen": t, "last_seen": t,
                                         "ppid": p["ppid"], "cpu_ticks": 0, "adj": [], "read_bytes": 0}
            rec["last_seen"] = t
            if not rec["cmdline"]:
                rec["cmdline"] = p["cmdline"]
            if rec["ppid"] is None:
                rec["ppid"] = p["ppid"]
            if p["adj"] is not None and p["adj"] not in rec["adj"]:
                rec["adj"].append(p["adj"])
            # A process absent from the first block started during the capture,
            # so all its ticks / bytes count. A drop means the pid was reused.
            for value, last, field in ((p["ticks"], last_ticks, "cpu_ticks"),
                                       (p["read_bytes"], last_rb, "read_bytes")):
                if value is None:
                    continue
                if pid in last:
                    d = value - last[pid] if value >= last[pid] else value
                else:
                    d = 0 if i == 0 else value
                last[pid] = value
                rec[field] += d
                if field == "cpu_ticks":
                    block_ticks += d
            for path_ in p["fds"]:
                key = (pid, path_)
                if key in fds:
                    fds[key]["last_seen"] = t
                else:
                    fds[key] = {"pid": pid, "path": path_, "first_seen": t, "last_seen": t}
        cpu.append({"time": t, "ticks": block_ticks, "target_top": tops[i]})

    # remote endpoints
    sockets: dict[tuple, dict] = {}
    for b in blocks:
        t = _fmt(b["time"])
        for proto, ip, port, local in b["sockets"]:
            key = (proto, ip, port)
            if key in sockets:
                sockets[key]["last_seen"] = t
            else:
                sockets[key] = {"proto": proto, "ip": ip, "port": port, "first_seen": t, "last_seen": t,
                                "locals": []}
            if local not in sockets[key]["locals"]:
                sockets[key]["locals"].append(local)   # the app's own connections, for parse_net.attribute

    # op occurrences reconstructed from the "ago" values
    lo = datetime.strptime(start[:19], _FMT) if start else (times[0] if times else None)
    hi = datetime.strptime(end[:19], _FMT) + timedelta(seconds=1) if end else \
        (times[-1] + timedelta(seconds=1) if times else None)
    ops: dict[str, dict] = {}
    clusters: dict[tuple, list] = {}   # (op, kind) -> [{"min","max"}]
    uid_modes: dict[str, str] = {}
    for b in blocks:
        uid_modes.update(b["uid_modes"])
        q = _query_time(b)
        tol = timedelta(seconds=_SAME_EVENT_S_OT if b["ot"] is not None else _SAME_EVENT_S_NO_OT)
        for op, mode, t_ago, r_ago in b["ops"]:
            ops.setdefault(op, {"mode": mode, "events": []})["mode"] = mode
            for kind, ago in (("access", t_ago), ("reject", r_ago)):
                if ago is None:
                    continue
                ev = q - timedelta(milliseconds=ago)
                cl = clusters.setdefault((op, kind), [])
                if cl and ev <= cl[-1]["min"] + tol:
                    cl[-1]["min"] = min(cl[-1]["min"], ev)
                    cl[-1]["max"] = max(cl[-1]["max"], ev)
                else:
                    cl.append({"min": ev, "max": ev, "tol": tol})
    for (op, kind), cl in clusters.items():
        for c in cl:
            # Every sample is early, never late, by at most the scatter `tol` allows: the
            # occurrence lies in [latest sample, earliest sample + tol]. The latest is the estimate.
            ev, latest_possible = c["max"], c["min"] + c["tol"]
            if not (lo - timedelta(seconds=_WINDOW_SLACK_S) <= ev < hi):
                continue
            # The estimate is never late, so round it to the second rather than truncate.
            ops[op]["events"].append({"kind": kind, "time": _fmt(ev + timedelta(milliseconds=500)),
                                      "target_top": _top_over(times, tops, ev, latest_possible)})
    for data in ops.values():
        data["events"].sort(key=lambda e: (e["time"], e["kind"]))

    return {
        "blocks": len(blocks),
        "first_time": _fmt(times[0]) if times else None,
        "last_time": _fmt(times[-1]) if times else None,
        "top": top,
        "procs": procs,
        "cpu": cpu,
        "sockets": list(sockets.values()),
        "ops": ops,
        "uid_modes": uid_modes,
        "fds": list(fds.values()),
    }
