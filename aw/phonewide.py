"""The overview of a phone run (docs/CONTRACT_PHONE.md, "aw/phonewide.py"): what every app did
during the run, attributed by uid and built into the overview by aw/overview.py.

An app is a uid of 10000 or more (the first application uid, the bound the phone poll uses for
its P lines); packages that share a uid are one app, named after the user-installed one. Lower
uids are the system itself: what they do is no app's. Attribution:

* a process: the uid on its P line in poll.txt; one the poll did not see, by logcat's process
  starts, then by ps_before.txt / ps_after.txt;
* a file access: the trace's TGID, as a process above;
* a connection (a pcap flow, a TLS connection of the key route): the S lines with the same local
  address and port, those to the same server first (the keys are every app's, so a decrypted
  connection is not by itself any app's);
* a permission access: the uid section of `dumpsys appops` it is listed under.

What none of these covers is given to no app; limits counts it. Each shared file is read once:
the trace as a stream, logcat once (then the few lines parse_logcat reads, per app), the appops
dumps once, the pcap once, tshark once.
"""

import bisect
import gzip
import json
import tempfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from aw import analyze, parse_appops, parse_filetrace, parse_logcat, parse_net, parse_poll

FIRST_APP_UID = 10000
TRACE_CLOCK_S = analyze.TRACE_CLOCK_S
# The appops entry flags of an access an app made on behalf of another (trusted / untrusted proxy):
# the app it was made for has the same access with flags tpd / upd, so it is that app's.
PROXY_FLAGS = {"tp", "up"}
# The tags parse_logcat reads; the other lines are left out before it runs once per app.
LOGCAT_TAGS = {"ActivityManager", "am_proc_start", "am_kill", "am_proc_died", "lowmemorykiller", "lmkd",
               "ActivityTaskManager", "ClipboardService", "ClipboardService-Controller", "AndroidRuntime",
               "screen_toggled"}
_EPOCH = datetime(1970, 1, 1)


# ---------------------------------------------------------------- reading

def _lines(path):
    """Lines of a text file without their ending; a last line without one was cut off and is left out."""
    return parse_logcat._complete_lines(path)


def _gz_lines(path):
    """Lines of the concatenated gzip members; a stream cut off inside its last member keeps what
    came before the cut line."""
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="\n") as f:
        try:
            for line in f:
                if line.endswith("\n"):
                    yield line.rstrip("\r\n")
        except EOFError:
            return


def _read_poll(path):
    """poll.txt of a phone run: block times, the package in front in each block (None: no
    topResumedActivity line), processes by (pid, uid), sockets by (proto, local, remote) and their
    uids also by (proto, local)."""
    times, tops, procs, sockets, locals_ = [], [], {}, {}, {}
    t = None
    for line in _lines(path):
        if line.startswith("=== "):
            m = parse_poll._BLOCK_RE.match(line)
            if m:
                t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                times.append(t)
                tops.append(None)
            continue
        if t is None:
            continue
        if line.startswith("P "):
            parts = line.split(None, 4)
            if len(parts) < 4 or not (parts[1].isdigit() and parts[3].isdigit()):
                continue
            pid, uid = int(parts[1]), int(parts[3])
            p = procs.get((pid, uid))
            if p is None:
                procs[(pid, uid)] = {"pid": pid, "uid": uid, "ppid": int(parts[2]) if parts[2].isdigit() else None,
                                     "name": parts[4].strip() if len(parts) > 4 else "",
                                     "first_seen": t, "last_seen": t}
            else:
                p["last_seen"] = t
        elif line.startswith("S "):
            proto, _, rest = line[2:].partition(" ")
            if proto not in ("tcp", "udp"):
                continue
            tokens = rest.split()
            i = next((k for k, x in enumerate(tokens) if x.startswith("uid:")), None)
            uid = int(tokens[i][4:]) if i is not None and tokens[i][4:].isdigit() else 0
            # local and peer are the first two tokens with a ':' (as in parse_poll)
            addrs = [x for x in tokens[:i] if ":" in x][:2]
            if len(addrs) != 2:
                continue
            local, remote = parse_poll._endpoint(addrs[0]), parse_poll._endpoint(addrs[1])
            if not local or local[0].is_loopback:
                continue
            locals_.setdefault((proto, parse_poll._ipport(*local)), set()).add(uid)
            if not remote or remote[0].is_loopback or remote[0].is_unspecified:
                continue
            key = (proto, parse_poll._ipport(*local), parse_poll._ipport(*remote))
            s = sockets.get(key)
            if s is None:
                sockets[key] = {"uids": {uid}, "first_seen": t, "last_seen": t}
            else:
                s["uids"].add(uid)
                s["last_seen"] = t
        elif "topResumedActivity=" in line:
            m = parse_poll._TOP_RE.search(line)
            if m:
                tops[-1] = m.group(1)
    return {"times": times, "tops": tops, "procs": procs, "sockets": sockets, "locals": locals_}


def _dump_entries(lines):
    """(uid, package, op, kind, state, flags, time) of every Access / Reject line of full
    `dumpsys appops` outputs (any number, one after another)."""
    uid = pkg = op = None
    for line in lines:
        if "Access:" in line or "Reject:" in line:
            if op is not None:
                m = parse_appops._ENTRY_RE.match(line)
                if m:
                    kind, state, flags, time, _ = m.groups()
                    yield uid, pkg, op, "access" if kind == "Access" else "reject", state, flags, time
            continue
        if line.startswith("  ") and not line.startswith("   "):
            # a top-level section: a uid, or something else (watchers, policy tags)
            m = parse_appops._UID_RE.match(line)
            uid = parse_logcat._uid_info(m.group(1))[0] if m else None
            pkg = op = None
        elif line.startswith("==="):
            uid = pkg = op = None
        elif uid is not None and "Package " in line:
            m = parse_appops._PKG_RE.match(line)
            if m:
                pkg, op = m.group(1), None
        elif pkg is not None and line.rstrip().endswith("):"):
            m = parse_appops._OP_RE.match(line)
            if m:
                op = m.group(1)


def _appops(run_dir, start, end, missing):
    """The accesses and rejections inside [start, end] that the dumps show, per uid: each distinct
    (package, op, kind, state, time) not already in appops_before.txt is one occurrence (diff_appops'
    rule over every dump of the run). -> ({uid: [occurrence]}, samples read)"""
    lo, hi = start[:19], end[:19]
    before = set()
    if (run_dir / "appops_before.txt").exists():
        before = set(_dump_entries(_lines(run_dir / "appops_before.txt")))
    else:
        missing.append("appops_before.txt")
    found = {}
    samples = 0

    def take(lines):
        for e in _dump_entries(lines):
            uid, pkg, op, kind, state, flags, time = e
            if flags in PROXY_FLAGS or e in before or not lo <= time[:19] <= hi:
                continue
            found.setdefault((uid, pkg, op, kind, state, time), set()).add(flags)

    if (run_dir / "appops_all.txt.gz").exists():
        def counted(lines):
            nonlocal samples
            for line in lines:
                if line.startswith("=== "):
                    samples += 1
                yield line
        take(counted(_gz_lines(run_dir / "appops_all.txt.gz")))
    else:
        missing.append("appops_all.txt.gz")
    if (run_dir / "appops_after.txt").exists():
        take(_lines(run_dir / "appops_after.txt"))
    else:
        missing.append("appops_after.txt")
    by_uid = {}
    for (uid, pkg, op, kind, state, time), flags in sorted(found.items(), key=lambda kv: kv[0][5]):
        by_uid.setdefault(uid, []).append({"package": pkg, "op": op, "kind": kind, "state": state,
                                           "flags": sorted(flags), "time": time})
    return by_uid, samples


def _logcat(path, groups, year):
    """parse_logcat's result per app (uid -> result for its first package, and the clipboard
    records of all its packages), and the start record of every pid (any app)."""
    keep, last = [], None
    for line in _lines(path):
        m = parse_logcat._HEAD.match(line)
        if not m:
            continue
        y, mo, d, hms = m.group(1), m.group(2), m.group(3), m.group(4)
        t = f"{y or year}-{mo}-{d} {hms}"
        tag, _ = parse_logcat._split_tag(m.group(7))
        if tag in LOGCAT_TAGS:
            keep.append(line)
        if last is None or t > last[0]:
            last = (t, line, tag in LOGCAT_TAGS)
    if last is not None and not last[2]:
        keep.append(last[1])           # parse_logcat's last_time, which decides a late clipboard read
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        sub = Path(tmp) / "logcat.txt"
        sub.write_text("".join(x + "\n" for x in keep), encoding="utf-8")
        pid_map = {}
        for uid, g in groups.items():
            res = None
            clip = []
            for pkg in g["packages"]:
                r = parse_logcat.parse_logcat(sub, pkg, uid, year=year)
                res = res or r
                clip += r["clipboard"]
            res["clipboard"] = sorted(clip, key=lambda c: c["time"])
            out[uid] = res
            pid_map = res["pid_map"]
        if not groups:
            pid_map = parse_logcat.parse_logcat(sub, "", -1, year=year)["pid_map"]
    return out, pid_map


def _ps_uid(user):
    """`u0_a123` -> 10123; `u0_i5` (an isolated process) -> None; any other user (root, system,
    radio, ...) is the system: 0."""
    head, sep, num = user.partition("_")
    if sep and head[:1] == "u" and head[1:].isdigit():
        if num[:1] == "a" and num[1:].isdigit():
            return int(head[1:]) * 100000 + FIRST_APP_UID + int(num[1:])
        return None
    return 0


# ---------------------------------------------------------------- front

class _Front:
    """Which package was in front, per poll block; a block's state lasts until the next block."""

    def __init__(self, times, tops):
        self.times, self.tops = times, tops

    def at(self, pkgs, t, within=0.0):
        """Whether one of pkgs was in front at t (over [t, t + within] when the state is the same
        throughout); None when it changes in that span or t lies before the first block."""
        d = analyze._dt(t) if isinstance(t, str) else t
        if d is None or not self.times:
            return None
        i = bisect.bisect_right(self.times, d) - 1
        if i < 0:
            return None
        j = bisect.bisect_right(self.times, d + timedelta(seconds=within)) - 1 if within else i
        states = {self.tops[k] in pkgs for k in range(i, j + 1)}
        return states.pop() if len(states) == 1 else None

    def over(self, pkgs, d0, d1):
        """The states over [d0, d1] (True: in front); the part before the first block is unknown."""
        if not self.times or d1 < self.times[0]:
            return set()
        i = max(bisect.bisect_right(self.times, d0) - 1, 0)
        j = bisect.bisect_right(self.times, d1) - 1
        return {self.tops[k] in pkgs for k in range(i, j + 1)}

    def unknown_seconds(self, end):
        """Seconds of blocks without a topResumedActivity line (analyze._unknown_front_spans)."""
        total = 0.0
        for k, t in enumerate(self.times):
            if self.tops[k] is not None:
                continue
            nxt = self.times[k + 1] if k + 1 < len(self.times) else (
                min(t + timedelta(seconds=1), max(t, end)) if end else t + timedelta(seconds=1))
            total += (nxt - t).total_seconds()
        return round(total)


class _AppFront:
    """analyze's front interface (at(t)) for one app."""

    def __init__(self, front, pkgs):
        self.front, self.pkgs = front, pkgs

    def at(self, t, within=0.0):
        return self.front.at(self.pkgs, t, within)


# ---------------------------------------------------------------- the file trace

def _trace(path, pid_uid, groups, sync):
    """One pass over the f2fs trace (parse_filetrace's line format and TGID rule). The accesses of
    each app to other apps' install packages and data and to shared storage, as
    {uid: {(kind, key): [(ts, write, entry, pid)]}}; kind "apk" / "data" (key: the other package) or
    "shared" (key: the folder). unattributed: such accesses by processes of no app."""
    pf = parse_filetrace
    by_app = {}
    unattributed = 0
    events = 0
    marker = None
    pending, waiting = [], {}

    def account(owner, ts, write, entry):
        nonlocal unattributed
        uid = pid_uid.get(owner)
        g = groups.get(uid)
        parts = entry.split("/")
        kind, pkg = pf._shape(parts)
        shared = len(parts) > 2 and parts[1] == "media"
        if g is None:
            if (kind is not None or shared) and (uid is None or uid % 100000 >= FIRST_APP_UID):
                unattributed += 1       # not a system process's
            return
        own = g["packages"]
        if pkg in own or (kind is None and parts[1:2] != ["media"] and any(p in parts for p in own)):
            return
        if kind == "apk":
            if write:
                return
            key = ("apk", pkg)
        elif kind == "data":
            key = ("data", pkg)
        elif shared:
            key = ("shared", pf._display(entry).rpartition("/")[0])
        else:
            return
        by_app.setdefault(uid, {}).setdefault(key, []).append((ts, write, entry, int(owner)))

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pf._HEAD.match(line)
            if m is None:
                continue
            comm, tid, tgid, ts, ev, body = m.groups()
            if ev == pf.READ_EVENT:
                write = False
            elif ev == pf.WRITE_EVENT:
                write = True
            else:
                if marker is None and ev == "tracing_mark_write" and body.startswith("AW_SYNC "):
                    try:
                        token = body.split()[1]
                        marker = {"trace_ts": float(ts), "epoch": float(token), "approx": "." not in token}
                    except (IndexError, ValueError):
                        pass
                continue
            rest, sep, _ = body.rpartition(", i_size ")
            if not sep:
                continue
            rest, sep, epid = rest.rpartition(", pid ")
            if not sep:
                continue
            rest, sep, cmdline = rest.rpartition(", cmdline ")
            if not sep:
                continue
            rest, sep, _ = rest.rpartition(", offset ")
            if not sep or not rest.startswith("entry_name "):
                continue
            entry = rest[11:]
            t = float(ts)
            events += 1
            if tgid and tgid.isdigit():
                tgid = str(int(tgid))
                for p in waiting.pop(tid, ()):
                    if p[5] == cmdline and t - p[2] <= pf.SAME_THREAD_S:
                        p[6] = tgid
                account(tgid, t, write, entry)
            else:
                p = [tid, epid.strip(), t, write, entry, cmdline, None]
                pending.append(p)
                waiting.setdefault(tid, []).append(p)
    for tid, epid, t, write, entry, _, owner in pending:
        account(owner or (epid if epid.isdigit() else tid), t, write, entry)
    if marker is None and sync:
        marker = {"trace_ts": sync["trace_ts"], "epoch": sync["epoch"], "approx": bool(sync.get("approx"))}
    return {"events": events, "sync": marker, "by_app": by_app, "unattributed": unattributed}


def _file_facts(accesses, pkgs, front, wall, within):
    """EVENTs and detail rows of one app's file accesses. One EVENT per thing (another app's install
    package, another app's data, a shared folder) with count the accesses, as aw/overview.py reads
    these categories; front: False when any access was while the app was not in front, else True
    when any was while it was, else None. Its time is the first access in that state."""
    category = {"apk": "installed_apps", "data": "other_app_data", "shared": "photos"}
    events, rows = [], []
    for (kind, key), xs in sorted(accesses.items()):
        reads = writes = 0
        first = {}               # front state -> (ts, time)
        files, pids = set(), set()
        for ts, write, entry, pid in xs:
            d = wall(ts)
            top = front.at(pkgs, d, within) if d is not None else None
            if top not in first or ts < first[top][0]:
                first[top] = (ts, d)
            if write:
                writes += 1
            else:
                reads += 1
            files.add(parse_filetrace._display(entry))
            pids.add(pid)
        top = False if False in first else (True if True in first else None)
        time = _fmt(first[top][1])
        if kind == "apk":
            what = f"读取 {key} 的安装包"
        elif kind == "data":
            what = f"读写 {key} 的数据（读 {reads} 次、写 {writes} 次）"
        else:
            what = f"读写 {key} 里的文件（读 {reads} 次、写 {writes} 次）"
        # at_least: the trace sees reads of the phone's storage, not reads the system answers from memory
        events.append({"category": category[kind], "time": time, "what": what, "code": f"{kind} {key}",
                       "front": top, "denied": False, "count": reads + writes, "at_least": True})
        rows.append({"kind": kind, "target": key, "front": top, "first_time": time,
                     "first_time_by_state": {str(k): _fmt(v[1]) for k, v in first.items()},
                     "reads": reads, "writes": writes, "files": sorted(files), "pids": sorted(pids)})
    return events, rows


def _fmt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S.%f")[:23] if d is not None else None


# ---------------------------------------------------------------- per app

def _groups(packages, labels):
    """uid -> the app: its packages, the package it is named after, label, third_party."""
    by_uid = {}
    for p in packages:
        if p.get("uid") is not None and p["uid"] >= FIRST_APP_UID:
            by_uid.setdefault(p["uid"], []).append(p)
    groups = {}
    for uid, ps in by_uid.items():
        ps = sorted(ps, key=lambda p: (not p.get("third_party"), p["package"]))
        main = ps[0]["package"]
        groups[uid] = {"uid": uid, "package": main, "packages": frozenset(p["package"] for p in ps),
                       "label": (labels or {}).get(main), "third_party": bool(ps[0].get("third_party"))}
    return groups


def _op_events(occurrences, pkgs, front, overview):
    """EVENTs of one app's appops occurrences (the clipboard ones go with logcat's records). code is
    the operation name alone: aw/overview.py tells an operation from a thing by it. In front: the
    entry's uid state is top and the poll shows the app in front."""
    titles = {k: t for k, t, _ in overview.CATEGORIES}
    events = []
    for o in occurrences:
        if o["op"] in analyze.CLIP_OPS:
            continue
        cat = overview.category_of(o["op"])
        info = parse_appops.OP_INFO.get(o["op"])
        what = info["zh"] if info else ("一项其他权限" if cat == "other" else f"{titles.get(cat, '')}相关的一项权限")
        top = False if o["state"] != "top" else front.at(pkgs, o["time"])
        events.append({"category": cat, "time": o["time"], "what": what, "code": o["op"],
                       "front": top, "denied": o["kind"] == "reject", "count": 1, "at_least": True})
    return events


def _clipboard_events(lc, occurrences, app_front):
    """Clipboard reads: logcat's records joined with the appops samples (analyze._clipboard)."""
    occ = [{"op": o["op"], "kind": o["kind"], "time": o["time"],
            "background": o["state"] != "top" or app_front.at(o["time"]) is False}
           for o in occurrences if o["op"] == "READ_CLIPBOARD"]
    clip = analyze._clipboard((lc or {}).get("clipboard") or [], occ, app_front)
    events = []
    for e in clip["events"]:
        if e["op"] != "read":
            continue
        bg = e.get("background")
        events.append({"category": "clipboard", "time": e["time"], "what": "读取剪贴板", "code": "READ_CLIPBOARD",
                       "front": None if bg is None else not bg, "denied": e["result"] == "blocked",
                       "count": 1, "at_least": e["source"] == "appops"})
    return events


def _start_events(g, lc, poll_procs, first_block, front):
    """background_start EVENTs (analyze._processes' new_not_top) and the app's process rows. A start
    to show one of its screens is left out, as aw/overview.py does for one-app runs: that is the app
    being opened (fixtures/phone_1119: 3 such starts, each in front within 5 s)."""
    pkgs = g["packages"]
    starts = {int(s["pid"]): s for s in (lc or {}).get("proc_starts") or []}
    app_starts = {s["pid"]: s for s in (lc or {}).get("app_process_starts") or []}
    seen = {p["pid"]: p for p in poll_procs}
    events, rows = [], []
    for pid in sorted(set(seen) | set(starts) | set(app_starts)):
        p, s, a = seen.get(pid), starts.get(pid), app_starts.get(pid)
        name = (p or {}).get("name") or (s or {}).get("process") or ""
        t = (s or a or {}).get("time") or (_fmt(p["first_seen"])[:19] if p else None)
        rows.append({"pid": pid, "name": name, "ppid": (p or {}).get("ppid"),
                     "first_seen": _fmt(p["first_seen"])[:19] if p else None,
                     "last_seen": _fmt(p["last_seen"])[:19] if p else None,
                     "started_by": "system" if s else ("app" if a else None),
                     "start_time": (s or a or {}).get("time"), "reason": (s or {}).get("reason"),
                     "component": (s or {}).get("component"), "caller": (s or {}).get("caller"),
                     "main": (a or {}).get("main")})
        if not (s or a) and (p is None or p["first_seen"] == first_block):
            continue        # already running when the poll began, or no start time known
        if s and analyze.REASON_ZH.get(s.get("reason")) == "打开界面":
            continue
        if s and s.get("component") and s["component"].split("/")[0] not in pkgs:
            continue        # started for another app's component (WebView's sandboxed renderers): not this app's doing
        if t is None or front.at(pkgs, t) is not False:
            continue
        if s:
            c = s.get("caller") or {}
            who = ("它自己发出的" if c.get("package") in pkgs or c.get("uid") == g["uid"]
                   else f"{c['package']} 发出的" if c.get("package") else "")
            reason = analyze.REASON_ZH.get(s.get("reason"), "")
            what = f"系统启动了它的进程 {name}" + (f"，起因：{who}{reason or '请求'}" if who or reason else "")
            code = f"pid {pid}; {s.get('process')}; reason {s.get('reason')}; component {s.get('component')}; caller {c}"
        elif a:
            what = f"它自己运行了一个程序（{name}）" if name else "它自己运行了一个程序"
            code = f"pid {pid}; app_process; main {a.get('main')}"
        else:
            what = f"出现了它的新进程 {name}"
            code = f"pid {pid}; {name}"
        events.append({"category": "background_start", "time": t, "what": what, "code": code, "front": False,
                       "denied": False, "count": 1, "at_least": not (s or a)})
    return events, rows


def _split_ipport(s):
    ip, _, port = s.rpartition(":")
    return ip.strip("[]"), int(port)


def _host_of(pcap, flows, ip):
    """A server's name for one app: the name the app's own flows sent in their ClientHello; else the
    one name the capture's DNS answers give for the address. Another app's ClientHello to the same
    address, or an address DNS gives several names for, says nothing about this app's connection:
    shared CDN addresses serve several apps (fixtures/phone_1119: one address answered for ten names
    of two companies). Then the server stays without a name."""
    name = parse_net._top_name(flows)
    if name:
        return name
    names = set(((pcap or {}).get("dns") or {}).get(ip) or ())
    return names.pop() if len(names) == 1 else None


# ---------------------------------------------------------------- network

def _network(pcap, poll, keylog, groups, front, offset, clear=None):
    """Per app: the network facts, the requests (decrypted, and cleartext from clear: parse_cleartext's result)
    and detail rows; the run's counts; and the cleartext requests of no app.
    A connection is an app's when the S lines with its local address and port carry the app's uid:
    those to the same server, else any (a socket's local address and port name it while it is
    open). No S line, or S lines of several uids, leave it to no app."""
    sockets, locals_ = poll["sockets"], poll["locals"]

    def whose(proto, loc, remote):
        """the app's uid, "system", or None (no app: see above, or an isolated process's uid)"""
        s = sockets.get((proto, loc, remote))
        uids = s["uids"] if s is not None else locals_.get((proto, loc)) or set()
        if len(uids) != 1:
            return None
        uid = next(iter(uids))
        if uid in groups:
            return uid
        return "system" if uid % 100000 < FIRST_APP_UID else None

    def local(epoch):
        return _EPOCH + timedelta(seconds=epoch) + offset

    counts = Counter()
    conns = {}               # uid -> {(proto, remote): {local: [pcap flow | None, S record | None]}}
    for ekey, e in ((pcap or {}).get("endpoints") or {}).items():
        proto, remote = ekey.split(" ", 1)
        for fl in e["flows"]:
            w = whose(proto, fl["local"], remote)
            cls = "app" if isinstance(w, int) else (w or "unattributed")
            counts[f"flows_{cls}"] += 1
            counts[f"bytes_{cls}"] += fl["bytes_out"] + fl["bytes_in"]
            if cls == "unattributed" and remote.endswith(":53"):
                counts["flows_unattributed_dns"] += 1
            if isinstance(w, int):
                conns.setdefault(w, {}).setdefault((proto, remote), {})[fl["local"]] = [
                    fl, sockets.get((proto, fl["local"], remote))]
    # connections the poll saw that carried no packet in the capture (or there is no capture)
    for (proto, loc, remote), s in sockets.items():
        w = whose(proto, loc, remote)
        if isinstance(w, int):
            conns.setdefault(w, {}).setdefault((proto, remote), {}).setdefault(loc, [None, s])

    conn_of, class_of = {}, {}
    for c in (keylog or {}).get("connections") or []:
        w = whose("tcp", parse_net._norm_ipport(c["client"]), parse_net._norm_ipport(c["server"]))
        cls = "app" if isinstance(w, int) else (w or "unattributed")
        conn_of[c["id"]] = w if isinstance(w, int) else None
        class_of[c["id"]] = cls
        counts[f"tls_{cls}"] += 1
        if c.get("decrypted"):
            counts[f"decrypted_{cls}"] += 1
    tls_of = {}
    for c in (keylog or {}).get("connections") or []:
        if conn_of[c["id"]] is not None:
            tls_of.setdefault(conn_of[c["id"]], []).append(c)

    out = {}
    for uid, eps in conns.items():
        pkgs = groups[uid]["packages"]
        endpoints, rows, quic = [], [], 0
        for (proto, remote), locs in sorted(eps.items()):
            ip, port = _split_ipport(remote)
            fls = [fl for fl, _ in locs.values() if fl is not None]
            host = _host_of(pcap, fls, ip)
            states = set()
            for loc, (fl, s) in sorted(locs.items()):
                if fl is not None:
                    states |= front.over(pkgs, local(fl["first_epoch"]), local(fl["last_epoch"]))
                else:
                    states |= front.over(pkgs, s["first_seen"], s["last_seen"])
                rows.append({"proto": proto, "local": loc, "remote": remote, "host": host,
                             "sni": fl["sni"] if fl else None,
                             "bytes_out": fl["bytes_out"] if fl else 0, "bytes_in": fl["bytes_in"] if fl else 0,
                             "first_packet": _fmt(local(fl["first_epoch"])) if fl else None,
                             "last_packet": _fmt(local(fl["last_epoch"])) if fl else None,
                             "first_seen": _fmt(s["first_seen"])[:19] if s else None,
                             "last_seen": _fmt(s["last_seen"])[:19] if s else None})
            if proto == "udp" and port == 443:
                quic += len(locs)
            endpoints.append({"host": host, "address": remote, "connections": len(locs),
                              "bytes": sum(fl["bytes_out"] + fl["bytes_in"] for fl in fls),
                              "front": True in states, "background": False in states})
        endpoints.sort(key=lambda e: (-e["bytes"], -e["connections"], e["host"] or "", e["address"]))
        tls = tls_of.get(uid) or []
        if keylog is not None:
            not_decrypted = sum(1 for c in tls if not c.get("decrypted")) + quic
        else:
            not_decrypted = sum(1 for r in rows if r["sni"] or r["remote"].endswith(":443"))
        out[uid] = {"network": {"endpoints": endpoints, "connections": sum(e["connections"] for e in endpoints),
                                "bytes": sum(e["bytes"] for e in endpoints), "not_decrypted": not_decrypted},
                    "connections": rows,
                    "tls": [{k: c.get(k) for k in ("id", "client", "server", "sni", "tls", "handshake_seen", "key",
                                                    "decrypted", "protocol", "exchanges")} for c in tls],
                    "requests": []}
    for x in (keylog or {}).get("exchanges") or []:
        uid = conn_of.get(x.get("connection"))
        counts[f"requests_{class_of.get(x.get('connection'), 'unattributed')}"] += 1
        if uid is not None:
            out.setdefault(uid, {"network": {"endpoints": [], "connections": 0, "bytes": 0, "not_decrypted": 0},
                                 "connections": [], "tls": [], "requests": []})
            out[uid]["requests"].append({**x, "front": front.at(groups[uid]["packages"], x.get("time"))})
    # Cleartext HTTP: its connections are attributed as every other (cleartext ids are tcp.stream numbers too,
    # distinct from the TLS ones).
    clear_of, nobody = {}, []
    for c in (clear or {}).get("connections") or []:
        w = whose("tcp", parse_net._norm_ipport(c["client"]), parse_net._norm_ipport(c["server"]))
        clear_of[c["id"]] = w if isinstance(w, int) else ("system" if w == "system" else None)
    for x in (clear or {}).get("exchanges") or []:
        w = clear_of.get(x.get("connection"))
        counts[f"cleartext_{'app' if isinstance(w, int) else w or 'unattributed'}"] += 1
        if isinstance(w, int):
            out.setdefault(w, {"network": {"endpoints": [], "connections": 0, "bytes": 0, "not_decrypted": 0},
                               "connections": [], "tls": [], "requests": []})
            out[w]["requests"].append({**x, "front": front.at(groups[w]["packages"], x.get("time"))})
        elif w is None:
            nobody.append(x)
    for n in out.values():
        n["requests"].sort(key=lambda x: x.get("time") or "")
    return out, counts, nobody


# ---------------------------------------------------------------- the run

def analyze_phone(run_dir, out_dir=None, labels=None) -> dict:
    """Reads a phone run, writes overview.json and each app's downloads, returns the overview."""
    from aw import collect, overview

    run_dir = Path(run_dir)
    out = Path(out_dir) if out_dir is not None else run_dir
    out.mkdir(parents=True, exist_ok=True)
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    start, end = meta["start_time"], meta["end_time"]
    offset = analyze._utc_offset(meta.get("utc_offset"))
    missing = []

    groups = _groups(collect.read_packages(run_dir), labels)

    poll = _read_poll(run_dir / "poll.txt") if (run_dir / "poll.txt").exists() else None
    if poll is None:
        missing.append("poll.txt")
        poll = {"times": [], "tops": [], "procs": {}, "sockets": {}, "locals": {}}
    front = _Front(poll["times"], poll["tops"])
    first_block = poll["times"][0] if poll["times"] else None

    lc_by_uid, pid_map = {}, {}
    if (run_dir / "logcat.txt").exists():
        lc_by_uid, pid_map = _logcat(run_dir / "logcat.txt", groups, int(start[:4]))
    else:
        missing.append("logcat.txt")

    # pid -> uid: the poll first, then logcat's starts, then ps; a pid the poll saw under two uids is no one's
    pid_uid, poll_uids = {}, {}
    for (pid, uid) in poll["procs"]:
        poll_uids.setdefault(pid, set()).add(uid)
    for pid, uids in poll_uids.items():
        if len(uids) == 1:
            pid_uid[str(pid)] = next(iter(uids))
    for pid, e in pid_map.items():
        uid = parse_logcat._uid_info(e.get("app_id") or "")[0]
        if uid is not None and int(pid) not in poll_uids:
            pid_uid.setdefault(str(int(pid)), uid)
    for name in ("ps_before.txt", "ps_after.txt"):
        if (run_dir / name).exists():
            for r in analyze._parse_ps(run_dir / name):
                uid = _ps_uid(r["user"])
                if uid is not None:
                    pid_uid.setdefault(str(r["pid"]), uid)

    ops_by_uid, samples = _appops(run_dir, start, end, missing)

    files = None
    if meta.get("filetrace_backend", "none") == "f2fs":
        if (run_dir / "filetrace_f2fs.txt").exists():
            files = _trace(run_dir / "filetrace_f2fs.txt", pid_uid, groups, meta.get("trace_sync"))
        else:
            missing.append("filetrace_f2fs.txt")
    sync = (files or {}).get("sync")
    within = TRACE_CLOCK_S if (sync or {}).get("approx") else 0.0

    def wall(ts):
        if sync is None:
            return None
        return _EPOCH + timedelta(seconds=sync["epoch"] + ts - sync["trace_ts"]) + offset

    pcap = None
    if (run_dir / "net.pcap").exists():
        try:
            pcap = parse_net.parse_pcap(run_dir / "net.pcap")
        except ValueError:
            missing.append("net.pcap")
    else:
        missing.append("net.pcap")
    keylog = keylog_error = clear = clear_error = None
    if (run_dir / "tls_keys.log").exists() and pcap is not None:
        from aw import parse_keylog
        try:
            keylog = parse_keylog.parse_keylog(run_dir / "net.pcap", run_dir / "tls_keys.log",
                                               utc_offset=meta.get("utc_offset", "+0000"))
            clear = keylog.get("cleartext")
        except parse_keylog.KeylogError as e:
            keylog_error = clear_error = str(e)
    elif (run_dir / "net.pcap").exists():     # cleartext HTTP needs no key: a tshark run of its own
        from aw import parse_keylog
        try:
            clear = parse_keylog.parse_cleartext(run_dir / "net.pcap", utc_offset=meta.get("utc_offset", "+0000"))
        except parse_keylog.KeylogError as e:
            clear_error = str(e)
    net, counts, clear_nobody = _network(pcap, poll, keylog, groups, front, offset, clear)

    procs_by_uid = {}
    for (pid, uid), p in poll["procs"].items():
        procs_by_uid.setdefault(uid, []).append(p)

    facts_list, details, system_ops = [], {}, 0
    for uid, occ in ops_by_uid.items():
        if uid is None or uid % 100000 < FIRST_APP_UID:
            system_ops += len(occ)
    for uid, g in sorted(groups.items()):
        pkgs = g["packages"]
        occ = ops_by_uid.get(uid) or []
        events = _op_events(occ, pkgs, front, overview)
        events += _clipboard_events(lc_by_uid.get(uid), occ, _AppFront(front, pkgs))
        starts, proc_rows = _start_events(g, lc_by_uid.get(uid), procs_by_uid.get(uid) or [], first_block, front)
        events += starts
        file_rows = []
        if files is not None and uid in files["by_app"]:
            fe, file_rows = _file_facts(files["by_app"][uid], pkgs, front, wall, within)
            events += fe
        n = net.get(uid) or {}
        network = n.get("network") or {"endpoints": [], "connections": 0, "bytes": 0, "not_decrypted": 0}
        requests = n.get("requests") or []
        if not (events or network["endpoints"] or requests):
            continue
        events.sort(key=lambda e: (e["time"] or "", e["category"]))
        facts = {"package": g["package"], "uid": uid, "label": g["label"], "third_party": g["third_party"],
                 "events": events, "network": network, "requests": requests}
        facts_list.append(facts)
        details[g["package"]] = {
            "format": 1, "package": g["package"], "packages": sorted(pkgs), "uid": uid, "label": g["label"],
            "third_party": g["third_party"], "events": events, "network": network,
            "permissions": occ, "processes": proc_rows, "files": file_rows,
            "connections": n.get("connections") or [], "tls_connections": n.get("tls") or [],
            "requests": [{"time": x.get("time"), "method": x.get("method"), "scheme": x.get("scheme"),
                          "host": x.get("host"), "path": x.get("path"),
                          "status": (x.get("response") or {}).get("status"),
                          "connection": x.get("connection"), "front": x["front"]} for x in requests]}

    # An app whose only facts are operations the overview leaves out (wake locks and the like) has no bar.
    apps = overview.rank([a for a in map(overview.build_app, facts_list) if a["bars"]])
    by_pkg = {f["package"]: f for f in facts_list}
    for app in apps:
        app["downloads"] = overview.write_downloads(out, app["package"], details[app["package"]],
                                                    by_pkg[app["package"]]["requests"])

    dev = meta.get("device") or {}
    name = " ".join(x for x in (dev.get("brand"), dev.get("model")) if x)
    seconds = (meta["end_epoch"] - meta["start_epoch"] if "start_epoch" in meta and "end_epoch" in meta
               else round((analyze._dt(end) - analyze._dt(start)).total_seconds()))
    result = {"format": 1,
              "run": {"id": run_dir.name, "scope": "phone", "package": None,
                      "device": name + (f" · Android {dev['android']}" if dev.get("android") else ""),
                      "start_time": start, "end_time": end, "seconds": seconds,
                      "net": bool(pcap and pcap.get("packets")),
                      "decrypt": bool(counts["decrypted_app"] + counts["decrypted_system"]
                                      + counts["decrypted_unattributed"])},
              "apps": apps,
              "cleartext": overview.cleartext_summary(
                  facts_list, clear is not None,
                  None if clear is not None else (clear_error or "没有抓包。"),
                  clear_nobody, counts["cleartext_system"]),
              "limits": _limits(meta, missing, groups, len(apps), counts, keylog, keylog_error, samples, files,
                                front, system_ops, clear, clear_error)}
    (out / "overview.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


def _limits(meta, missing, groups, listed, counts, keylog, keylog_error, samples, files, front, system_ops,
            clear=None, clear_error=None):
    limits = [f"手机上共有 {len(groups)} 个应用（包括系统自带的），其中 {len(groups) - listed} 个在这次采集中"
              "没有用权限、读你的信息或者联网（防休眠、振动这类不算），没有列出。"]
    if "poll.txt" in missing:
        limits.append("没有轮询记录（poll.txt）：不知道你什么时候在用哪个应用，进程和网络连接也对不上应用。")
    else:
        limits.append("手机上的进程和网络连接大约每秒查看一次：只存在不到 1 秒的进程和连接可能没有看到。")
        unknown = front.unknown_seconds(analyze._dt(meta["end_time"]))
        if unknown:
            limits.append(f"有约 {unknown} 秒不知道你在用哪个应用（没有记录到屏幕上的界面，可能是屏幕关着），"
                          "这段时间算作所有应用都在后台。")
    system = []
    if system_ops:
        system.append(f"{system_ops} 次权限使用")
    if counts["flows_system"]:
        system.append(f"{counts['flows_system']} 个网络连接")
    if counts["requests_system"]:
        system.append(f"解密出的 {counts['requests_system']} 个请求")
    if counts["cleartext_system"]:
        system.append(f"没加密的 {counts['cleartext_system']} 个请求")
    if system:
        limits.append("系统本身（不属于任何应用的系统程序）做的事没有算到应用上，也没有列出："
                      + "、".join(system) + "。")
    if counts["flows_unattributed"]:
        kb = counts["bytes_unattributed"] / 1024
        dns = counts["flows_unattributed_dns"]
        limits.append(f"抓包里有 {counts['flows_unattributed']} 个网络连接（约 {kb:.0f} KB）不知道是哪个应用的"
                      + (f"，其中 {dns} 个是查询网站地址的域名查询（通常由系统代应用发出）" if dns else "")
                      + "：很快就结束的连接可能在两次查看之间没被看到，这些连接没有算到任何应用上。")
    if "net.pcap" in missing:
        limits.append("这次没有抓包：没有网络连接的流量和服务器名称。" if meta.get("net") is False
                      else "没有抓包文件（net.pcap），或者它的格式读不了：没有网络连接的流量和服务器名称。")
    if keylog is not None:
        dec = counts["decrypted_app"] + counts["decrypted_system"] + counts["decrypted_unattributed"]
        if counts["decrypted_unattributed"]:
            limits.append(f"解开了 {dec} 个加密连接，其中 {counts['decrypted_unattributed']} 个不知道是哪个应用的，"
                          f"里面的 {counts['requests_unattributed']} 个请求没有算到任何应用上。")
        limits.append("解密只能解开采集开始以后新建立、并且用手机系统自带的加密功能建立的连接：采集开始前就已连上的、"
                      "应用用自己的加密功能建立的、走 UDP 的（QUIC）连接，内容都看不到。")
    elif keylog_error:
        limits.append(f"没能解密抓包（{keylog_error.rstrip('。')}）：这次没有解密的内容。")
    elif meta.get("decrypt") == "keylog":
        limits.append("要求了解密，但没有记录到密钥（tls_keys.log）：这次没有解密的内容。")
    if clear is not None:
        if counts["cleartext_unattributed"]:
            limits.append(f"抓包里有 {counts['cleartext_unattributed']} 个没加密的请求不知道是哪个应用发的："
                          "很快就结束的连接可能在两次查看之间没被看到，这些请求没有算到任何应用上。")
        limits.append("没加密的请求（明文 HTTP）是直接从抓包里读出来的，不需要解密：只认得出 HTTP，别的没加密的内容没有列出；"
                      "采集开始前就已连上的连接，只从抓到的第一个完整请求读起。")
    elif clear_error:
        limits.append(f"没能检查哪些请求没加密（{clear_error.rstrip('。')}）。")
    if samples:
        limits.append("权限的使用情况大约每 10 秒查看一次：两次查看之间同一项权限用了多次，只能看出一次，"
                      "所以写的是“至少”多少次。")
    elif "appops_all.txt.gz" in missing:
        limits.append("没有每 10 秒一次的权限记录（appops_all.txt.gz）：权限使用只来自采集开始和结束时的两次查看，"
                      "每项权限最多只看得到最后一次。")
    if "appops_after.txt" in missing and not samples:
        limits.append("没有采集结束时的权限记录（appops_after.txt）：看不到权限使用。")
    if "logcat.txt" in missing:
        limits.append("没有系统日志（logcat.txt）：看不到进程是因为什么启动的，也没有剪贴板记录。")
    if files is None:
        limits.append("这次没有跟踪文件访问：看不到应用读写了哪些文件。")
    else:
        limits.append("文件的读写只记录得到真正读写手机存储的那些，系统已经放在内存里的内容再读一次是看不到的，"
                      "所以写的是“至少”。")
    if files is not None and files["unattributed"]:
        limits.append(f"文件跟踪里有 {files['unattributed']} 次对照片和文件、或应用目录的访问，来自系统程序或"
                      "没有对上任何应用的程序，没有算到应用上。")
    if meta.get("autostop") in analyze.AUTOSTOP_ZH:
        limits.append(analyze.AUTOSTOP_ZH[meta["autostop"]].format(t=analyze._hms(meta["end_time"])))
    return limits
