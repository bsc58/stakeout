"""Parse the system-wide f2fs file trace (ftrace trace_pipe text) and sort the
app's file accesses into own files, other apps' install packages, other apps'
data, public shared storage and system files.

One streaming pass. An event whose TGID column is unknown (``-------``) comes
from a thread whose TGID the kernel had not recorded yet when the line was
formatted; it is recorded at the thread's next context switch, so the same
thread's next lines carry it. Such an event takes the TGID of the next
known-TGID line of its TID, but only when that line is evidently the same
thread: same thread name (event ``cmdline``) and at most ``SAME_THREAD_S``
later. TIDs are reused within minutes on a busy phone (pid_max 32768), so a
later line of the same TID can belong to another process. Otherwise the
event's ``pid`` (the TID) is used, as the contract says.
"""
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

# comm-TID (TGID) [cpu] flags seconds: event: body
# The TGID column exists only with options/record-tgid, the flags column only
# with irq-info; both are optional here so that a trace without them still parses.
_HEAD = re.compile(
    r"\s*(.*?)-(\d+)\s+(?:\(\s*([^)]*?)\s*\)\s+)?\[\d+\]\s+(?:\S+\s+)?(\d+\.\d+):\s+(\w+):\s?(.*)"
)
_OFFSET = re.compile(r"([+-])(\d\d):?(\d\d)$")

READ_EVENT = "f2fs_dataread_start"
WRITE_EVENT = "f2fs_datawrite_start"
SAME_THREAD_S = 10.0


def _tz(utc_offset):
    m = _OFFSET.search(utc_offset.strip())
    sign = -1 if m.group(1) == "-" else 1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def _display(path):
    """entry_name (relative to the /data mount) -> path as the user knows it."""
    parts = path.split("/", 3)
    if len(parts) > 2 and parts[1] == "media" and parts[2].isdigit():
        base = "/sdcard" if parts[2] == "0" else "/storage/emulated/" + parts[2]
        return base + ("/" + parts[3] if len(parts) > 3 else "")
    return "/data" + path


def _shape(parts):
    """("apk"|"data", package) for an app's install or data directory, else (None, None)."""
    top = parts[1] if len(parts) > 1 else ""
    n = len(parts)
    if top == "app" and n > 3:
        i = 3 if parts[2].startswith("~~") else 2
        if n > i + 1 and "-" in parts[i]:
            return "apk", parts[i].split("-", 1)[0]
    elif top == "data" and n > 3:
        return "data", parts[2]
    elif top in ("user", "user_de") and n > 4 and parts[2].isdigit():
        return "data", parts[3]
    elif (top == "media" and n > 6 and parts[2].isdigit() and parts[3] == "Android"
          and parts[4] in ("data", "media", "obb")):
        return "data", parts[5]
    return None, None


def parse_f2fs_trace(path, package: str, target_pids: set[int], pid_names: dict | None = None,
                     sync: dict | None = None, utc_offset: str = "+0000") -> dict:
    targets = {str(int(p)) for p in target_pids}
    pid_names = pid_names or {}

    events = 0
    first_ts = last_ts = None
    marker = None
    pending = []            # [tid, epid, comm, t, write, entry, cmdline, tgid|None] with an unknown TGID
    waiting = {}            # tid -> pending entries not yet matched with a later known-TGID line

    acc = {
        "target": 0,
        "own_r": 0, "own_w": 0,
        "apks": {},        # pkg -> [reads, first_ts, set(pids)]
        "data": {},        # pkg -> [reads, writes, [paths]]
        "shared": {},      # dir -> [reads, writes, [files]]
        "sys_r": 0, "sys_w": 0, "sys_top": Counter(),
        "procs": {},       # pid -> [reads, writes, first ts]
        "comm": {},        # pid -> thread name of its main thread (or first seen)
    }

    def account(owner, tid, comm, ts, write, entry):
        if owner not in targets:
            return False
        acc["target"] += 1
        pr = acc["procs"].get(owner)
        if pr is None:
            pr = acc["procs"][owner] = [0, 0, ts]
        pr[write] += 1
        if ts < pr[2]:
            pr[2] = ts
        if comm != "<...>" and (tid == owner or owner not in acc["comm"]):
            acc["comm"][owner] = comm

        parts = entry.split("/")
        kind, pkg = _shape(parts)
        # A folder named after the package in public storage (/media/0/Download/<pkg>/)
        # is still public storage; the app's own storage there is Android/{data,media,obb}.
        if pkg == package or (kind is None and package in parts and parts[1:2] != ["media"]):
            if write:
                acc["own_w"] += 1
            else:
                acc["own_r"] += 1
        elif kind == "apk" and not write:
            a = acc["apks"].get(pkg)
            if a is None:
                acc["apks"][pkg] = [1, ts, {int(owner)}]
            else:
                a[0] += 1
                if ts < a[1]:
                    a[1] = ts
                a[2].add(int(owner))
        elif kind == "data":
            d = acc["data"].get(pkg)
            if d is None:
                d = acc["data"][pkg] = [0, 0, []]
            d[1 if write else 0] += 1
            shown = _display(entry)
            if len(d[2]) < 5 and shown not in d[2]:
                d[2].append(shown)
        elif len(parts) > 2 and parts[1] == "media":
            shown = _display(entry)
            folder, _, _ = shown.rpartition("/")
            s = acc["shared"].get(folder)
            if s is None:
                s = acc["shared"][folder] = [0, 0, []]
            s[1 if write else 0] += 1
            if len(s[2]) < 10 and shown not in s[2]:
                s[2].append(shown)
        else:
            if write:
                acc["sys_w"] += 1
            else:
                acc["sys_r"] += 1
            acc["sys_top"][_display(entry)] += 1
        return True

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _HEAD.match(line)
            if m is None:
                continue
            comm, tid, tgid, ts, ev, body = m.groups()
            if ev == READ_EVENT:
                write = False
            elif ev == WRITE_EVENT:
                write = True
            else:
                if marker is None and ev == "tracing_mark_write" and body.startswith("AW_SYNC "):
                    try:
                        token = body.split()[1]
                        # A whole-second epoch (`date +%s`) is truncated before the marker
                        # is written: times derived from it are up to 1 s early.
                        marker = {"trace_ts": float(ts), "epoch": float(token),
                                  "approx": "." not in token, "source": "marker"}
                    except (IndexError, ValueError):
                        pass
                continue

            # entry_name <path>, offset N, bytes N, cmdline <thread>, pid N, i_size N, ino N
            # Parsed from the right: paths and thread names may contain ", ".
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
            if first_ts is None:
                first_ts = t
            last_ts = t

            if tgid and tgid.isdigit():
                tgid = str(int(tgid))
                for p in waiting.pop(tid, ()):
                    if p[6] == cmdline and t - p[3] <= SAME_THREAD_S:
                        p[7] = tgid
                account(tgid, tid, comm, t, write, entry)
            else:
                p = [tid, epid.strip(), comm, t, write, entry, cmdline, None]
                pending.append(p)
                waiting.setdefault(tid, []).append(p)

    resolved = attributed = 0
    for tid, epid, comm, t, write, entry, _, owner in pending:
        if owner is None:
            owner = epid if epid.isdigit() else tid
        else:
            resolved += 1
        if account(owner, tid, comm, t, write, entry):
            attributed += 1

    used_sync = marker
    if used_sync is None and sync:
        used_sync = {"trace_ts": sync["trace_ts"], "epoch": sync["epoch"],
                     "approx": bool(sync.get("approx", False)), "source": "meta"}
    tz = _tz(utc_offset)

    def wall(ts):
        if used_sync is None:
            return None
        d = datetime.fromtimestamp(used_sync["epoch"] + (ts - used_sync["trace_ts"]), tz)
        return d.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % (d.microsecond // 1000)

    # name: the process name analyze knows (None when it knows none); thread: the trace's
    # 15-character thread name of its main thread, which a process can set to anything.
    by_process = [{"pid": int(p), "name": pid_names.get(int(p), pid_names.get(p)), "thread": acc["comm"].get(p),
                   "reads": r, "writes": w, "first_ts": t}
                  for p, (r, w, t) in acc["procs"].items()]
    by_process.sort(key=lambda x: (-(x["reads"] + x["writes"]), x["pid"]))

    return {
        "events": events,
        "target_events": acc["target"],
        "first_ts": first_ts,
        "last_ts": last_ts,
        "sync": used_sync,
        "tgid_unknown": {"events": len(pending), "resolved": resolved, "target": attributed},
        "own": {"reads": acc["own_r"], "writes": acc["own_w"]},
        "other_app_apks": [
            {"package": p, "reads": a[0], "first_time": wall(a[1]), "first_ts": a[1],
             "pids": sorted(a[2])}
            for p, a in sorted(acc["apks"].items())
        ],
        "other_app_data": [
            {"package": p, "reads": d[0], "writes": d[1], "paths": d[2]}
            for p, d in sorted(acc["data"].items())
        ],
        "shared_storage": [
            {"dir": k, "reads": s[0], "writes": s[1], "files": s[2]}
            for k, s in sorted(acc["shared"].items())
        ],
        "system": {"reads": acc["sys_r"], "writes": acc["sys_w"],
                   "top": [[p, n] for p, n in acc["sys_top"].most_common(15)]},
        "by_process": by_process,
    }
