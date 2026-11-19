"""Parse `logcat -b all -v threadtime [-v year]` output for one app.

Recognised line families (ColorOS 15 / Android 15, also AOSP):

* process starts: ``ActivityManager: Start proc PID:NAME/UID for TYPE {COMPONENT}``
  and the events-buffer twin ``am_proc_start: [user,pid,uid,name,type,{component},{extras}]``
  (ColorOS adds ``{ callingPackage = …, callingUid = …, callingAction = … }``).
* process kills: ``ActivityManager: Killing PID:NAME/UID (adj N): REASON``,
  ``am_kill : [user,pid,name,adj,reason(,rss)]`` and lmkd
  ``lowmemorykiller: Kill 'NAME' (PID), uid N, …; reason: …``.
* process deaths: ``ActivityManager: Process NAME (pid N) has died: STATE``
  and ``am_proc_died: [user,pid,name,adj,procstate]``. A death that follows a kill line is part of
  that kill; the others (crash, exit, killed by the app itself) go to ``proc_deaths``, not ``proc_kills``.
* activity starts: ``ActivityTaskManager: START u0 {intent} with MODE from uid N …``.
* clipboard: ``ClipboardService: clipboardAccessAllowed: op=29 result=true callingPackage=P``,
  ``ClipboardService: op = 29Denying clipboard access to P, …``,
  ``ClipboardService: Could not grant permission to primary clip. Clearing clipboard. …`` and
  ``ClipboardService-Controller: return empty clip for: UID because: REASON``.
  When the clip changes, ClipboardService checks access once per registered change listener, in a
  tight loop on the thread that changed it. Those checks name the listening apps but are not reads:
  they go to ``clipboard_notify``, not ``clipboard``. Checks of one op within CHECK_BURST_S of each
  other are one ``clipboard`` event; its ``checks`` key says how many lines it stands for. A read
  blocked by a ``return empty clip`` line carries that line as ``block_raw``.
* processes the app starts itself with ``app_process`` (no ActivityManager line):
  ``AndroidRuntime: >>>>>> START com.android.internal.os.RuntimeInit uid N <<<<<<`` in the new
  process (its pid in the PID column), then ``AndroidRuntime: Calling main entry <class>``.
* screen on / off: events-buffer ``screen_toggled: 1`` / ``screen_toggled: 0``.
"""

import os
import re
import time
from datetime import datetime, timedelta

_HEAD = re.compile(
    r"^(?:(\d{4})-)?(\d\d)-(\d\d) (\d\d:\d\d:\d\d(?:\.\d+)?)\s+(\d+)\s+(\d+)\s+[VDIWEFAS] (.*)$")

_START_PROC = re.compile(r"^Start proc (\d+):([^/\s]+)/(\S+?)(?: \[[^\]]*\])? for (.*)$")
_KILLING = re.compile(r"^Killing (\d+):([^/\s]+)/(\S+) \(adj (-?\d+)\): (.*)$")
_DIED = re.compile(r"^Process (\S+) \(pid (\d+)\) has died: ?(.*)$")
_LMK = re.compile(r"^Kill '([^']*)' \((\d+)\), uid (\d+), oom_score_adj (-?\d+)(?:.*?; reason: (.*))?")
_START_ACT = re.compile(r"^START u\d+ \{")
_FROM_UID = re.compile(r"\bfrom uid (\d+)")
_CLIP_ALLOWED = re.compile(r"^clipboardAccessAllowed: op=(\d+) result=(\w+) callingPackage=(\S+)")
_CLIP_DENYING = re.compile(r"^(?:op = (\d+))?Denying clipboard access to ([^,\s]+),")
_CLIP_EMPTY = re.compile(r"^return empty clip for: (\d+) because: (.*)$")
_CLIP_CLEARING = "Could not grant permission to primary clip"
_RUNTIME_INIT = re.compile(r"^>>>>>> START com\.android\.internal\.os\.RuntimeInit uid (\d+) <<<<<<")
_MAIN_ENTRY = re.compile(r"^Calling main entry (\S+)")
_UIDSTR = re.compile(r"^u(\d+)(ai|a|s|i)(\d+)(?:i(\d+))?$")

CLIP_OPS = {"29": "read", "30": "write"}
BLOCK_WINDOW_S = 1.0
CHECK_BURST_S = 0.1      # access checks this close together are one clipboard access
_RESULT_RANK = ["blocked", "unknown", "allowed"]   # a burst takes the first of these any of its checks has
LISTENER_GAP_S = 0.002   # successive checks of one listener loop; real reads on one thread are further apart
KILL_MERGE_S = 5         # Killing + am_kill (+ lmkd) lines of one kill
DEATH_WINDOW_S = 10      # am_proc_died + "has died" of one death, and a death after its kill


def _uid_info(s):
    """`1000`, `u0a378`, `u0i573`, `u0ai5`, `u0a382i572` -> (uid, owner app uid or None)."""
    if s.isdigit():
        return int(s), int(s)
    m = _UIDSTR.match(s)
    if not m:
        return None, None
    user, kind, num, iso = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4)
    base = user * 100000
    if kind == "a":
        owner = base + 10000 + num
        return (base + 99000 + int(iso) if iso else owner), owner
    if kind == "s":
        return base + num, base + num
    if kind == "i":
        return base + 99000 + num, None
    return base + 90000 + num, None      # "ai": app-zygote isolated


def _owner_of(num_uid):
    """Owning app uid of a numeric uid; isolated uids (app id 90000-99999) carry none."""
    return num_uid if (num_uid % 100000) < 90000 else None


def _format_uid(uid):
    """Inverse of _uid_info for a numeric uid (UserHandle.formatUid)."""
    if uid < 10000:
        return str(uid)
    user, app = divmod(uid, 100000)
    if 99000 <= app <= 99999:
        return f"u{user}i{app - 99000}"
    if 90000 <= app < 99000:
        return f"u{user}ai{app - 90000}"
    if app >= 10000:
        return f"u{user}a{app - 10000}"
    return f"u{user}s{app}"


def _split_tag(rest):
    i = rest.find(": ")
    if i < 0:
        return rest.strip(), ""
    return rest[:i].strip(), rest[i + 2:]


def _braced(s, start):
    """Content of the balanced {...} beginning at s[start] == '{', or None if unterminated."""
    depth = 0
    for i in range(start, len(s)):
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[start + 1:i], i + 1
    return None, None


def _intent_fields(body):
    """Top-level `key=value` tokens of Intent.toShortString(), ignoring nested sel={…}."""
    tokens, cur, depth = [], [], 0
    for c in body:
        if c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        if c == " " and depth == 0:
            tokens.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    tokens.append("".join(cur))
    out = {}
    for t in tokens:
        k, sep, v = t.partition("=")
        if sep and k and k not in out:
            out[k] = v
    return out


def _event_fields(msg):
    """`[a,b,{c,d},e]` -> ['a','b','{c,d}','e'] (commas inside braces kept)."""
    body = msg.strip()
    if body.startswith("["):
        body = body[1:]
    if body.endswith("]"):
        body = body[:-1]
    out, cur, depth = [], [], 0
    for c in body:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return out


def _caller(extras):
    """ColorOS am_proc_start extras `{ callingPackage = x, callingUid = 1, callingAction = y }`."""
    e = extras.strip()
    if not (e.startswith("{") and e.endswith("}")):
        return None
    kv = {}
    for part in e[1:-1].split(","):
        k, sep, v = part.partition("=")
        if sep:
            kv[k.strip()] = v.strip()
    if not kv:
        return None
    uid = kv.get("callingUid")
    return {"package": kv.get("callingPackage"),
            "uid": int(uid) if uid and uid.isdigit() else None,
            "action": kv.get("callingAction")}


def _component_of(s):
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]
    return s if s and s != "NULL" else None


def _ts(t):
    return datetime.strptime(t[:23].ljust(23, "0") if "." in t else t + ".000", "%Y-%m-%d %H:%M:%S.%f")


def _owns_name(package, process):
    return process == package or process.startswith(package + ":")


def _listener_checks(clip_lines):
    """Indices into clip_lines of the access checks made while notifying clipboard listeners.

    clip_lines: (time, (pid, tid), package, op, result, raw) in file order; op "change" marks
    "Could not grant permission to primary clip. Clearing clipboard.". After a change (that line or
    a write check) the read checks that follow on the same thread, each within LISTENER_GAP_S of the
    previous line, are the listener loop. The change is not always logged (AOSP logs only denials,
    the timed clear logs nothing), so a run of read checks naming two or more packages without a
    change line is taken as a listener loop too.
    """
    listener, runs, cur = set(), [], {}
    gap = timedelta(seconds=LISTENER_GAP_S)
    for i, (t, key, pkg, op, _res, _raw) in enumerate(clip_lines):
        dt = _ts(t)
        run = cur.get(key)
        if run is None or abs(dt - run["last"]) > gap:
            run = cur[key] = {"last": dt, "changed": False, "reads": []}
            runs.append(run)
        run["last"] = dt
        if op != "read":
            run["changed"] = True
        elif run["changed"]:
            listener.add(i)
        else:
            run["reads"].append(i)
    for run in runs:
        if not run["changed"] and len({clip_lines[i][2] for i in run["reads"]}) >= 2:
            listener.update(run["reads"])
    return listener


def _complete_lines(path):
    """Lines without their ending, read one at a time; a last line without "\\n" was cut off and is dropped."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="\n") as f:
        for line in f:
            if not line.endswith("\n"):
                return
            yield line[:-1].rstrip("\r")


def parse_logcat(path, package: str, uid: int, year: int | None = None) -> dict:
    if year is None:
        year = time.localtime(os.path.getmtime(path)).tm_year
    app_id = _format_uid(uid)

    lines = 0
    first = last_time = None
    starts = {}        # (pid, process) -> record (any app)
    kills = []           # kill lines, any app
    deaths = []          # death lines, any app
    acts = []
    clip_lines = []      # clipboard access checks (any app) and clip-change lines, in file order
    clip_empty = []      # (time, line) of "return empty clip" for the app's uid
    app_process = {}     # pid -> {"time","pid","main"}: the app's own app_process runs
    screen = []

    for line in _complete_lines(path):
        m = _HEAD.match(line)
        if not m:
            continue
        y, mo, d, hms, pid_s, tid_s, rest = m.groups()
        t = f"{y or year}-{mo}-{d} {hms}"
        lines += 1
        if first is None or t < first:
            first = t
        if last_time is None or t > last_time:
            last_time = t
        tag, msg = _split_tag(rest)

        if tag == "ActivityManager":
            if msg.startswith("Start proc "):
                sm = _START_PROC.match(msg)
                if not sm:
                    continue
                pid, proc, uidstr, tail = sm.groups()
                reason, comp = tail.strip(), None
                b = tail.find("{")
                if b >= 0:
                    inner, _ = _braced(tail, b)
                    reason = tail[:b].strip()
                    comp = inner if inner is not None else tail[b + 1:]
                elif " " in reason and "/" in reason.rsplit(" ", 1)[1]:
                    reason, comp = reason.rsplit(" ", 1)
                full, owner = _uid_info(uidstr)
                rec = starts.setdefault((pid, proc), {"time": t, "pid": int(pid), "process": proc,
                                                      "reason": reason, "component": comp, "caller": None})
                rec.update(time=min(rec["time"], t), reason=reason, component=comp,
                           app_id=uidstr, uid=full, owner=owner)
            elif msg.startswith("Killing "):
                km = _KILLING.match(msg)
                if km:
                    pid, proc, uidstr, _adj, reason = km.groups()
                    full, owner = _uid_info(uidstr)
                    kills.append({"time": t, "pid": int(pid), "process": proc, "reason": reason.strip(),
                                  "uid": full, "owner": owner})
            elif msg.startswith("Process "):
                dm = _DIED.match(msg)
                if dm:
                    deaths.append({"time": t, "pid": int(dm.group(2)), "process": dm.group(1),
                                   "state": dm.group(3).strip() or None, "owner": None})
        elif tag == "am_proc_start":
            fl = _event_fields(msg)
            if len(fl) >= 5 and fl[1].isdigit() and fl[2].isdigit():
                pid, num_uid, proc, reason = fl[1], int(fl[2]), fl[3], fl[4]
                comp = _component_of(fl[5]) if len(fl) > 5 else None
                rec = starts.setdefault((pid, proc), {"time": t, "pid": int(pid), "process": proc,
                                                      "reason": reason, "component": comp, "caller": None})
                rec["time"] = min(rec["time"], t)
                rec.setdefault("app_id", _format_uid(num_uid))
                rec.setdefault("uid", num_uid)
                rec.setdefault("owner", _owner_of(num_uid))
                if len(fl) > 6:
                    rec["caller"] = _caller(",".join(fl[6:]))
        elif tag == "am_kill":
            fl = _event_fields(msg)
            if len(fl) >= 5 and fl[1].isdigit():
                rest_f = fl[4:]
                if len(rest_f) > 1 and rest_f[-1].strip().isdigit():
                    rest_f = rest_f[:-1]
                kills.append({"time": t, "pid": int(fl[1]), "process": fl[2], "reason": ",".join(rest_f).strip(),
                              "uid": None, "owner": None})
        elif tag == "am_proc_died":
            fl = _event_fields(msg)
            if len(fl) >= 3 and fl[1].isdigit():
                deaths.append({"time": t, "pid": int(fl[1]), "process": fl[2], "state": None, "owner": None})
        elif tag == "lowmemorykiller" or tag == "lmkd":
            lm = _LMK.match(msg)
            if lm:
                lu = int(lm.group(3))
                kills.append({"time": t, "pid": int(lm.group(2)), "process": lm.group(1),
                              "reason": "lmkd" + (": " + lm.group(5).strip() if lm.group(5) else ""),
                              "uid": lu, "owner": _owner_of(lu)})
        elif tag == "ActivityTaskManager":
            if _START_ACT.match(msg):
                inner, end = _braced(msg, msg.index("{"))
                if inner is None:
                    continue
                fields = _intent_fields(inner)
                cmp = fields.get("cmp")
                target = (cmp or fields.get("pkg") or "").split("/")[0]
                fu = _FROM_UID.search(msg, end)
                acts.append({"time": t, "component": cmp, "action": fields.get("act"),
                             "data": fields.get("dat"), "caller_uid": int(fu.group(1)) if fu else None,
                             "raw": msg.strip(), "_target": target})
        elif tag == "ClipboardService":
            thread = (pid_s, tid_s)
            cm = _CLIP_ALLOWED.match(msg)
            if cm:
                if cm.group(1) in CLIP_OPS:
                    res = {"true": "allowed", "false": "blocked"}.get(cm.group(2), "unknown")
                    clip_lines.append((t, thread, cm.group(3), CLIP_OPS[cm.group(1)], res, msg.strip()))
                continue
            cm = _CLIP_DENYING.match(msg)
            if cm:
                clip_lines.append((t, thread, cm.group(2), CLIP_OPS.get(cm.group(1) or "29", "read"),
                                   "blocked", msg.strip()))
            elif msg.startswith(_CLIP_CLEARING):
                clip_lines.append((t, thread, None, "change", None, None))
        elif tag == "ClipboardService-Controller":
            cm = _CLIP_EMPTY.match(msg)
            if cm and int(cm.group(1)) == uid:
                clip_empty.append((_ts(t), msg.strip()))
        elif tag == "AndroidRuntime":
            rm = _RUNTIME_INIT.match(msg)
            if rm:
                if int(rm.group(1)) == uid:
                    app_process[pid_s] = {"time": t, "pid": int(pid_s), "main": None}
                else:
                    app_process.pop(pid_s, None)
            else:
                mm = _MAIN_ENTRY.match(msg)
                if mm and pid_s in app_process and app_process[pid_s]["main"] is None:
                    app_process[pid_s]["main"] = mm.group(1)
        elif tag == "screen_toggled":
            if msg.strip() in ("0", "1"):
                screen.append({"time": t, "on": msg.strip() == "1"})

    # pid_map: every process start, any app
    pid_map = {}
    for rec in sorted(starts.values(), key=lambda r: r["time"]):
        pid_map[str(rec["pid"])] = {"process": rec["process"], "app_id": rec.get("app_id"), "time": rec["time"]}

    def is_app(rec):
        if rec.get("uid") == uid or rec.get("owner") == uid:
            return True
        return rec.get("owner") is None and _owns_name(package, rec["process"])

    proc_starts, caused, starts_by_pid = [], [], {}
    for rec in sorted(starts.values(), key=lambda r: r["time"]):
        starts_by_pid.setdefault(rec["pid"], []).append(rec)
        out = {k: rec[k] for k in ("time", "pid", "process", "reason", "component", "caller")}
        if is_app(rec):
            proc_starts.append(out)
        elif rec["caller"] and (rec["caller"]["package"] == package or rec["caller"]["uid"] == uid):
            caused.append(out)

    def is_app_proc(rec):
        """Kill/death record -> the app's? Without an owner uid (am_kill, am_proc_died, `has died`,
        lmkd on an isolated uid) it goes by process name, else by the latest start of that pid."""
        if rec["owner"] is not None:
            return rec["owner"] == uid
        if _owns_name(package, rec["process"]):
            return True
        before = [s for s in starts_by_pid.get(rec["pid"], ()) if s["time"] <= rec["time"]]
        return bool(before) and before[-1]["process"] == rec["process"] and is_app(before[-1])

    proc_kills, kill_times, last = [], {}, {}
    for k in sorted(kills, key=lambda r: r["time"]):
        if not is_app_proc(k):
            continue
        kt = _ts(k["time"])
        kill_times.setdefault(k["pid"], []).append(kt)
        prev = last.get(k["pid"])
        if prev is not None and kt - _ts(prev["time"]) <= timedelta(seconds=KILL_MERGE_S):
            prev["reason"] = prev["reason"] or k["reason"]
            continue
        last[k["pid"]] = rec = {"time": k["time"], "pid": k["pid"], "process": k["process"], "reason": k["reason"]}
        proc_kills.append(rec)

    proc_deaths, last = [], {}
    window = timedelta(seconds=DEATH_WINDOW_S)
    for d in sorted(deaths, key=lambda r: r["time"]):
        if not is_app_proc(d):
            continue
        dt = _ts(d["time"])
        if any(timedelta(0) <= dt - kt <= window for kt in kill_times.get(d["pid"], ())):
            continue     # the death that follows a kill line
        prev = last.get(d["pid"])
        if prev is not None and dt - _ts(prev["time"]) <= window:
            prev["state"] = prev["state"] or d["state"]
            continue
        last[d["pid"]] = rec = {"time": d["time"], "pid": d["pid"], "process": d["process"], "state": d["state"]}
        proc_deaths.append(rec)

    activity_starts, by_app = [], []
    for a in sorted(acts, key=lambda r: r["time"]):
        target = a.pop("_target")
        if target == package:
            activity_starts.append(a)
        elif a["caller_uid"] == uid:
            by_app.append(a)

    listener = _listener_checks(clip_lines)
    clip_ops, clip_notify = [], []
    for i, (t, _thread, pkg, op, res, raw) in enumerate(clip_lines):
        if pkg != package:
            continue
        if i in listener:
            clip_notify.append({"time": t, "result": res, "raw": raw})
        else:
            clip_ops.append({"time": t, "op": op, "result": res, "raw": raw})

    last_dt = _ts(last_time) if last_time else None
    clipboard = []
    for c in sorted(clip_ops, key=lambda r: r["time"]):
        if c["op"] == "read" and c["result"] == "allowed":
            ct = _ts(c["time"])
            empty = next((raw for e, raw in clip_empty if timedelta(0) <= e - ct <= timedelta(seconds=BLOCK_WINDOW_S)),
                         None)
            if empty is not None:
                c["result"] = "blocked"
                c["block_raw"] = empty
            elif last_dt is not None and last_dt - ct < timedelta(seconds=BLOCK_WINDOW_S):
                c["result"] = "unknown"     # a block line may have been cut off with the capture
        # One clipboard access is logged as a burst of checks a millisecond apart (xhs_1004:
        # .386 and .387, then a single "return empty clip"); the burst is one event.
        prev = clipboard[-1] if clipboard else None
        if prev and prev["op"] == c["op"] and _ts(c["time"]) - _ts(prev["_last"]) <= timedelta(seconds=CHECK_BURST_S):
            prev["_last"] = c["time"]
            prev["checks"] += 1
            prev["result"] = min(prev["result"], c["result"], key=_RESULT_RANK.index)
            prev["block_raw"] = prev["block_raw"] or c.get("block_raw")
            continue
        clipboard.append({"block_raw": None, **c, "checks": 1, "_last": c["time"]})
    for c in clipboard:
        del c["_last"]

    return {"lines": lines, "first_time": first, "last_time": last_time,
            "proc_starts": proc_starts, "proc_kills": proc_kills, "proc_deaths": proc_deaths,
            "activity_starts": activity_starts, "clipboard": clipboard, "clipboard_notify": clip_notify,
            "pid_map": pid_map, "caused_starts": caused, "activity_starts_by_app": by_app,
            "app_process_starts": sorted(app_process.values(), key=lambda r: r["time"]),
            "screen": sorted(screen, key=lambda r: r["time"])}
