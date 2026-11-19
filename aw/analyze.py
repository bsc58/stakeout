"""Build the analysis result from a run directory (docs/CONTRACT.md: "aw/analyze.py", "Result";
decrypted traffic: docs/CONTRACT_DECRYPT.md, the key route: docs/CONTRACT_KEYLOG.md)."""

import bisect
import json
import re
import shutil
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from aw import parse_appops, parse_filetrace, parse_logcat, parse_net, parse_poll

# A poll occurrence time is the latest sample, rounded to the second (parse_poll): it lies within
# about 1.6 s of the exact time the appops dump and logcat give for the same occurrence.
POLL_MATCH_S = 2.0
LATE_START_S = 5          # a source starting later than this after the capture start is reported
# A source ending earlier than this before the capture end is reported. `aw_ctl.sh stop` writes
# end_time after waiting up to 5 s for the monitors to exit.
EARLY_END_S = 10
# With an approximate sync, trace times are early, never late, by up to about a second: the
# marker carries a truncated whole-second epoch, meta.trace_sync pairs the first trace line
# with the start second. analyze measures part of it from the app's process starts (_trace_lag).
TRACE_CLOCK_S = 1.0
CLIP_OPS = {"READ_CLIPBOARD": "read", "WRITE_CLIPBOARD": "write"}
# Chinese for values that both these texts and the report (aw/report.py) show.
RESULT_ZH = {"allowed": "允许", "blocked": "被系统拒绝", "unknown": "结果未知"}
REASON_ZH = {"broadcast": "广播", "service": "服务", "activity": "打开界面", "top-activity": "打开界面",
             "next-activity": "打开界面", "next-top-activity": "打开界面", "content provider": "数据接口调用",
             "backup": "备份", "restart": "重启"}
POLL_ZH = "轮询（每 1–2 秒查看一次）"
FILE_LIMITS = {
    "package_dump.txt": "未采集到 package_dump.txt：不知道应用已获得哪些权限",
    "logcat.txt": "未采集到 logcat.txt：没有进程启动原因和剪贴板日志",
    "poll.txt": "未采集到 poll.txt：无法判断应用何时在前台，也没有轮询得到的进程、连接和权限记录",
    "filetrace_f2fs.txt": "未采集到 filetrace_f2fs.txt：没有文件访问记录",
    "tls_events.log": "未采集到 tls_events.log：没有 eCapture 解密的内容",
    "tls_keys.log": "未采集到 tls_keys.log：没有密钥解密的内容",
}
# Data files: absent from the run directory, or listed in meta.missing (absent or empty on the phone).
DATA_FILES = set(FILE_LIMITS) | {"appops_before.txt", "appops_after.txt", "ps_before.txt", "ps_after.txt",
                                 "net.pcap"}
# Other meta.missing items: collect's state files, and the free text xhs_1004 (made before appwatch) carries.
MISSING_ZH = {
    "S lines in poll.txt": "poll.txt 里没有网络连接（S 行）",
    "OT lines in poll.txt": "poll.txt 里没有权限查询时刻（OT 行），由轮询推算的权限使用时间可能相差几秒",
    "AW_SYNC marker in filetrace_f2fs.txt": "filetrace_f2fs.txt 里没有时钟对照标记（AW_SYNC）",
    "year in logcat timestamps": "logcat.txt 的时间没有年份，按采集开始的年份补上",
    "start_epoch": "没有记录采集开始时的系统时间（start_epoch）：无法核对抓包是否从采集开始就有数据",
    "end_epoch": "没有记录采集结束时的系统时间（end_epoch）",
    "utc_offset": "没有记录手机的时区（utc_offset）：文件访问的时间按 UTC 换算，可能与手机时间相差几个小时",
    "filetrace_backend": "没有记录文件跟踪方式（filetrace_backend）",
    "decrypt": "没有记录是否进行了解密（decrypt）",
    "device_props.txt": "没有记录手机型号和系统版本（device_props.txt）",
    "kernel.txt": "没有记录内核版本（kernel.txt）",
}
# meta.unavailable: what aw_ctl.sh found missing on the phone (its WARN lines).
UNAVAILABLE_ZH = {
    "tcpdump": "手机上没有 tcpdump 程序：本次没有抓包，没有域名和流量数据",
    "f2fs_events": "手机内核没有 f2fs 文件读写的跟踪事件：本次没有跟踪文件访问",
    "trace_filter": "手机内核没有接受文件跟踪的过滤条件（用来排除采集自己写入的文件，否则跟踪记录会不断增长）："
                    "本次没有跟踪文件访问",
    "ecapture": "要求了解密，但 eCapture 没有在手机上启动（原因在运行目录的 ecapture_keylog_stdout.log 里，"
                "较早版本的采集是 ecapture_stdout.log）：本次没有解密内容",
}
# Decrypted traffic (docs/CONTRACT_DECRYPT.md, docs/CONTRACT_KEYLOG.md): the sources, and the reason codes
# of an exchange's "partial" list and of the parsers' undecoded content. Unknown codes are shown raw.
DECRYPT_SOURCE_ZH = {"ecapture": "eCapture", "keylog": "密钥解密", "har": "代理 HAR 文件"}
PARTIAL_ZH = {
    "hpack_state_unknown": "连接的开头没有记录到，部分请求头无法还原",
    "request_incomplete": "请求不完整",
    "response_incomplete": "响应不完整",
    "response_not_matched": "没有找到对应的响应",
    "body_not_decoded": "正文没有解码",
    "outside_capture": "不在本次采集时间内",
    # codes aw/parse_tls.py adds (exchange "partial" and undecoded records)
    "connection_start_not_captured": "所在连接的开头不在记录里：记录没有连接标识，请求和响应是按流编号和先后顺序对上的，"
                                     "从同一连接上更早的请求还原的头部字段也基于这个推断",
    "record_order_unknown": "记录的先后顺序无法确定，这部分内容没有使用",
    "connection_closed": "连接关闭（没有内容的记录）",
    "connection_unknown": "无法确定属于哪个连接，这部分内容没有使用",
    "empty": "没有内容的写入",
    "h2_control": "HTTP/2 控制帧（连接设置、心跳、流量控制等，不含请求内容）",
    "incomplete_at_end": "到连接关闭或采集结束时还没有收发完",
    "not_http": "不是能识别的 HTTP 内容",
    "response_without_request": "找不到对应请求的响应",
    "server_push": "服务器推送的内容",
    "stream_conflict": "同一连接上的记录前后矛盾（可能缺了记录）",
    "stream_start_not_captured": "请求或响应的开头没有记录到",
}
ECAPTURE_SCOPE_ZH = ("eCapture 只能看到应用通过系统 TLS 库（Conscrypt 的 libssl.so，OkHttp、HttpsURLConnection 用的就是它）"
                     "收发的内容；应用自带的 TLS 库（例如 Cronet）和 HTTP/3（QUIC）里的内容看不到")
# The key route: what it cannot see, and the three groups of the app's TLS connections (keylog coverage).
KEYLOG_SCOPE_ZH = ("密钥解密只能解开采集期间新建立、并且是通过系统加密库（Conscrypt 的 libssl.so，OkHttp、HttpsURLConnection "
                   "用的就是它）建立的加密连接：采集开始前就已建立的连接，抓包里没有建立连接时的握手，也就没有密钥；"
                   "应用自带的加密库（例如 Cronet）建立的连接，eCapture 记录不到密钥；QUIC（HTTP/3，走 UDP）连接不在解密范围内；"
                   "tcpdump 没有抓到的数据包（手机繁忙时可能丢包）里的内容也看不到")
KEYLOG_GROUP_ZH = {"decrypted": "解开了，看得到内容",
                   "before_capture": "采集开始前就已建立，没有密钥",
                   "no_key": "采集期间建立，但没有记录到密钥",
                   "key_no_content": "有密钥，但没有解出内容"}
AUTOSTOP_ZH = {"deadline": "采集达到最长时间，由手机在 {t} 自行停止",
               "disk": "手机存储空间不足 1 GB，采集由手机在 {t} 自行停止"}
_EPOCH = datetime(1970, 1, 1)


def _dt(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _hms(s):
    return s[11:19] if s and len(s) >= 19 else (s or "?")


def _nearest(t, candidates):
    """Index of the candidate time nearest to t within POLL_MATCH_S, else None."""
    d = _dt(t)
    best = None
    for k, c in enumerate(candidates):
        c = _dt(c)
        if d is None or c is None:
            continue
        gap = abs((d - c).total_seconds())
        if gap <= POLL_MATCH_S and (best is None or gap < best[0]):
            best = (gap, k)
    return best[1] if best else None


def _by_time(rows, key="time"):
    return sorted(rows, key=lambda r: _dt(r.get(key)) or datetime.max)


def _utc_offset(text):
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", (text or "").strip())
    if not m:
        return timedelta(0)
    d = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return -d if m.group(1) == "-" else d


def _parse_ps(path):
    """`ps -A -o PID,PPID,USER,NAME` -> [{"pid","ppid","user","name"}]."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split(None, 3)
            if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
                rows.append({"pid": int(parts[0]), "ppid": int(parts[1]), "user": parts[2],
                             "name": parts[3].strip()})
    return rows


def _parse_granted(path, package):
    """Runtime permissions with granted=true inside the `Package [<package>]` section of `dumpsys package`."""
    granted, in_pkg, in_rt = [], False, False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if line.startswith("  Package ["):
                in_pkg, in_rt = line.startswith(f"  Package [{package}]"), False
            elif s and not line[0].isspace():
                in_pkg = in_rt = False
            elif in_pkg and s == "runtime permissions:":
                in_rt = True
            elif in_rt:
                m = re.match(r"([\w.]+): granted=(true|false)", s)
                if not m:
                    in_rt = False
                elif m.group(2) == "true" and m.group(1) not in granted:
                    granted.append(m.group(1))
    return granted


def _ps_user(app_id):
    m = re.fullmatch(r"u(\d+)a(\d+)", app_id or "")
    return f"u{m.group(1)}_a{m.group(2)}" if m else app_id


class _Front:
    """Whether the app was the front app at a given time, from the per-block poll records.

    A block's state lasts from that block to the next one; the CPU ticks parse_poll gives a block
    were used since the previous block, so they belong to the previous block's state."""

    def __init__(self, poll):
        rows = sorted((d, bool(c.get("target_top")), c.get("ticks") or 0)
                      for c in (poll or {}).get("cpu", []) if (d := _dt(c.get("time"))))
        self.times = [r[0] for r in rows]
        self.top = [r[1] for r in rows]
        self.ticks = [r[2] for r in rows]

    def at(self, t, within=0.0):
        """State at t, or over [t, t + within] seconds when it is the same throughout;
        None when it changes in that span or there is no poll block at or before t."""
        d = _dt(t)
        if d is None or not self.times:
            return None
        i = bisect.bisect_right(self.times, d) - 1
        j = bisect.bisect_right(self.times, d + timedelta(seconds=within)) - 1
        if i < 0:
            return None
        states = set(self.top[i:j + 1])
        return states.pop() if len(states) == 1 else None

    def totals(self, end=None):
        """(seconds_top, seconds_not_top, cpu_ticks_not_top); the last block lasts 1 s, at most until end."""
        top = not_top = 0.0
        ticks = 0
        n = len(self.times)
        for i, t in enumerate(self.times):
            if i + 1 < n:
                dur, used = (self.times[i + 1] - t).total_seconds(), self.ticks[i + 1]
            else:
                dur, used = 1.0 if end is None else min(1.0, max(0.0, (end - t).total_seconds())), 0
            if self.top[i]:
                top += dur
            else:
                not_top += dur
                ticks += used
        return round(top), round(not_top), ticks


def _unknown_front_spans(poll, end):
    """[(start, end)] of poll blocks without a topResumedActivity line (same convention as _Front.totals)."""
    segs = [(_dt(t.get("start")), not t.get("component")) for t in (poll or {}).get("top", [])]
    spans = []
    for i, (t, unknown) in enumerate(segs):
        if not unknown or t is None:
            continue
        nxt = segs[i + 1][0] if i + 1 < len(segs) else None
        if nxt is None:
            last = _dt((poll or {}).get("last_time")) or t
            nxt = last + timedelta(seconds=1) if end is None else min(last + timedelta(seconds=1), max(last, end))
        spans.append((t, nxt))
    return spans


def _screen_off_spans(screen, end):
    """[(off, on)] from logcat's screen_toggled records; still off at the end of the log: until end."""
    spans, off = [], None
    for s in screen:
        d = _dt(s.get("time"))
        if d is None:
            continue
        if not s.get("on") and off is None:
            off = d
        elif s.get("on") and off is not None:
            spans.append((off, d))
            off = None
    if off is not None and end is not None:
        spans.append((off, end))
    return spans


def _overlap(spans, others):
    return sum(max(0.0, (min(b, d) - max(a, c)).total_seconds()) for a, b in spans for c, d in others)


def _trace_lag(files, starts, utc_offset):
    """Seconds by which the trace's converted times are early, as far as the app's own process
    starts show it: a process's first file event cannot come before logcat's start of that process.
    0 when the sync is exact or no start tells. A gap larger than the clock can be off means the
    pid belonged to another process before, and is not used."""
    sync = files.get("sync")
    if not sync or not sync.get("approx"):
        return 0.0
    offset = _utc_offset(utc_offset)
    lag = 0.0
    for p in files.get("by_process") or []:
        start = _dt(starts.get(p["pid"]))
        if start is None or p.get("first_ts") is None:
            continue
        first = _EPOCH + timedelta(seconds=sync["epoch"] + p["first_ts"] - sync["trace_ts"]) + offset
        gap = (start - first).total_seconds()
        if gap <= TRACE_CLOCK_S:
            lag = max(lag, gap)
    return lag


def _shift(t, seconds):
    d = _dt(t)
    return (d + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.%f")[:23] if d else t


def _host_name(host):
    """An exchange's host without a port ("a.example.com:8443", "[2001:db8::1]:8443"), lower case."""
    host = (host or "").lower()
    if host.startswith("["):
        return host[:host.find("]") + 1]
    return host.split(":")[0] if host.count(":") == 1 else host


def _body_size_unknown(side):
    """True when the size of a request's or response's body is not known in full: no response was
    matched, the side was not recorded to its end, or its size is unknown (parse_har)."""
    if side is None:
        return True
    body = side.get("body")
    return side.get("complete") is False or (body is not None and body.get("size") is None)


def _addr(ip, port):
    """"ip:port" as parse_keylog writes a connection's server address (IPv6 in brackets)."""
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"


def _keylog_coverage(connections, sockets, endpoints):
    """The app's TLS connections in three groups (docs/CONTRACT_KEYLOG.md): decrypted (the keys are the
    app's only, so a decrypted connection is the app's in any case), opened before the capture (no
    ClientHello in it), and handshake in the capture but no key. A connection that did not decrypt is the
    app's when the poll saw its local address on the app's socket to that server, as parse_net.attribute
    counts the app's flows: the server address alone is not enough (fixtures/live_xhs_keylog_1119: 9
    Douyin connections went to addresses the app used too). A fourth group, key_no_content: the key file
    has the connection's key (so it is the app's) but nothing decrypted (live_xhs_keylog_1119: one connection
    closed right after its handshake). hosts: [[name, connections]], the name from the ClientHello, else
    the endpoint's host; None: known only by address."""
    names = {_addr(e["ip"], e["port"]): e.get("host") for e in endpoints if e.get("proto") == "tcp"}
    own = {}
    for s in sockets:
        if s.get("proto") == "tcp":
            own.setdefault(_addr(s["ip"], s["port"]), set()).update(s.get("locals") or ())
    groups = {"decrypted": [], "before_capture": [], "no_key": [], "key_no_content": []}
    for c in connections:
        if c.get("decrypted"):
            groups["decrypted"].append(c)
        elif c.get("key"):
            groups["key_no_content"].append(c)
        elif c.get("client") in own.get(c.get("server"), ()):
            groups["no_key" if c.get("handshake_seen") else "before_capture"].append(c)
    cov = {"sockets": bool(sockets)}
    for g, cs in groups.items():
        hosts = Counter(c.get("sni") or names.get(c.get("server")) for c in cs)
        cov[g] = {"connections": len(cs), "ids": [c["id"] for c in cs],
                  "hosts": [[h, n] for h, n in sorted(hosts.items(), key=lambda kv: (kv[0] is None, -kv[1], kv[0] or ""))]}
    # decrypted, but the bytes are not HTTP (parse_keylog: protocol None)
    cov["decrypted"]["not_http"] = sum(1 for c in groups["decrypted"] if c.get("protocol") is None)
    return cov


def _decrypted(tls, har, start, end, endpoints, keylog=None, keylog_error=None, sockets=()):
    """result["decrypted"] from parse_tls_events / parse_keylog / parse_har results (None: that source is
    absent). Sets the "plaintext" of the endpoints that have exchanges inside the capture window: by host
    name for eCapture and HAR, by the connection's server address for the key route."""
    lo, hi = _dt(start), _dt(end) + timedelta(seconds=1)        # end_time is truncated to the second
    har_rows, in_window = [], 0
    for x in (har or {}).get("exchanges") or []:
        x = dict(x, partial=list(x.get("partial") or []))
        t = _dt(x.get("time"))
        if t is not None and lo <= t < hi:
            in_window += 1
        elif "outside_capture" not in x["partial"]:
            x["partial"].append("outside_capture")
        har_rows.append(x)
    rows = _by_time(list((tls or {}).get("exchanges") or []) + list((keylog or {}).get("exchanges") or []) + har_rows)
    exchanges = [{"id": i, **x} for i, x in enumerate(rows, 1)]

    groups = {}
    for x in exchanges:
        g = groups.setdefault(x.get("host"), {"host": x.get("host"), "exchanges": 0, "methods": {}, "sources": [],
                                              "request_bytes": 0, "response_bytes": 0, "request_bodies_unknown": 0,
                                              "response_bodies_unknown": 0, "paths": Counter()})
        g["exchanges"] += 1
        if x.get("method"):
            g["methods"][x["method"]] = g["methods"].get(x["method"], 0) + 1
        if x["source"] not in g["sources"]:
            g["sources"].append(x["source"])
        # body sizes as sent; headers are not counted. A body not recorded in full makes the sum a lower bound.
        for side in ("request", "response"):
            g[f"{side}_bytes"] += ((x.get(side) or {}).get("body") or {}).get("size") or 0
            g[f"{side}_bodies_unknown"] += _body_size_unknown(x.get(side))
        if x.get("path"):
            g["paths"][x["path"]] += 1
    hosts = sorted(groups.values(), key=lambda g: (-g["exchanges"], g["host"] or ""))
    for g in hosts:
        g["paths"] = [[p, n] for p, n in sorted(g["paths"].items(), key=lambda kv: (-kv[1], kv[0]))[:10]]

    # An exchange outside the capture window did not travel over the connections the poll saw.
    ids, by_server = {}, {}
    for x in exchanges:
        if "outside_capture" in x["partial"]:
            continue
        if x["source"] == "keylog":
            if x.get("server"):
                by_server.setdefault(x["server"], []).append(x["id"])
        elif x.get("host"):
            ids.setdefault(_host_name(x["host"]), []).append(x["id"])
    for e in endpoints:
        found = set(ids.get(e["host"].lower()) or []) if e.get("host") else set()
        if e.get("proto") == "tcp":
            found |= set(by_server.get(_addr(e.get("ip"), e.get("port"))) or [])
        if found:
            e["plaintext"] = {"exchanges": len(found), "ids": sorted(found)}
    not_covered = {}
    if tls is not None or har is not None or keylog is not None:
        for e in endpoints:
            if e.get("host") and e.get("plaintext") is None:
                not_covered[e["host"]] = not_covered.get(e["host"], 0) + (e.get("bytes_out") or 0) + (e.get("bytes_in") or 0)

    return {
        "sources": [s for s in ("ecapture", "keylog", "har") if any(x["source"] == s for x in exchanges)],
        "ecapture": {k: tls.get(k) for k in ("records", "bytes", "first_time", "last_time", "out_of_order",
                                             "cut_off", "undecoded")} if tls is not None else None,
        "keylog": {"tshark": keylog.get("tshark"), "keys": keylog.get("keys"),
                   "connections": keylog.get("connections") or [], "undecoded": keylog.get("undecoded"),
                   "coverage": _keylog_coverage(keylog.get("connections") or [], sockets, endpoints)}
        if keylog is not None else None,
        "keylog_error": keylog_error,       # the key route was due but could not run (tshark, no net.pcap)
        "har": {"creator": har.get("creator"), "entries": har.get("entries"), "skipped": har.get("skipped"),
                "in_window": in_window, "outside_window": len(har_rows) - in_window} if har is not None else None,
        "exchanges": exchanges,
        "hosts": hosts,
        "not_covered": [{"host": h, "bytes": b} for h, b in sorted(not_covered.items(), key=lambda kv: (-kv[1], kv[0]))],
    }


def decrypted_summary(dec):
    """How many requests were decrypted, by source, and to how many hosts (highlights and report).
    In fixtures/live_xhs_tls_0120, 27 of 33 requests have no host: their :authority came from an
    HPACK table whose start was not captured."""
    xs = dec["exchanges"]
    named = sum(1 for h in dec["hosts"] if h["host"])
    unknown = [x for x in xs if not x.get("host")]
    text = (f"解密了 {len(xs)} 个 HTTPS 请求（"
            + "、".join(f"{DECRYPT_SOURCE_ZH[s]} {sum(x['source'] == s for x in xs)} 个" for s in dec["sources"]) + "）")
    if named:
        text += (f"，其中 {len(xs) - len(unknown)} 个" if unknown else "，") + f"发往 {named} 个域名"
    if unknown:
        text += f"，{len(unknown)} 个" if named else "，都"
        text += "不知道发往哪个域名"
        if all("hpack_state_unknown" in (x.get("partial") or []) for x in unknown):
            text += f"（{PARTIAL_ZH['hpack_state_unknown']}）"
    return text


def _tls_hosts(endpoints):
    """Host names of the app's endpoints that carried TLS in the capture: a TLS ClientHello named the
    host or its server address (host_source "sni"), or TCP port 443 carried bytes."""
    return {e["host"].lower() for e in endpoints if e.get("host") and (
        e.get("host_source") == "sni" or (e.get("proto") == "tcp" and e.get("port") == 443
                                           and (e.get("bytes_out") or 0) + (e.get("bytes_in") or 0) > 0))}


def coverage_text(dec, endpoints, listed=True):
    """What the decrypted requests leave open about the app's connections (highlights and report): its
    hosts with no decrypted request (named when `listed`), its servers known only by address, and the
    usual reasons. "" when there is nothing to say. Requests whose host is unknown may have gone to
    any of them, so then "no request" is not certain; as possible destinations only the uncovered hosts
    with TLS traffic that end with such a request's connection_host_tail are named."""
    nc = dec.get("not_covered") or []
    inside = [x for x in dec.get("exchanges") or [] if "outside_capture" not in (x.get("partial") or [])]
    nameless = [e for e in endpoints if not e.get("host")] if inside else []
    if not nc and not nameless:
        return ""
    hostless = [x for x in inside if not x.get("host")]
    unknown = len(hostless)
    text = ""
    if nc:
        names = ("：" + "、".join(h["host"] for h in nc[:5]) + ("等" if len(nc) > 5 else "")) if listed else ""
        text += (f"应用连接的 {len(nc)} 个域名，解密到的请求中没有一个能确定是发往它们的{names}。" if unknown
                 else f"应用连接的 {len(nc)} 个域名没有解密到内容{names}。")
    if nameless:
        total = sum((e.get("bytes_out") or 0) + (e.get("bytes_in") or 0) for e in nameless)
        text += (f"应用{'另' if nc else ''}有 {len(nameless)} 个服务器只有 IP 地址"
                 + (f"（抓包约 {total / 1024:.0f} KB）" if total >= 1024 else f"（抓包约 {total} 字节）" if total else "")
                 + "，不知道解密到的请求里有没有发往它们的。")
    if unknown:
        text += f"解密到的请求中有 {unknown} 个不知道发往哪个域名"
        tails = sorted({x["connection_host_tail"].lower() for x in hostless if x.get("connection_host_tail")})
        tls = _tls_hosts(endpoints)
        maybe = [h["host"] for h in nc if h["host"].lower() in tls and any(h["host"].lower().endswith(t) for t in tails)]
        if maybe:
            hit = [t for t in tails if any(h.lower().endswith(t) for h in maybe)]
            text += (f"；其中有的请求所在连接的服务器名以 {'、'.join(hit)} 结尾，可能有发往 "
                     + "、".join(maybe) + " 的")
        text += "。"
    why = (["应用用自己的网络库收发（eCapture 只能看到系统 TLS 库里的内容）"] if dec.get("ecapture") is not None else []) \
        + (["这些连接没有经过代理，或者应用不接受代理的证书（证书固定）"] if dec.get("har") is not None else []) \
        + ["连接用的不是 HTTPS"]
    text += "没有解密到内容时，通常的原因是" + "，或者".join(why)
    if dec.get("har") is None:
        text += "；这种情况可以按 docs/MITM.md 自己设置代理录制，再用 analyze --har 导入"
    return text + "。"


def keylog_coverage_text(kl, listed=True):
    """How many of the app's TLS connections the key route opened, and why the others stayed closed
    (highlights and report); with `listed`, a few host names per group."""
    cov = kl["coverage"]
    d, b, n = cov["decrypted"], cov["before_capture"], cov["no_key"]
    k = cov.get("key_no_content") or {"connections": 0, "hosts": []}
    empty = (f"{k['connections']} 个记录到了密钥，但没有解出任何内容{{}}：连接在握手后没有收发数据就关闭了，"
             "或者数据包没有抓全")

    def names(g):
        named = [h for h, _ in g["hosts"] if h]
        if not listed or not named:
            return ""
        return "（如 " + "、".join(named[:3]) + ("等" if len(named) > 3 else "") + "）"

    not_http = f"，其中 {d['not_http']} 个的内容不是 HTTP 请求，只统计了数据量" if d.get("not_http") else ""
    if not cov.get("sockets"):
        text = (f"解开了应用的 {d['connections']} 个加密连接{names(d)}{not_http}" if d["connections"]
                else "没有解开应用的任何加密连接")
        if k["connections"]:
            text += "；另有" + empty.format(names(k))
        return text + "。轮询没有记录应用的网络连接，抓包里其他没有解开的加密连接哪些属于这个应用，无法判断。"
    total = d["connections"] + b["connections"] + n["connections"] + k["connections"]
    if not total:
        return "抓包里没有这个应用的加密连接。"
    parts = [f"{d['connections']} 个解开了{names(d)}，看得到内容{not_http}"] if d["connections"] else []
    if b["connections"]:
        parts.append(f"{b['connections']} 个在采集开始前就已建立{names(b)}，抓包里没有建立连接时的握手，也就没有密钥，解不开")
    if n["connections"]:
        parts.append(f"{n['connections']} 个是采集期间建立的{names(n)}，但没有记录到密钥，解不开：通常是因为应用用了"
                     "自己带的加密库（例如 Cronet），eCapture 只记录系统加密库的密钥，也可能是 eCapture 漏记了这次握手")
    if k["connections"]:
        parts.append(empty.format(names(k)))
    return f"抓包里有应用的 {total} 个加密连接（HTTPS 用的就是这种连接）：" + "；".join(parts) + "。"


def _decrypt_limits(meta, dec, har_error, endpoints):
    limits = []
    if "ecapture" in (meta.get("unavailable") or []):
        limits.append(UNAVAILABLE_ZH["ecapture"])
    if har_error:
        limits.append(f"运行目录里的 mitm.har 无法读取（{har_error}）：没有导入代理录制的内容")
    if dec.get("keylog_error"):
        limits.append(f"没能用密钥解密抓包（{dec['keylog_error'].rstrip('。')}）：本次没有密钥解密的内容")
    kl = dec.get("keylog")
    if kl is not None:
        limits.append(KEYLOG_SCOPE_ZH)
        cov = kl["coverage"]
        if cov["before_capture"]["connections"]:
            limits.append(f"应用有 {cov['before_capture']['connections']} 个加密连接在采集开始前就已建立，没有密钥，内容看不到。"
                          "要避免这种情况：先在手机上彻底停止这个应用，再开始采集，看到开始采集的提示后再打开应用"
                          "（开始采集时应用已经在运行，run --decrypt 会提醒）")
        if cov.get("sockets"):
            limits.append("没有解开的加密连接，只算了轮询时看到属于这个应用的：轮询每 1–2 秒查看一次，"
                          "很快就结束的连接可能没有算进去")
        quic = [e for e in endpoints if e.get("proto") == "udp" and e.get("port") == 443]
        if quic:
            total = sum((e.get("bytes_out") or 0) + (e.get("bytes_in") or 0) for e in quic)
            limits.append(f"应用有 {len(quic)} 个 UDP 443 端口的连接（QUIC，HTTP/3 用的就是它"
                          + (f"，抓包约 {total / 1024:.0f} KB" if total >= 1024 else "")
                          + "）：密钥解密不包括这种连接，内容看不到")
        und = kl.get("undecoded") or {}
        if und.get("bytes"):
            why = "、".join(f"{PARTIAL_ZH.get(c, c)} {k:,} 字节" for c, k in (und.get("reasons") or {}).items())
            limits.append(f"解开的内容中有 {und['bytes']:,} 字节不属于任何请求" + (f"：{why}" if why else ""))
    ecap, har = dec["ecapture"], dec["har"]
    if ecap is not None:
        limits.append(ECAPTURE_SCOPE_ZH)
        und = ecap.get("undecoded") or {}
        if und.get("records"):
            # undecoded.bytes also counts control frames inside records that carry a request: not these records' size
            why = "、".join(f"{PARTIAL_ZH.get(c, c)} {n} 条" for c, n in (und.get("reasons") or {}).items())
            limits.append(f"eCapture 的记录中有 {und['records']} 条没有归入任何请求" + (f"：{why}" if why else "")
                          + f"；不属于任何请求的内容共 {und.get('bytes') or 0:,} 字节")
    # what the exchanges themselves leave open; outside_capture, body_not_decoded and
    # connection_start_not_captured have their own lines
    own_line = ("outside_capture", "body_not_decoded", "connection_start_not_captured")
    open_codes = Counter(c for x in dec["exchanges"] for c in x.get("partial") or [] if c not in own_line)
    if open_codes:
        n = sum(1 for x in dec["exchanges"] if set(x.get("partial") or []) & set(open_codes))
        limits.append(f"解密到的 {len(dec['exchanges'])} 个请求中有 {n} 个不完整或不确定（"
                      + "；".join(f"{PARTIAL_ZH.get(c, c)}：{k} 个" for c, k in open_codes.most_common())
                      + "）：报告里只列出确定的部分，每个请求下注明了原因")
    late = sum(1 for x in dec["exchanges"] if "connection_start_not_captured" in (x.get("partial") or []))
    if late:
        limits.append(f"解密到的请求中有 {late} 个所在的 HTTP/2 连接，开头不在记录里（连接在 eCapture 开始之前就已建立时"
                      "会这样）：记录没有连接标识，这些请求和响应是按流编号和先后顺序对上的，从同一连接上更早的请求还原的头部字段"
                      "也基于这个推断。要避免这种情况：先在手机上彻底停止这个应用，再开始采集，看到开始采集的提示后再打开应用")
    if har is not None:
        limits.append("HAR 文件是你自己设置的代理录制的，里面可能有手机上其他应用的请求，Stakeout 无法区分")
        if har["outside_window"]:
            limits.append(f"HAR 文件中有 {har['outside_window']} 个请求不在本次采集时间内（{_hms(meta['start_time'])} 至 "
                          f"{_hms(meta['end_time'])}），报告中标为“{PARTIAL_ZH['outside_capture']}”，"
                          "也不用来判断应用的哪些连接被解密了")
        if har.get("skipped"):
            limits.append(f"HAR 文件中有 {har['skipped']} 条记录没有可用的请求，没有导入")
    # Content-Encoding of the bodies that were not decoded; None: the Content-Encoding header could not be
    # restored and the bytes are neither text nor a verified gzip member (make_body); "": parse_har could
    # not turn the HAR text back into the bytes sent (size unknown).
    encodings = Counter()
    for x in dec["exchanges"]:
        for side in ("request", "response"):
            body = (x.get(side) or {}).get("body")
            if body and not body.get("decoded"):
                encodings["" if body.get("size") is None else body.get("encoding")] += 1
    if encodings:
        known = ("br", "zstd", "gzip", "x-gzip", "deflate")
        label = {None: "压缩方式不明的", "": "无法还原的"}
        why = (["br、zstd 压缩无法用 Python 标准库解码"] if encodings.keys() & {"br", "zstd"} else []) \
            + (["gzip、deflate 压缩的正文没能解码，说明数据不完整或已损坏"]
               if encodings.keys() & {"gzip", "x-gzip", "deflate"} else []) \
            + ([f"不支持的压缩方式 {'、'.join(e for e in encodings if e and e not in known)}"]
               if any(e and e not in known for e in encodings) else []) \
            + (["压缩方式不明：头部里的压缩方式（Content-Encoding）没能还原，内容既不是文本，也不是校验通过的 gzip 数据，"
                "可能经过了别的压缩"] if None in encodings else []) \
            + (["HAR 文件里的正文无法还原成发送时的字节"] if "" in encodings else [])
        limits.append(f"有 {sum(encodings.values())} 个正文没有解码（"
                      + "、".join(f"{label[e]} {n} 个" if e in label else f"{e} {n} 个" for e, n in encodings.items())
                      + "）：" + "；".join(why) + "；这些正文不显示解码后的内容，报告只给出类型和大小"
                      "（加 --show-secrets 时，有字节的还给出 sha256 和开头字节的十六进制）")
    return limits


def analyze(run_dir, out_dir=None, har=None) -> dict:
    """har: a HAR file to import (copied to <run_dir>/mitm.har); without it an existing mitm.har is used.
    A har that is not a HAR file raises parse_har's ValueError before anything is copied."""
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    pkg, uid, app_id = meta["package"], meta["uid"], meta["app_id"]
    start, end = meta["start_time"], meta["end_time"]
    missing = []

    def load(name, fn, *args, **kwargs):
        try:
            return fn(run_dir / name, *args, **kwargs)
        except FileNotFoundError:
            missing.append(name)
            return None

    poll = load("poll.txt", parse_poll.parse_poll, pkg, start=start, end=end)
    logcat = load("logcat.txt", parse_logcat.parse_logcat, pkg, uid, year=int(start[:4]))
    before = load("appops_before.txt", parse_appops.parse_appops_dump)
    after = load("appops_after.txt", parse_appops.parse_appops_dump)
    granted = load("package_dump.txt", _parse_granted, pkg)
    ps_rows = (load("ps_before.txt", _parse_ps) or []) + (load("ps_after.txt", _parse_ps) or [])
    app_starts = (logcat or {}).get("app_process_starts") or []

    # The app's processes: poll, logcat (system starts, then the app's own app_process runs) and ps,
    # in that order of preference for the name.
    app_user = _ps_user(app_id)
    names, pid_time = {}, {}

    def add_pid(pid, name, time=None):
        pid = int(pid)
        if not names.get(pid):
            names[pid] = (name or "").strip()
        if time and pid not in pid_time:
            pid_time[pid] = time

    for pid, p in ((poll or {}).get("procs") or {}).items():
        add_pid(pid, p.get("cmdline"))
    for s in (logcat or {}).get("proc_starts", []):
        add_pid(s["pid"], s.get("process"), s.get("time"))
    for pid, e in ((logcat or {}).get("pid_map") or {}).items():
        if e.get("app_id") == app_id:
            add_pid(pid, e.get("process"), e.get("time"))
    for s in app_starts:
        add_pid(s["pid"], None, s["time"])
    for r in ps_rows:
        if r["user"] == app_user:
            add_pid(r["pid"], r["name"])
    target_pids = set(names)
    pid_names = {pid: n for pid, n in names.items() if n}

    front = _Front(poll)
    backend = meta.get("filetrace_backend", "none")
    files = None
    if backend == "f2fs":
        files = load("filetrace_f2fs.txt", parse_filetrace.parse_f2fs_trace, pkg, target_pids,
                     pid_names=pid_names, sync=meta.get("trace_sync"),
                     utc_offset=meta.get("utc_offset", "+0000"))
    files = {**files, "backend": "f2fs"} if files is not None else {"backend": backend}
    if "events" in files:
        starts_at = {int(s["pid"]): s["time"] for s in (logcat or {}).get("proc_starts", [])}
        starts_at.update({s["pid"]: s["time"] for s in app_starts})
        lag = _trace_lag(files, starts_at, meta.get("utc_offset"))
        if lag:
            files["clock_lag_s"] = round(lag, 3)
        # A converted trace time t means the access happened in [t, t + what is left of the clock
        # error]: only when the front state is the same throughout is it said to be in front or not.
        within = max(0.0, TRACE_CLOCK_S - lag) if (files.get("sync") or {}).get("approx") else 0.0
        for a in files.get("other_app_apks") or []:
            a["first_time"] = _shift(a.get("first_time"), lag)
            top = front.at(a.get("first_time"), within)
            a["background"] = None if top is None else not top
    files["open_files"] = (poll or {}).get("fds") or []

    pcap, unreadable = None, []
    try:
        pcap = load("net.pcap", parse_net.parse_pcap)
    except ValueError:          # pcapng or a link type parse_pcap does not read
        unreadable.append("net.pcap")
    sockets = (poll or {}).get("sockets") or []
    if sockets and pcap is not None:
        endpoints = parse_net.attribute(pcap, sockets)
    else:
        endpoints = [{"proto": s.get("proto"), "ip": s.get("ip"), "port": s.get("port"), "host": None,
                      "host_source": None, "first_seen": s.get("first_seen"), "last_seen": s.get("last_seen"),
                      "bytes_out": None, "bytes_in": None, "plaintext": None} for s in sockets]
    # aw_poll.sh looks at the app's sockets in every block; xhs_1004 (made before it) did not.
    sampled = bool(poll and poll.get("blocks")) and "S lines in poll.txt" not in (meta.get("missing") or [])
    network = {"attributed": bool(sockets), "sockets_sampled": sampled, "pcap": pcap is not None,
               "packets": pcap.get("packets") if pcap else None, "endpoints": endpoints,
               "hosts_unattributed": parse_net.hosts_unattributed(pcap) if pcap is not None and not sockets else []}

    utc_offset = meta.get("utc_offset", "+0000")
    tls = keylog = keylog_error = None
    # The files decide, not meta.decrypt alone: fixtures/live_xhs_tls_0120 has tls_events.log and no
    # "decrypt" key; fixtures/live_xhs_keylog_1119 has the keys and says "ecapture" (the key-mode eCapture was
    # started by hand). With tls_keys.log only the key route is used. The parsers are imported only for
    # runs that have decrypted traffic.
    if (run_dir / "tls_keys.log").exists():
        if (run_dir / "net.pcap").exists():
            from aw import parse_keylog
            try:
                keylog = parse_keylog.parse_keylog(run_dir / "net.pcap", run_dir / "tls_keys.log",
                                                   utc_offset=utc_offset)
            except parse_keylog.KeylogError as e:      # tshark missing or failing: one Chinese sentence
                keylog_error = str(e)
        else:
            keylog_error = "没有抓包文件 net.pcap"
    elif meta.get("decrypt") == "keylog":
        missing.append("tls_keys.log")
    elif meta.get("decrypt") == "ecapture" or (run_dir / "tls_events.log").exists():
        from aw import parse_tls
        tls = load("tls_events.log", parse_tls.parse_tls_events, utc_offset=utc_offset)
    har_result, har_error = None, None
    if har is not None:
        from aw import parse_har
        har_result = parse_har.parse_har(har, utc_offset=utc_offset)
        dest = run_dir / "mitm.har"
        if not (dest.exists() and dest.samefile(har)):
            shutil.copyfile(har, dest)
    elif (run_dir / "mitm.har").is_file():
        from aw import parse_har
        try:
            har_result = parse_har.parse_har(run_dir / "mitm.har", utc_offset=utc_offset)
        except ValueError as e:
            har_error = str(e)
    decrypted = _decrypted(tls, har_result, start, end, endpoints, keylog, keylog_error, sockets)

    dump_entries = parse_appops.diff_appops(before, after, start, end) if after is not None else []
    used, occurrences = _permissions(dump_entries, (poll or {}).get("ops") or {}, front)
    clipboard = _clipboard((logcat or {}).get("clipboard", []), occurrences, front)
    processes, new_not_top = _processes(pkg, poll, logcat, app_starts, ps_rows, app_user, names, pid_time, front)
    timeline, events_not_top = _timeline(pkg, uid, poll, logcat, processes, occurrences, clipboard, files,
                                         network, decrypted["exchanges"], front)

    seconds_top, seconds_not_top, ticks_not_top = front.totals(_dt(end))
    background = {"seconds_top": seconds_top, "seconds_not_top": seconds_not_top,
                  "cpu_ticks_not_top": ticks_not_top,
                  # processes the poll never saw: their CPU time is not in cpu_ticks_not_top
                  "procs_not_polled": sum(1 for p in processes["procs"] if p["source"] != "poll"),
                  "events_not_top": events_not_top}

    meta_out = dict(meta)
    if "start_epoch" in meta and "end_epoch" in meta:
        meta_out["duration_s"] = meta["end_epoch"] - meta["start_epoch"]
    else:
        meta_out["duration_s"] = round((_dt(end) - _dt(start)).total_seconds())

    have_poll = bool(poll and poll.get("blocks"))
    captured = {"poll": have_poll, "logcat": bool(logcat and logcat.get("lines")),
                "appops": bool(after and after.get("ops")), "ps": bool(ps_rows),
                "trace": "events" in files, "pcap": pcap is not None,
                "decrypted": tls is not None or keylog is not None or har_result is not None}
    # Processes the poll saw until its last block, with only the front app's oom_score_adj (0),
    # while the app was no longer in front.
    last_block = (poll or {}).get("last_time")
    kept_fg = [p for p in processes["procs"]
               if p["source"] == "poll" and p.get("last_seen") == last_block and p.get("adj")
               and set(p["adj"]) == {0}] if have_poll and front.at(last_block) is False else []

    result = {
        "meta": meta_out,
        "highlights": [],
        "permissions": {"granted": granted or [], "used": used},
        "clipboard": clipboard,
        "files": files,
        "processes": processes,
        "background": background,
        "network": network,
        "decrypted": decrypted,
        "timeline": timeline,
        "captured": captured,
        "limits": _limits(meta, missing, unreadable, poll, logcat, pcap, files, network, bool(target_pids),
                          _decrypt_limits(meta, decrypted, har_error, endpoints)),
    }
    result["highlights"] = _highlights(result, have_poll, bool(target_pids), occurrences, new_not_top, kept_fg)

    out = Path(out_dir) if out_dir is not None else run_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    return result


def _permissions(dump_entries, poll_ops, front):
    """Merge appops dump entries and poll events into one record per (op, kind) plus a list of occurrences."""
    keys = {}
    for e in dump_entries:
        keys.setdefault((e["op"], e["kind"]), ([], []))[0].append(e)
    for op, o in poll_ops.items():
        for ev in o.get("events", []):
            keys.setdefault((op, ev["kind"]), ([], []))[1].append(ev)

    used, occurrences = [], []
    for (op, kind), (dumps, polls) in keys.items():
        occ = [{"op": op, "kind": kind, "time": e["time"], "state": e.get("state"),
                "background": e.get("state") != "top" or front.at(e["time"]) is False} for e in dumps]
        # The poll occurrence nearest to a dump entry is the same occurrence; the dump has the exact
        # time. One dump entry stands for one occurrence, so it replaces at most one poll occurrence.
        same = {_nearest(e["time"], [ev["time"] for ev in polls]) for e in dumps}
        occ += [{"op": op, "kind": kind, "time": ev["time"], **_poll_state(ev)}
                for k, ev in enumerate(polls) if k not in same]
        occ = _by_time(occ)
        info = parse_appops.op_info(op)
        used.append({"op": op, "zh": info.get("zh", op), "category": info.get("category"),
                     "sensitive": bool(info.get("sensitive")), "kind": kind,
                     "count": len(occ) if polls else None,
                     "last_time": occ[-1]["time"] if occ else None,
                     "states": list(dict.fromkeys(o["state"] or "unknown" for o in occ)),
                     "background": any(o["background"] for o in occ),
                     "source": "both" if dumps and polls else ("dump" if dumps else "poll")})
        for o in occ:
            o.update(zh=info.get("zh", op), sensitive=bool(info.get("sensitive")))
        occurrences += occ
    used.sort(key=lambda r: (not r["background"], not r["sensitive"], r["op"], r["kind"]))
    return used, _by_time(occurrences)


def _poll_state(ev):
    """state / background of a poll occurrence; both None when parse_poll could not tell the front
    state (before the first poll block, or the occurrence may lie on either side of a front switch)."""
    top = ev.get("target_top")
    if top is None:
        return {"state": None, "background": None}
    return {"state": "top" if top else "bg", "background": not top}


def _clipboard(log_events, occurrences, front):
    events = []
    for e in log_events:
        top = front.at(e["time"])
        events.append({"time": e["time"], "op": e["op"], "result": e.get("result") or "unknown",
                       "source": "logcat", "background": None if top is None else not top, "raw": e.get("raw"),
                       "block_raw": e.get("block_raw"), "checks": e.get("checks", 1)})
    # Each logcat line is the same occurrence as the appops occurrence nearest to it. Several lines
    # can fall on one occurrence (the poll cannot tell reads a moment apart), but one line never
    # stands for two occurrences the poll kept apart.
    logged = list(events)
    for op in CLIP_OPS.values():
        occ = [o for o in occurrences if CLIP_OPS.get(o["op"]) == op]
        same = set()
        for e in logged:
            if e["op"] != op:
                continue
            k = _nearest(e["time"], [o["time"] for o in occ])
            if k is not None:
                same.add(k)
                if e["result"] == "unknown":
                    e["result"] = "allowed" if occ[k]["kind"] == "access" else "blocked"
        events += [{"time": o["time"], "op": op, "result": "allowed" if o["kind"] == "access" else "blocked",
                    "source": "appops", "background": o["background"], "raw": None, "block_raw": None,
                    "checks": None}
                   for k, o in enumerate(occ) if k not in same]
    events = _by_time(events)
    return {"reads": sum(e["op"] == "read" for e in events),
            "blocked": sum(e["result"] == "blocked" for e in events),
            "writes": sum(e["op"] == "write" for e in events),
            "events": events}


def _processes(pkg, poll, logcat, app_starts, ps_rows, app_user, names, pid_time, front):
    """started_by: "system" (an ActivityManager start), "app" (the app ran app_process), None (not seen)."""
    starts = (logcat or {}).get("proc_starts", [])
    start_by_pid = {int(s["pid"]): s for s in starts}
    app_start_by_pid = {s["pid"]: s for s in app_starts}

    def started_by(pid):
        return "system" if pid in start_by_pid else ("app" if pid in app_start_by_pid else None)

    def main(pid):
        return (app_start_by_pid.get(pid) or {}).get("main")

    poll_procs = (poll or {}).get("procs") or {}
    procs = [{**p, "pid": int(pid), "cmdline": (p.get("cmdline") or "").strip(), "source": "poll",
              "started_by": started_by(int(pid)), "main": main(int(pid))}
             for pid, p in poll_procs.items()]
    ps_ppid = {r["pid"]: r["ppid"] for r in ps_rows if r["user"] == app_user}
    for pid in sorted(set(names) - {int(p) for p in poll_procs}):
        procs.append({"pid": pid, "cmdline": names[pid], "first_seen": pid_time.get(pid), "last_seen": None,
                      "ppid": ps_ppid.get(pid), "cpu_ticks": None, "adj": [], "read_bytes": None,
                      "source": "logcat" if pid in pid_time else "ps", "started_by": started_by(pid),
                      "main": main(pid)})
    procs = _by_time(procs, "first_seen")

    own = re.compile(re.escape(pkg) + r"(:\S*)?")
    commands = [{"pid": p["pid"], "cmdline": p["cmdline"]} for p in procs
                if p["cmdline"] and not own.fullmatch(p["cmdline"])]

    # kind "kill": a kill line (the system ended it); "died": only a death line (crash, exit, the app itself)
    kills = [{**k, "kind": "kill"} for k in (logcat or {}).get("proc_kills", [])]
    kills += [{"time": d["time"], "pid": d["pid"], "process": d["process"], "reason": d.get("state"), "kind": "died"}
              for d in (logcat or {}).get("proc_deaths", [])]

    first_block = (poll or {}).get("first_time")
    new_not_top = []
    for p in procs:
        s = start_by_pid.get(p["pid"]) or app_start_by_pid.get(p["pid"])
        t = s["time"] if s else p.get("first_seen")
        if not s and (p["source"] != "poll" or t == first_block):
            continue        # already running when the poll started, or no start time known
        if front.at(t) is False:
            new_not_top.append({"pid": p["pid"], "name": p["cmdline"] or (s or {}).get("process", ""),
                                "time": t, "started_by": p["started_by"], "reason": (s or {}).get("reason"),
                                "component": (s or {}).get("component"), "caller": (s or {}).get("caller")})
    return ({"procs": procs, "starts": starts, "app_starts": app_starts, "kills": _by_time(kills),
             "caused_starts": (logcat or {}).get("caused_starts", []),
             "activity_starts": (logcat or {}).get("activity_starts", []), "commands": commands},
            _by_time(new_not_top))


def start_cause(s, pkg, uid):
    """What made the system start a process, from a proc_starts / caused_starts record:
    "广播", or with the am_proc_start caller "应用自己（uid 10378）发起的广播", "com.android.systemui 发起的服务"."""
    reason = s.get("reason")
    what = REASON_ZH.get(reason, reason) or "原因不明"
    c = s.get("caller") or {}
    if (uid is not None and c.get("uid") == uid) or (pkg and c.get("package") == pkg):
        who = f"应用自己（uid {uid}）"
    elif c.get("package"):
        who = c["package"]
    elif c.get("uid") is not None:
        who = f"uid {c['uid']}"
    else:
        return what
    return f"{who}发起的{what}"


def _state_suffix(background):
    return "，不在前台" if background else ("，无法判断当时是否在前台" if background is None else "")


def _perm_text(o):
    return f"{o['zh']}（{o['op']}）：{'使用' if o['kind'] == 'access' else '被拒绝'}" + _state_suffix(o["background"])


def _timeline(pkg, uid, poll, logcat, processes, occurrences, clipboard, files, network, exchanges, front):
    """(timeline, events_not_top). bg=None: decide from the poll front record; bg=False: never a background event."""
    tl, not_top = [], []

    def add(time, kind, text, bg=None):
        if not time:
            return
        tl.append({"time": time, "kind": kind, "text": text})
        if bg or (bg is None and front.at(time) is False):
            not_top.append({"time": time, "what": text})

    for t in (poll or {}).get("top", []):
        if t.get("component"):
            add(t.get("start"), "front", f"前台：{t['component']}" + ("（本应用）" if t.get("package") == pkg else ""),
                bg=False)
        else:
            add(t.get("start"), "front", "没有记录到前台界面", bg=False)
    for s in (logcat or {}).get("screen", []):
        add(s.get("time"), "screen", "屏幕打开" if s.get("on") else "屏幕关闭", bg=False)

    started = set()
    for s in processes["starts"]:
        started.add(int(s["pid"]))
        add(s.get("time"), "proc", f"系统启动进程 {s.get('process')}（pid {s.get('pid')}），原因：{start_cause(s, pkg, uid)}"
            + (f" {s['component']}" if s.get("component") else ""))
    for s in processes["caused_starts"]:
        add(s.get("time"), "proc", f"系统启动其他应用的进程 {s.get('process')}（pid {s.get('pid')}），原因："
            f"{start_cause(s, pkg, uid)}" + (f" {s['component']}" if s.get("component") else ""))
    for s in processes["app_starts"]:
        started.add(s["pid"])
        add(s["time"], "proc", f"应用自己通过 app_process 启动进程（pid {s['pid']}"
            + (f"，入口 {s['main']}" if s.get("main") else "") + "）")
    for k in processes["kills"]:
        what = "被系统结束" if k.get("kind") != "died" else "结束（系统日志没有写明原因）"
        add(k.get("time"), "proc", f"进程 {k.get('process')}（pid {k.get('pid')}）{what}"
            + (f"：{k['reason']}" if k.get("reason") else ""), bg=False)
    first, last = (poll or {}).get("first_time"), (poll or {}).get("last_time")
    for p in processes["procs"]:
        if p["source"] != "poll":
            continue
        label = f"{p['cmdline'] or '（名称未知）'}（pid {p['pid']}）"
        if p.get("first_seen") != first and p["pid"] not in started:
            add(p.get("first_seen"), "proc", f"出现进程 {label}")
        if p.get("last_seen") != last:
            add(p.get("last_seen"), "proc", f"最后一次看到进程 {label}", bg=False)
    for a in processes["activity_starts"]:
        text = f"启动界面 {a.get('component')}" + (f"（{a['action']}）" if a.get("action") else "")
        add(a.get("time"), "proc", text + (f"，发起方 uid {a['caller_uid']}" if a.get("caller_uid") else ""), bg=False)

    for o in occurrences:
        if o["op"] not in CLIP_OPS:
            add(o["time"], "perm", _perm_text(o), bg=bool(o["background"]))    # unknown state: not listed as background
    for e in clipboard["events"]:
        text = f"{'读取' if e['op'] == 'read' else '写入'}剪贴板：{RESULT_ZH.get(e['result'], e['result'])}"
        add(e["time"], "clipboard", text + _state_suffix(e.get("background")), bg=bool(e.get("background")))
    for a in files.get("other_app_apks", []):
        add(a.get("first_time"), "file", f"首次读取 {a['package']} 的安装包（共 {a.get('reads')} 次）",
            bg=bool(a.get("background")))
    for e in network["endpoints"]:
        where = f"{e.get('ip')}:{e.get('port')}"
        add(e.get("first_seen"), "net", f"连接 {e['host']}（{where}，{e.get('proto')}）" if e.get("host")
            else f"连接 {where}（{e.get('proto')}）")
    # Decrypted requests, one row per source, host and second. A HAR file can hold other apps' requests:
    # those rows are not listed as things the app did while not in front.
    groups = {}
    for x in exchanges:
        if x.get("time") and "outside_capture" not in x["partial"]:
            groups.setdefault((x["source"], x.get("host"), x["time"][:19]), []).append(x)
    for (source, host, _), xs in groups.items():
        methods = Counter(x["method"] for x in xs if x.get("method"))
        text = ((f"解密到发往 {host} 的 {len(xs)} 个请求" if host else f"解密到 {len(xs)} 个不知道域名的请求")
                + ("（" + "、".join(f"{m} {n}" for m, n in methods.items()) + "）" if methods else "")
                + ("，来自代理 HAR 文件" if source == "har" else ""))
        add(xs[0]["time"], "decrypted", text, bg=False if source == "har" else None)
    return _by_time(tl), _by_time(not_top)


def _limits(meta, missing, unreadable, poll, logcat, pcap, files, network, have_pids, decrypt_limits):
    limits, done = [], set()
    # absent here, or absent or empty on the phone (collect lists those in meta.missing)
    absent = list(dict.fromkeys(missing + [m for m in meta.get("missing") or [] if m in DATA_FILES]))
    unavailable = meta.get("unavailable") or []
    if "appops_after.txt" in absent:
        limits.append("未采集到 appops_after.txt：权限使用仅来自轮询" if poll and poll.get("blocks")
                      else "未采集到 appops_after.txt，轮询也没有记录：没有权限使用记录")
        done.add("appops_after.txt")
    if "ps_before.txt" in absent and "ps_after.txt" in absent:
        limits.append("未采集到 ps_before.txt、ps_after.txt：应用进程只来自轮询和系统日志")
        done |= {"ps_before.txt", "ps_after.txt"}
    if "tcpdump" in unavailable and meta.get("net") is False:
        limits.append(UNAVAILABLE_ZH["tcpdump"])
        done.add("net.pcap")
    elif "net.pcap" in absent:
        limits.append("本次没有抓包：没有域名和流量数据" if meta.get("net") is False
                      else "未采集到 net.pcap：没有域名和流量数据")
        done.add("net.pcap")
    if "net.pcap" in unreadable:
        limits.append("net.pcap 的格式无法识别（只能读取 classic pcap，链路类型 1、113、276）：没有域名和流量数据")
    backend = meta.get("filetrace_backend", "none")
    trace_off = [UNAVAILABLE_ZH[u] for u in ("f2fs_events", "trace_filter") if u in unavailable]
    if backend == "none":
        limits += trace_off or ["本次没有启用文件跟踪：没有文件访问记录"]
    elif backend != "f2fs":
        limits.append(f"不支持的文件跟踪方式 {backend}：没有文件访问记录")
    for name in absent:
        if name not in done:
            limits.append(FILE_LIMITS.get(name, f"未采集到 {name}"))
    if poll is not None and not poll.get("blocks"):
        limits.append("poll.txt 里没有记录：无法判断应用何时在前台，也没有轮询得到的进程、连接和权限记录")
    if meta.get("autostop") in AUTOSTOP_ZH:
        limits.append(AUTOSTOP_ZH[meta["autostop"]].format(t=_hms(meta["end_time"])))

    start, end = _dt(meta["start_time"]), _dt(meta["end_time"])
    for src, label, consequence in ((poll, "轮询", "不知道前台应用和应用进程"),
                                    (logcat, "系统日志", "看不到进程启动和剪贴板记录")):
        first, last = _dt((src or {}).get("first_time")), _dt((src or {}).get("last_time"))
        if first and start and (first - start).total_seconds() > LATE_START_S:
            gap = round((first - start).total_seconds())
            limits.append(f"{label}从 {_hms(src['first_time'])} 才开始，此前 {gap} 秒{consequence}")
        if last and end and (end - last).total_seconds() > EARLY_END_S:
            gap = round((end - last).total_seconds())
            limits.append(f"{label}在 {_hms(src['last_time'])} 就结束了，此后 {gap} 秒{consequence}")
    if pcap is not None:
        if not pcap.get("packets"):
            limits.append("抓包文件里没有数据包：没有域名和流量数据")
        else:
            if pcap.get("first_epoch") and meta.get("start_epoch") and \
                    pcap["first_epoch"] - meta["start_epoch"] > LATE_START_S:
                gap = round(pcap["first_epoch"] - meta["start_epoch"])
                limits.append(f"抓包里的第一个数据包在采集开始 {gap} 秒后，此前的网络流量没有记录")
            if pcap.get("last_epoch") and meta.get("end_epoch") and \
                    meta["end_epoch"] - pcap["last_epoch"] > EARLY_END_S:
                gap = round(meta["end_epoch"] - pcap["last_epoch"])
                limits.append(f"抓包里的最后一个数据包在采集结束前 {gap} 秒，此后的网络流量没有记录")
    sync = files.get("sync")
    if files.get("events") and sync and meta.get("end_epoch"):
        last_epoch = sync["epoch"] + files["last_ts"] - sync["trace_ts"] + (files.get("clock_lag_s") or 0)
        if meta["end_epoch"] - last_epoch > EARLY_END_S:
            limits.append(f"文件跟踪的最后一条记录在采集结束前 {round(meta['end_epoch'] - last_epoch)} 秒，"
                          "此后的文件访问没有记录")
    spans = _unknown_front_spans(poll, end)
    unknown = round(sum((b - a).total_seconds() for a, b in spans))
    if unknown:
        text = f"轮询中有约 {unknown} 秒没有记录到前台界面（没有 topResumedActivity）"
        off = round(_overlap(spans, _screen_off_spans((logcat or {}).get("screen", []), end)))
        if off:
            text += f"，其中约 {off} 秒屏幕是关闭的（系统日志 screen_toggled）"
        limits.append(text + "；这段时间按应用不在前台计算")
    nameless = sum(1 for e in network["endpoints"] if not e.get("host"))
    if network["pcap"] and nameless:
        limits.append(f"应用连接的服务器中有 {nameless} 个在抓包里找不到域名（没有加密握手里的服务器名，"
                      "也没有域名解析记录），只列出 IP 地址")
    if network["sockets_sampled"]:
        limits.append("应用的网络连接每 1–2 秒查看一次：持续不到 2 秒的连接可能没有记录到")
        if network["pcap"] and not network["attributed"]:
            limits.append("轮询时一次也没有看到应用的网络连接：网络部分列出的是全手机抓包里的服务器，"
                          "不能确定哪些属于该应用")
    elif poll and poll.get("blocks"):
        limits.append("轮询没有记录应用的网络连接（S 行）" + ("：网络部分是全系统抓包里的域名，不能确定哪些属于该应用"
                                                  if network["pcap"] else ""))
    if "events" in files:          # the trace was read
        if not files["events"]:
            limits.append("文件跟踪里没有任何记录：没有文件访问记录")
        elif not have_pids:
            limits.append("没有找到应用的进程号：文件跟踪里的访问无法归到这个应用，没有文件访问记录")
        if not sync:
            limits.append("文件跟踪没有可用的时钟对照：文件访问没有具体时间")
        elif sync.get("approx"):
            lag = files.get("clock_lag_s")
            limits.append(("文件跟踪的时间是换算出来的，可能比实际早 1 秒左右" if not lag else
                           f"文件跟踪的时间是换算出来的：已按应用进程的启动时刻（系统日志）推后 {lag:.2f} 秒，"
                           f"仍可能比实际早约 {max(0.0, TRACE_CLOCK_S - lag):.1f} 秒")
                          + "；前台切换前后这段时间里的文件访问，不判断当时应用是否在前台")
    if network["pcap"]:
        limits.append("抓包在所有网卡上进行，同一个包可能被记录多次：流量字节数是约数")
    limits += decrypt_limits
    covered =set(absent) | ({"S lines in poll.txt"} if poll and poll.get("blocks") else set())
    noted = [MISSING_ZH.get(m, f"缺少 {m}") for m in meta.get("missing") or [] if m not in covered]
    if noted:
        limits.append("采集记录注明：" + "；".join(noted))
    return limits


def _highlights(result, have_poll, have_pids, occurrences, new_not_top, kept_fg):
    notable, info = [], []
    meta, bg, procs = result["meta"], result["background"], result["processes"]
    started_by = {p["pid"]: p.get("started_by") for p in procs["procs"]}

    overview = f"采集 {meta['duration_s']} 秒（{_hms(meta['start_time'])} 至 {_hms(meta['end_time'])}）"
    if have_poll:
        overview += f"；应用在前台约 {bg['seconds_top']} 秒，不在前台约 {bg['seconds_not_top']} 秒"
        if bg["cpu_ticks_not_top"]:
            cpu = f"{bg['cpu_ticks_not_top'] / 100:.1f}"
            overview += (f"，不在前台时用了至少约 {cpu} 秒 CPU 时间（不含轮询没有看到的 {bg['procs_not_polled']} 个进程）"
                         if bg.get("procs_not_polled") else f"，不在前台时用了约 {cpu} 秒 CPU 时间")
    info.append(overview + "。")

    files = result["files"]
    apks = files.get("other_app_apks") or []
    if apks:
        # Readers the app started itself with app_process, and the others (for example the main
        # process, which also reads other packages' code it loads, such as Google Play services).
        own = [a for a in apks if any(started_by.get(p) == "app" for p in a.get("pids") or ())]
        others = [a for a in apks if any(started_by.get(p) != "app" for p in a.get("pids") or ())]
        pool = [a for a in own if a not in others] or apks
        examples = sorted(pool, key=lambda a: -(a.get("reads") or 0))[:5]
        text = f"读取了 {len(apks)} 个其他应用的安装包，如 " + "、".join(a["package"] for a in examples)
        times = sorted(t for a in apks if (t := a.get("first_time")))
        if times:
            text += f"；首次读取的时间在 {_hms(times[0])} 至 {_hms(times[-1])} 之间"
            n_bg = sum(1 for a in apks if a.get("background"))
            if n_bg:
                text += f"，其中 {n_bg} 个是在应用不在前台时首次读取的"
        if own:
            text += f"；应用自己通过 app_process 启动的进程读取了其中 {len(own)} 个"
            if others:
                readers = sorted({p for a in others for p in a.get("pids") or () if started_by.get(p) != "app"})
                names = {p["pid"]: p["cmdline"] for p in procs["procs"]}
                text += ("，" + "、".join(f"{names.get(p) or '（名称未知）'}（pid {p}）" for p in readers)
                         + f"读取了其中 {len(others)} 个：" + "、".join(a["package"] for a in others[:3])
                         + ("等" if len(others) > 3 else ""))
        notable.append(text + "。")
    data = files.get("other_app_data") or []
    if data:
        shown = []
        for d in data[:5]:
            paths = d.get("paths") or []
            shown.append(d["package"] + (f"（{'、'.join(paths[:3])}{'等' if len(paths) > 3 else ''}）" if paths else ""))
        notable.append(f"访问了 {len(data)} 个其他应用的数据目录（{_rw(data)}）：" + "、".join(shown)
                       + ("等" if len(data) > 5 else "") + "。")
    shared = files.get("shared_storage") or []
    if shared:
        info.append(f"访问了共享存储中 {len(shared)} 个目录的文件（{_rw(shared)}），如 "
                    + "、".join(d["dir"] for d in shared[:3]) + "。")
    if files.get("events") and have_pids and not data and not shared:
        info.append("没有访问其他应用的数据目录，也没有访问共享存储（/sdcard 下的照片、下载等公共文件）。")

    front_use, front_reject, unknown_use = {}, {}, {}
    for (op, kind), occ in _group(o for o in occurrences if o["op"] not in CLIP_OPS).items():
        o0 = occ[0]
        label = f"{o0['zh']}（{op}）"
        bg_occ = [o for o in occ if o["background"]]
        if bg_occ and (o0["sensitive"] or kind == "reject"):
            what = f"使用了{label}" if kind == "access" else f"尝试使用{label}，被系统拒绝"
            notable.append(f"不在前台时{what}，记录到 {len(bg_occ)} 次，最后一次在 {_hms(bg_occ[-1]['time'])}。")
        fg = sum(1 for o in occ if o["background"] is False)
        unknown = [o for o in occ if o["background"] is None]
        if kind == "access" and o0["sensitive"]:
            if fg:
                front_use[label] = fg
            if unknown:
                unknown_use[label] = unknown
        elif fg and kind == "reject":
            front_reject[label] = fg
    if front_use:
        info.append("在前台时使用了：" + "、".join(f"{k}{n} 次" for k, n in front_use.items()) + "。")
    if unknown_use:
        info.append("无法判断当时应用是否在前台（发生在前台切换前后，或轮询开始之前）："
                    + "、".join(f"{k}{len(v)} 次（{'、'.join(_hms(o['time']) for o in v)}）"
                               for k, v in unknown_use.items()) + "。")
    if front_reject:
        info.append("在前台时被系统拒绝：" + "、".join(f"{k}{n} 次" for k, n in front_reject.items()) + "。")

    clip = result["clipboard"]
    reads = [e for e in clip["events"] if e["op"] == "read"]
    if reads:
        text = f"读取剪贴板 {len(reads)} 次（{_hms(reads[0]['time'])} 至 {_hms(reads[-1]['time'])}）"
        blocked = sum(e["result"] == "blocked" for e in reads)
        if blocked:
            text += f"，其中 {blocked} 次{RESULT_ZH['blocked']}，没有拿到内容"
        n_bg = sum(bool(e.get("background")) for e in reads)
        if n_bg:
            text += f"；{n_bg} 次发生在不在前台时"
        notable.append(text + "。")
    if clip["writes"]:
        info.append(f"写入剪贴板 {clip['writes']} 次。")

    pkg, uid = meta["package"], meta.get("uid")
    if new_not_top:
        by_app = [p for p in new_not_top if p.get("started_by") == "app"]
        parts = []
        if by_app:
            when = _hms(by_app[0]["time"]) + ("" if len(by_app) == 1 else f" 至 {_hms(by_app[-1]['time'])}")
            parts.append(f"{len(by_app)} 个是应用自己通过 app_process 启动的（pid "
                         + "、".join(str(p["pid"]) for p in by_app) + f"，{when}）")
        for p in new_not_top:
            if p.get("started_by") == "app":
                continue
            s = f"{p['name'] or '（名称未知）'}（pid {p['pid']}，{_hms(p['time'])}"
            if p.get("reason"):
                s += f"，系统启动，原因：{start_cause(p, pkg, uid)}" + (f"，组件 {p['component']}" if p.get("component") else "")
            parts.append(s + "）")
        notable.append(f"不在前台时新出现了 {len(new_not_top)} 个应用进程：" + "；".join(parts) + "。")
    if kept_fg:
        parts = []
        for p in kept_fg:
            how = "，应用自己通过 app_process 启动" if p.get("started_by") == "app" else ""
            parts.append(f"{p['cmdline'] or '（名称未知）'}（pid {p['pid']}{how}，{_hms(p['first_seen'])} 起）")
        notable.append(f"应用不在前台时，有 {len(kept_fg)} 个应用进程一直运行到采集结束，"
                       "它们的内存回收优先级（oom_score_adj）始终是 0，与前台应用相同：" + "、".join(parts) + "。")
    if procs["commands"]:
        notable.append(f"应用的身份（{meta['app_id']}）下运行了 {len(procs['commands'])} 个进程名不是应用自己的程序："
                       + "、".join(f"{c['cmdline']}（pid {c['pid']}）" for c in procs["commands"]) + "。")
    n_kill = sum(1 for k in procs["kills"] if k.get("kind") != "died")
    n_died = len(procs["kills"]) - n_kill
    if n_kill:
        info.append(f"系统结束了应用的进程 {n_kill} 次。")
    if n_died:
        info.append(f"应用的进程另有 {n_died} 次结束，系统日志没有写明原因。")
    if procs["activity_starts"]:
        info.append(f"应用的界面被启动了 {len(procs['activity_starts'])} 次。")

    net = result["network"]
    if net["endpoints"]:
        hosts = list(dict.fromkeys(e["host"] for e in net["endpoints"] if e.get("host")))
        text = f"应用连接了 {len(net['endpoints'])} 个远程地址"
        if hosts:
            text += f"，其中 {len(hosts)} 个域名：" + "、".join(hosts[:5]) + ("等" if len(hosts) > 5 else "")
        total = sum((e.get("bytes_out") or 0) + (e.get("bytes_in") or 0) for e in net["endpoints"])
        if total:
            text += f"；收发约 {total / 1024:.0f} KB"
        info.append(text + "。")
    elif net.get("sockets_sampled"):
        info.append("每 1–2 秒查看一次应用的网络连接，采集期间一次也没有看到。")
    if not net["endpoints"] and net["hosts_unattributed"]:
        rows = sorted(net["hosts_unattributed"], key=lambda h: -(h.get("bytes") or 0))
        # A row without host_source has no name: its host is the bare IP address.
        names = list(dict.fromkeys(h["host"] for h in rows if h.get("host") and h.get("host_source")))
        ips = {h["host"] for h in rows if h.get("host") and not h.get("host_source")}
        if names:
            text = (f"全系统抓包中出现了 {len(names)} 个域名（不能确定哪些属于该应用），流量最多的是："
                    + "、".join(names[:5]))
            if ips:
                text += f"；另有 {len(ips)} 个只有 IP 地址的服务器"
        else:
            text = f"全系统抓包中没有域名，只有 {len(ips)} 个服务器的 IP 地址（不能确定哪些属于该应用）"
        info.append(text + "。")

    dec = result["decrypted"]
    if result["captured"].get("decrypted"):
        xs = dec["exchanges"]
        if xs:
            named = [h["host"] for h in dec["hosts"] if h["host"]]
            text = decrypted_summary(dec)
            if named:
                text += "；请求最多的域名是 " + "、".join(named[:3])
            if (dec["har"] or {}).get("outside_window"):
                text += f"；其中 {dec['har']['outside_window']} 个不在本次采集时间内"
            if "har" in dec["sources"]:
                text += "；HAR 文件里可能有手机上其他应用的请求"
            info.append(text + "。")
        else:
            used = "、".join(DECRYPT_SOURCE_ZH[s] for s in ("ecapture", "keylog", "har") if dec.get(s) is not None)
            info.append(f"进行了解密（{used}），但没有解密到任何请求。")
        # the key route knows each connection; the others only host names
        coverage = keylog_coverage_text(dec["keylog"]) if dec.get("keylog") else coverage_text(dec, net["endpoints"])
        if coverage:
            info.append(coverage)
    elif dec.get("keylog_error"):
        info.append(f"有加密连接的密钥记录（tls_keys.log），但没能用它解密抓包：{dec['keylog_error'].rstrip('。')}。")

    return [{"level": "notable", "text": t} for t in notable] + [{"level": "info", "text": t} for t in info]


def _rw(rows):
    return f"读 {sum(r.get('reads') or 0 for r in rows)} 次、写 {sum(r.get('writes') or 0 for r in rows)} 次"


def _group(occurrences):
    groups = {}
    for o in occurrences:
        groups.setdefault((o["op"], o["kind"]), []).append(o)
    return groups
