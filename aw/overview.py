"""The overview of a run (docs/CONTRACT_PHONE.md, "The overview", "Categories", "Ranking"): per app a few
counted facts (bars), the details behind them (sections) and the files to download, apps ranked by what
they took.

Both producers fill the same per-app facts record and hand it to build_app: aw.phonewide for phone runs,
from_app_result here for one-app runs (from the existing result.json). Everything in an APP is for the page,
which shows no captured value: names and counts only. Values are in the downloads.

How the facts are read:

- An EVENT counts `count` times, except in the categories that count things (installed_apps: other apps,
  other_app_data: other apps, photos: folders): there an event whose `code` is not an appops operation name
  (upper case and underscores) stands for one thing, and `count` is how often it was accessed.
- `front` None (not known whether the app was in front) counts as seen, but not as seen while not in front.
- sent_data weighs 2 only when a request carried one of the kinds of information below; otherwise 1.
- A request with source "cleartext" went out without encryption (cleartext HTTP, read straight from the capture);
  the others were decrypted. sent_data counts both, its bar's "cleartext" the cleartext ones, and the overview's
  "cleartext" (cleartext_summary) lists per app what went out without encryption.
"""

import bisect
import ipaddress
import json
import re
import shutil
import unicodedata
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode

from aw import __version__
from aw.exchange import header, sensitive_kind
from aw.parse_appops import op_info

CATEGORIES = (            # (key, title, weight); the order breaks ties between bars
    ("location", "定位", 3),
    ("camera", "相机", 3),
    ("microphone", "麦克风", 3),
    ("contacts", "通讯录", 3),
    ("sms", "短信", 3),
    ("call_log", "通话记录", 3),
    ("calendar", "日历", 2),
    ("phone_state", "手机号和设备信息", 2),
    ("photos", "相册和文件", 3),
    ("clipboard", "剪贴板", 3),
    ("installed_apps", "你装了哪些应用", 3),
    ("other_app_data", "其他应用的数据", 3),
    ("sensors", "传感器和运动状态", 2),
    ("background_start", "后台自己启动", 1),
    ("network", "联网", 1),
    ("sent_data", "发出去的信息", 2),
    ("other", "其他权限", 1),
)
TITLE = {k: t for k, t, _ in CATEGORIES}
WEIGHT = {k: w for k, _, w in CATEGORIES}
_ORDER = {k: i for i, (k, _, _) in enumerate(CATEGORIES)}
# What a bar says before its count ("访问通讯录 3 次"); the categories not listed use their title.
BAR_TITLE = {"camera": "用相机", "microphone": "用麦克风", "contacts": "访问通讯录", "sms": "访问短信",
             "call_log": "访问通话记录", "calendar": "访问日历", "phone_state": "读手机号和设备信息",
             "photos": "访问相册和文件", "clipboard": "读剪贴板", "installed_apps": "查看你装了哪些应用",
             "other_app_data": "访问其他应用的数据", "sensors": "用传感器"}
# Operations every app uses to work and that take nothing from the owner: not in the overview (they stay in
# the downloads).
_ROUTINE = {"WAKE_LOCK", "VIBRATE", "TOAST_WINDOW", "TAKE_AUDIO_FOCUS", "START_FOREGROUND", "PLAY_AUDIO"}


def _routine(code):
    return code in _ROUTINE or (code or "").startswith("AUDIO_")

# The category of each appops operation; every other operation is "other". The two *_SOURCE operations are not
# in aw.parse_appops but occur on the phone (fixtures/phone_1119).
_OPS = {
    "location": ("COARSE_LOCATION", "FINE_LOCATION", "GPS", "MONITOR_LOCATION", "MONITOR_HIGH_POWER_LOCATION",
                 "WIFI_SCAN", "NEIGHBORING_CELLS", "ACCESS_MEDIA_LOCATION", "FINE_LOCATION_SOURCE",
                 "COARSE_LOCATION_SOURCE"),
    "camera": ("CAMERA", "PHONE_CALL_CAMERA"),
    "microphone": ("RECORD_AUDIO", "PHONE_CALL_MICROPHONE", "RECORD_AUDIO_HOTWORD", "RECORD_AUDIO_OUTPUT"),
    "contacts": ("READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"),
    "sms": ("READ_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "SEND_SMS", "WRITE_SMS", "READ_ICC_SMS",
            "WRITE_ICC_SMS", "READ_CELL_BROADCASTS", "RECEIVE_EMERGECY_SMS"),
    "call_log": ("READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS"),
    "calendar": ("READ_CALENDAR", "WRITE_CALENDAR"),
    "phone_state": ("READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_DEVICE_IDENTIFIERS",
                    "USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER"),
    "photos": ("READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_AUDIO",
               "WRITE_MEDIA_AUDIO", "READ_MEDIA_VIDEO", "WRITE_MEDIA_VIDEO", "READ_MEDIA_IMAGES",
               "WRITE_MEDIA_IMAGES", "READ_MEDIA_VISUAL_USER_SELECTED", "MANAGE_MEDIA"),
    "clipboard": ("READ_CLIPBOARD", "WRITE_CLIPBOARD"),
    # which apps are installed, and which ones you use
    "installed_apps": ("GET_INSTALLED_APPS", "QUERY_ALL_PACKAGES", "GET_USAGE_STATS"),
    "sensors": ("BODY_SENSORS", "DIRECTION_SENSORS", "ACTIVITY_RECOGNITION"),
}
_OP_CATEGORY = {op: key for key, ops in _OPS.items() for op in ops}
_OP_CODE = re.compile(r"[A-Z][A-Z0-9_]+")
_PER_THING = {"installed_apps": "个", "other_app_data": "个应用", "photos": "个文件夹"}
# One location fix is often recorded under several of these at once.
_LOCATION_BUNDLE = {"COARSE_LOCATION", "FINE_LOCATION", "GPS", "MONITOR_LOCATION", "MONITOR_HIGH_POWER_LOCATION"}

ROWS_MAX = 50
WHEN_ZH = {True: "你正在用它", False: "你没打开它", None: "不确定"}
# "用了 3 次定位": the verb and what follows the count, per category
_PHRASE = {
    "location": ("用了", "定位"), "camera": ("用了", "相机"), "microphone": ("用了", "麦克风"),
    "contacts": ("用了", "通讯录权限"), "sms": ("用了", "短信权限"), "call_log": ("用了", "通话记录权限"),
    "calendar": ("用了", "日历权限"), "phone_state": ("读取了", "手机号和设备信息"),
    "photos": ("用了", "相册和文件权限"), "clipboard": ("用了", "剪贴板"),
    "installed_apps": ("查询了", "已安装或常用的应用"), "other_app_data": ("访问了", "其他应用的数据"),
    "sensors": ("用了", "传感器"), "background_start": ("启动了", ""), "other": ("用了", "其他权限"),
}

# Kinds of information a request's field names show (sent_data). sensitive_kind's "identity" is split into
# account and device identifiers; its "signature" is not information about the phone's owner.
KIND_ZH = {"device": "设备标识", "account": "账号标识", "location": "位置", "address": "手机的网络地址",
           "credential": "登录凭据"}
_ACCOUNT = re.compile(r"(?:^|[-_.])(?:uid|user[-_.]?id|openid|unionid)(?:[-_.]|$)")
_LOCATION = {"lat", "lng", "lon", "latitude", "longitude", "gps", "geo", "geohash", "location", "coord", "coords",
             "coordinate", "coordinates"}
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_PAIR_NAME = re.compile(r"(?:^|[&;,?#\s])([A-Za-z_][\w.-]{0,63})\s*=")
_JSON_KEY = re.compile(r'"((?:[^"\\\r\n]|\\.){1,64})"\s*:')

DOWNLOAD_TITLE = {"requests.har": "看到的全部请求（HAR 格式，含完整内容）",
                  "detail.json": "全部明细（JSON 格式，含技术名称）",
                  "report.html": "详细报告（网页）"}
_HTTP_VERSION = {"h2": "HTTP/2", "http/1.1": "HTTP/1.1", "http/1.0": "HTTP/1.0", "h3": "HTTP/3"}
_ACTIVITY_REASONS = {"activity", "top-activity", "next-activity", "next-top-activity"}
_REASON_ZH = {"broadcast": "广播", "service": "服务", "content provider": "数据接口调用", "backup": "备份",
              "restart": "重启"}


def category_of(op: str) -> str:
    """The category key of an appops operation name; "other" for one that fits no category."""
    return _OP_CATEGORY.get(op, "other")


def _dt(s):
    if not s:
        return None
    try:
        return datetime.strptime(s[:23], "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _hms(s):
    return s[11:19] if s and len(s) >= 19 else "—"


def _times(n, at_least):
    return f"至少 {n} 次" if at_least else f"{n} 次"


def _size(n):
    if n < 1024:
        return f"{n} 字节"
    if n < 1024 * 1024:
        return f"约 {n / 1024:.0f} KB"
    return f"约 {n / 1024 / 1024:.1f} MB"


def _is_op(code):
    return bool(_OP_CODE.fullmatch(code or ""))


# A label of a host name that looks like a token or an identifier: 32 or more letters and digits with both,
# the rule aw.exchange hides values by (fixtures/phone_1119 has a server named after a 63-digit hex label).
_TOKEN_LABEL = re.compile(r"(?=[^.]*[0-9])(?=[^.]*[A-Za-z])[A-Za-z0-9_-]{32,}")


def _shown_host(host):
    """A server's name as the page shows it: a label that looks like an identifier is replaced."""
    return ".".join("〈编号〉" if _TOKEN_LABEL.fullmatch(p) else p for p in host.split("."))


def _is_address(host):
    """Whether a request's host (as in its Host header: a port, brackets and a zone may come with it) is a
    server address, not a name. A cleartext request's Host is often one; the page shows no addresses."""
    h = host.strip()
    if h.startswith("["):
        h = h[1:].partition("]")[0]
    elif h.count(":") == 1:
        h = h.partition(":")[0]
    try:
        ipaddress.ip_address(h.partition("%")[0])
        return True
    except ValueError:
        return False


def _request_host(host):
    """A request's host as the page shows it; None when there is no name (none, or only an address)."""
    if not host or _is_address(host):
        return None
    return _shown_host(host)


def _cleartext(x):
    return x.get("source") == "cleartext"


def _level(weight, front, background):
    if weight == 3 and background:
        return "high"
    if (weight == 3 and front) or (weight == 2 and background):
        return "medium"
    return "low"


_LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


# -- one category from events -------------------------------------------------------------------------------

def _when_tail(n, b, u, unit, suffix=""):
    """(tail, clause) about when: all while not in front, all while in front, or a clause for the part."""
    every = "都" if n > 1 else ""
    if b == n:
        return f"，{every}是在你没打开它的时候{suffix}", None
    if b == 0 and u == 0:
        return f"，{every}是在你正在用它的时候{suffix}", None
    if b == 0:
        return "", (f"{n - u}{unit}是在你正在用它的时候{suffix}" if u < n else None)
    return "", f"{b}{unit}是在你没打开它的时候{suffix}"


def _among(clauses):
    """"，其中 …" for the clauses about a part, or ""."""
    text = "，".join(clauses)
    return f"，其中{'' if text.startswith('至少') else ' '}{text}" if text else ""


def _unknown_sentence(n, u, unit):
    if not u:
        return ""
    return "无法判断当时你是不是正在用它。" if u == n else f"有 {u}{unit}无法判断当时你是不是正在用它。"


def _ops_sentence(key, evs):
    n = sum(e["count"] for e in evs)
    al = any(e.get("at_least") for e in evs)
    d = sum(e["count"] for e in evs if e.get("denied"))
    bg = [e for e in evs if e.get("front") is False]
    b, u = sum(e["count"] for e in bg), sum(e["count"] for e in evs if e.get("front") is None)
    verb, noun = _PHRASE[key]
    whats = Counter()
    for e in evs:
        whats[e.get("what") or ""] += e["count"]
    if key == "background_start" or not any(whats):
        breakdown = ""
    elif len(whats) == 1:
        breakdown = "" if next(iter(whats)) == noun else f"（{next(iter(whats))}）"
    else:
        shown = whats.most_common(5)
        breakdown = "（" + "、".join(f"{w} {k} 次" for w, k in shown) + ("等" if len(whats) > 5 else "") + "）"
    least = ("它的进程" if key == "background_start" else "") + ("至少" if al else "")
    if d == n:
        lead = f"{least}想{verb.removesuffix('了')} {n} 次{noun}{breakdown}，{'都' if n > 1 else ''}被系统拒绝了"
    else:
        lead = f"{least}{verb} {n} 次{noun}{breakdown}"
    tail, when = _when_tail(n, b, u, " 次")
    if when and b and any(e.get("at_least") for e in bg):
        when = "至少 " + when
    clauses = ([f"{_times(d, any(e.get('at_least') for e in evs if e.get('denied')))}被系统拒绝"]
               if 0 < d < n else []) + ([when] if when else [])
    return lead + tail + _among(clauses) + "。" + _unknown_sentence(n, u, " 次")


def _things_sentence(key, evs):
    n, total = len(evs), sum(e["count"] for e in evs)
    least = "至少" if any(e.get("at_least") for e in evs) else ""
    b = sum(1 for e in evs if e.get("front") is False)
    u = sum(1 for e in evs if e.get("front") is None)
    if key == "installed_apps":
        lead = (f"{least}读取了 {n} 个其他应用的安装包（安装包里是那个应用的程序和资源，能读到就说明你装了这个应用）")
        suffix = "第一次读取的"
    elif key == "other_app_data":
        lead = f"{least}访问了 {n} 个其他应用存放自己数据的地方（共 {total} 次），那里存的是那个应用自己的设置和记录"
        suffix = ""
    else:
        lead = f"{least}读写了公共文件夹（照片、下载、文档等）里 {n} 个文件夹的文件（共 {total} 次）"
        suffix = ""
    tail, when = _when_tail(n, b, u, " 个", suffix)
    return lead + tail + _among([when] if when else []) + "。" + _unknown_sentence(n, u, " 个")


def _event_rows(evs, technical):
    denied = any(e.get("denied") for e in evs)
    counts = technical or any(e["count"] != 1 for e in evs)
    columns = ["时间", "做了什么", "当时"] + (["结果"] if denied else []) + (["次数"] if counts else []) \
        + (["技术名称"] if technical else [])
    rows = []
    for e in sorted(evs, key=lambda e: (_dt(e.get("time")) or datetime.max, e.get("what") or "")):
        row = [(e.get("time") or "—") if technical else _hms(e.get("time")), e.get("what") or "", WHEN_ZH[e.get("front")]]
        if denied:
            row.append("被系统拒绝" if e.get("denied") else ("允许" if _is_op(e.get("code")) else "—"))
        if counts:
            row.append(e["count"])
        if technical:
            row.append(e.get("code") or "")
        rows.append(row)
    return columns, rows


def _events_part(key, evs, technical):
    is_thing = [key in _PER_THING and not _is_op(e.get("code")) for e in evs]
    things = [e for e, t in zip(evs, is_thing) if t]
    ops = [e for e, t in zip(evs, is_thing) if not t]
    title = TITLE[key]
    summary = ""
    count = background = denied = 0
    if things:
        count += len(things)
        background += sum(1 for e in things if e.get("front") is False)
        denied += sum(1 for e in things if e.get("denied"))
        summary += _things_sentence(key, things)
    if ops:
        count += sum(e["count"] for e in ops)
        background += sum(e["count"] for e in ops if e.get("front") is False)
        denied += sum(e["count"] for e in ops if e.get("denied"))
        summary += _ops_sentence(key, ops)
        codes = {e.get("code") for e in ops}
        if key == "location" and len(codes & _LOCATION_BUNDLE) >= 2:
            summary += "系统每次定位往往会同时记下好几项（例如精确位置和 GPS 定位），这里每一项分开计数。"
        if key == "clipboard" and any(e.get("denied") and "读" in (e.get("what") or "") for e in ops):
            summary += "被系统拒绝的那几次，它没有拿到剪贴板里的内容。"
    columns, rows = _event_rows(evs, technical)
    return {"key": key, "weight": WEIGHT[key],
            "front": any(e.get("front") is not False for e in evs),
            "background": any(e.get("front") is False for e in evs),
            "text": f"{BAR_TITLE.get(key, title)} {_times(count, any(e.get('at_least') for e in evs))}", "count": count, "background_count": background,
            "denied": denied, "summary": summary, "columns": columns, "rows": rows}


# -- network and sent data -----------------------------------------------------------------------------------

def _network_part(net, technical):
    eps = net.get("endpoints") or []
    if not eps:
        return None
    servers = {}
    for e in eps:
        # a server without a name is its address without the port: one machine, however many ports
        key = e.get("host") or (e.get("address") or "").rpartition(":")[0] or e.get("address")
        s = servers.setdefault(key, {"named": bool(e.get("host")), "bytes": 0,
                                                                    "front": False, "background": False})
        s["bytes"] += e.get("bytes") or 0
        s["front"] |= bool(e.get("front"))
        s["background"] |= bool(e.get("background"))
    n = len(servers)
    b = sum(1 for s in servers.values() if s["background"])
    u = sum(1 for s in servers.values() if not s["front"] and not s["background"])
    nameless = sum(1 for s in servers.values() if not s["named"])
    total = sum(s["bytes"] for s in servers.values())
    tail, when = _when_tail(n, b, u, " 个")
    if b == n and any(s["front"] for s in servers.values()):     # not only while it was not in front
        tail = f"，在你没打开它的时候也{'都' if n > 1 else ''}连着"
    elif when and b:
        when = f"{b} 个在你没打开它的时候也连着"
    if nameless == n:
        names = f"（{'都' if n > 1 else ''}只知道地址，不知道域名）"
    else:
        names = f"（其中 {nameless} 个只知道地址，不知道域名）" if nameless else ""
    size = _size(total)
    summary = (f"连了 {n} 个服务器" + names + (f"，收发{'' if size.startswith('约') else ' '}{size}" if total else "")
               + tail + _among([when] if when else []) + "。" + _unknown_sentence(n, u, " 个"))
    if net.get("not_decrypted"):
        summary += f"它有 {net['not_decrypted']} 个加密连接的内容没能解开。"

    def when_of(f, bg):
        return "两种时候都有" if f and bg else WHEN_ZH[True if f else (False if bg else None)]

    if technical:
        columns = ["服务器", "地址", "连接数", "数据量（字节）", "当时"]
        rows = [[e.get("host") or "", e.get("address") or "", e.get("connections") or 0, e.get("bytes") or 0,
                 when_of(e.get("front"), e.get("background"))]
                for e in sorted(eps, key=lambda e: -(e.get("bytes") or 0))]
    else:
        columns = ["服务器", "数据量", "当时"]
        named = sorted(((h, s) for h, s in servers.items() if s["named"]), key=lambda hs: (-hs[1]["bytes"], hs[0]))
        rows = [[_shown_host(h), _size(s["bytes"]), when_of(s["front"], s["background"])] for h, s in named]
        rest = [s for s in servers.values() if not s["named"]]
        if rest:
            rows.append([f"不知道域名的服务器（{len(rest)} 个）", _size(sum(s["bytes"] for s in rest)),
                         when_of(any(s["front"] for s in rest), any(s["background"] for s in rest))])
    return {"key": "network", "weight": WEIGHT["network"],
            "front": any(s["front"] or not s["background"] for s in servers.values()), "background": b > 0,
            "text": f"{TITLE['network']} {n} 个服务器", "count": n, "background_count": b, "denied": 0,
            "summary": summary, "columns": columns, "rows": rows}


def _norm(name):
    return _CAMEL.sub("_", name or "").lower()


def _kind_of(name):
    """The kind of information a field name shows (KIND_ZH's keys), or None. A name says what it is in its last
    word or two (context_ip_type is a type, enable_location_permission a permission; on
    fixtures/live_xhs_keylog_1119 a match anywhere in the name took in both); a last word "id" is also left off
    (page_session_id names a session)."""
    words = [w for w in re.split(r"[-_.]+", _norm(name)) if w]
    for ws in [words] + ([words[:-1]] if len(words) > 1 and words[-1] in ("id", "ids") else []):
        for k in (1, 2):
            tail, head = "_".join(ws[-k:]), "_".join(ws[-k:-1])
            kind = sensitive_kind(tail)
            if kind and not sensitive_kind(head):       # the match takes in the last word
                if kind == "identity":
                    return "account" if _ACCOUNT.search(tail) else "device"
                return kind if kind in ("credential", "address") else None
        if ws and ws[-1] in _LOCATION:
            return "location"
    return None


def _field_names(x):
    """The names of the fields a request carried: headers, name=value pairs inside header values, query, form and
    JSON body fields. Bodies that are not text (binary) are not examined."""
    req = x.get("request") or {}
    names = []
    for k, v in req.get("headers") or []:
        if k.startswith(":"):
            continue
        names.append(k)
        if "=" in (v or ""):
            names += _PAIR_NAME.findall(v)
    names += [k for k, _ in x.get("query") or []]
    body = req.get("body") or {}
    text = body.get("text")
    if text:
        if body.get("kind") == "form":
            names += [k for k, _ in parse_qsl(text, keep_blank_values=True)]
        elif body.get("kind") in ("json", "text"):
            names += _JSON_KEY.findall(text)
    return names


def _kinds(x):
    """{kind: Counter of the field names that show it} for one request."""
    out = {}
    for name in _field_names(x):
        kind = _kind_of(name)
        if kind:
            out.setdefault(kind, Counter())[name] += 1
    return out


def _sent_part(requests, technical):
    if not requests:
        return None
    per = [(x, _kinds(x)) for x in requests]
    n = len(per)
    b = sum(1 for x, _ in per if x.get("front") is False)
    u = sum(1 for x, _ in per if x.get("front") is None)
    clear = sum(1 for x, _ in per if _cleartext(x))
    hosts = Counter(x.get("host") for x, _ in per)
    with_kind = Counter(k for _, ks in per for k in ks)
    order = [k for k in KIND_ZH if with_kind[k]]
    tail, when = _when_tail(n, b, u, " 个")
    if when and b:
        when = f"{b} 个是在你没打开它的时候发的"
    if not clear:
        lead = f"解密后看到它发出了 {n} 个请求"
    elif clear == n:
        lead = f"看到它没加密就发出了 {n} 个请求（明文 HTTP）"
    else:
        lead = f"看到它发出了 {n} 个请求（{n - clear} 个是解密后看到的，{clear} 个没加密，用的是明文 HTTP）"
    summary = (lead + f"，发往 {len(hosts)} 个服务器" + tail + _among([when] if when else [])
               + "。" + _unknown_sentence(n, u, " 个"))
    if order:
        summary += "按字段名来看，" + "，".join(f"{with_kind[k]} 个请求里有{KIND_ZH[k]}类的字段" for k in order) + "。"
    else:
        summary += "按字段名来看，请求里没有设备标识、账号标识、位置、手机的网络地址或登录凭据类的字段。"
    if clear:
        summary += "没加密的请求在路上谁都看得到：同一个网络里的其他人（例如同一个 Wi-Fi 上的人）和网络运营商都能看到它的内容。"
    binary = sum(1 for x, _ in per if ((x.get("request") or {}).get("body") or {}).get("kind") == "binary")
    if binary:
        summary += f"有 {binary} 个请求发出的内容不是文字，看不出里面带了什么。"
    summary += "每个请求的完整内容可以在下面下载。"
    text = f"{TITLE['sent_data']} {n} 次"
    if order:
        text += "，含" + "、".join(KIND_ZH[k] for k in order[:2]) + ("等" if len(order) > 2 else "") + "字段"
    if technical:
        columns = ["时间", "方法", "服务器", "路径", "状态", "当时", "带了哪些信息", "字段名", "不完整的原因", "加密"]
        rows = [[x.get("time") or "", x.get("method") or "", x.get("host") or "", x.get("path") or "",
                 (x.get("response") or {}).get("status") or "", WHEN_ZH[x.get("front")],
                 "、".join(KIND_ZH[k] for k in KIND_ZH if k in ks),
                 "、".join(sorted({nm for c in ks.values() for nm in c})), "、".join(x.get("partial") or []),
                 "没加密（明文 HTTP）" if _cleartext(x) else "解密后看到"]
                for x, ks in per]
    else:
        columns = ["服务器", "请求数"] + (["其中没加密"] if clear else []) + ["你没打开它时", "带了哪些信息"]
        rows = []
        for host, count in sorted(hosts.items(), key=lambda hc: (-hc[1], hc[0] or "")):
            mine = [(x, ks) for x, ks in per if x.get("host") == host]
            kinds = {k for _, ks in mine for k in ks}
            rows.append([_request_host(host) or "（不知道域名）", count]
                        + ([sum(1 for x, _ in mine if _cleartext(x))] if clear else [])
                        + [sum(1 for x, _ in mine if x.get("front") is False),
                           "、".join(KIND_ZH[k] for k in KIND_ZH if k in kinds) or "—"])
    return {"key": "sent_data", "weight": WEIGHT["sent_data"] if order else 1,
            "front": b < n, "background": b > 0,
            "text": text, "count": n, "background_count": b, "denied": 0, "cleartext": clear,
            "summary": summary, "columns": columns, "rows": rows}


def cleartext_summary(facts_list, checked=True, note=None, unattributed=(), system=0) -> dict:
    """The overview's "cleartext": which apps sent requests without encryption (source "cleartext"), with names and
    counts only. facts_list: the listed apps' facts; checked: whether the capture was read for them (note: why not,
    one sentence); unattributed: the cleartext requests no app could be found for; system: how many the system sent."""
    apps = []
    for f in facts_list:
        xs = [x for x in f.get("requests") or [] if _cleartext(x)]
        if not xs:
            continue
        hosts = Counter(_request_host(x.get("host")) for x in xs)
        kinds = {k for x in xs for k in _kinds(x)}
        apps.append({"package": f["package"], "label": f.get("label"), "requests": len(xs),
                     "background": sum(1 for x in xs if x.get("front") is False),
                     "hosts": [[h, c] for h, c in sorted(hosts.items(), key=lambda hc: (-hc[1], hc[0] is None, hc[0] or ""))],
                     "kinds": [KIND_ZH[k] for k in KIND_ZH if k in kinds]})
    apps.sort(key=lambda a: (-len(a["kinds"]), -a["requests"], a["package"]))
    others = Counter(_request_host(x.get("host")) for x in unattributed)
    return {"checked": bool(checked), "note": note, "requests": sum(a["requests"] for a in apps), "apps": apps,
            "unattributed": {"requests": len(unattributed),
                             "hosts": [[h, c] for h, c in sorted(others.items(), key=lambda hc: (-hc[1], hc[0] is None, hc[0] or ""))]},
            "system": system}


def _hosts_text(hosts, limit=5):
    """"发往 a.example（2 次）、…": a space only before a name, not before Chinese text."""
    named = [f"{h}（{c} 次）" for h, c in hosts if h]
    nameless = sum(c for h, c in hosts if not h)
    if nameless:
        named.append(f"只知道地址的服务器（{nameless} 次）")
    text = "、".join(named[:limit]) + (f" 等 {len(named)} 个" if len(named) > limit else "")
    return ("发往 " if text[:1].isascii() else "发往") + text


def cleartext_lines(overview: dict, names=None) -> list:
    """The overview's "cleartext" as plain sentences (the terminal after a run); [] for an overview without it.
    An app is named by its label from overview["apps"], else from names ({package: label}), else by its package.
    The names are the apps' own text (a request's Host, an app's label): their control characters are left out,
    so that they cannot drive the terminal."""
    c = overview.get("cleartext")
    if not c:
        return []
    if not c.get("checked"):
        return [f"没加密的请求（明文 HTTP）：这次看不出来。{c.get('note') or ''}".rstrip()]
    labels = dict(names or {})
    labels.update({a["package"]: a["label"] for a in overview.get("apps") or [] if a.get("label")})
    apps, other = c.get("apps") or [], c.get("unattributed") or {}
    if apps:
        lines = [f"没加密的请求（明文 HTTP）：{len(apps)} 个应用没加密就发出了请求，同一网络里的其他人和运营商都能看到内容。"]
        for a in apps:
            name = labels.get(a["package"]) or a.get("label")
            who = f"{name}（{a['package']}）" if name else a["package"]
            line = f"  {who}：{a['requests']} 次"
            if a.get("background"):
                line += f"，其中 {a['background']} 次在你没打开它的时候"
            line += f"；{_hosts_text(a['hosts'])}"
            line += f"；带了{'、'.join(a['kinds'])}类的字段" if a.get("kinds") else "；按字段名看没带设备、账号、位置这类信息"
            lines.append(line + "。")
    else:
        lines = ["没加密的请求（明文 HTTP）：这次没有看到哪个应用没加密就发请求。"]
    if other.get("requests"):
        lines.append(f"  另有 {other['requests']} 个没加密的请求不知道是哪个应用发的（可能是连接太短，没对上应用），"
                     f"{_hosts_text(other.get('hosts') or [])}。")
    if c.get("system"):
        lines.append(f"  系统本身没加密发了 {c['system']} 个请求，没有算到应用上。")
    return ["".join(ch for ch in line if unicodedata.category(ch) != "Cc") for line in lines]


# -- the app ----------------------------------------------------------------------------------------------

def _parts(facts, technical=False):
    groups = {}
    for e in facts.get("events") or []:
        key = e.get("category") if e.get("category") in _PHRASE else "other"
        if key == "other" and not technical and _routine(e.get("code")):
            continue
        groups.setdefault(key, []).append(e)
    parts = [_events_part(k, evs, technical) for k, evs in groups.items()]
    parts += [p for p in (_network_part(facts.get("network") or {}, technical),
                          _sent_part(facts.get("requests") or [], technical)) if p]
    for p in parts:
        p["level"] = _level(p["weight"], p["front"], p["background"])
    parts.sort(key=lambda p: (_LEVEL_ORDER[p["level"]], -p["weight"], -p["count"], _ORDER[p["key"]]))
    return parts


def build_app(facts: dict) -> dict:
    """APP (docs/CONTRACT_PHONE.md) from one app's facts; "downloads" is left empty for the producer."""
    parts = _parts(facts)
    score = sum(p["weight"] * ((1 if p["front"] else 0) + 3 * (1 if p["background"] else 0)) for p in parts)
    return {"package": facts["package"], "uid": facts.get("uid"), "label": facts.get("label"),
            "third_party": bool(facts.get("third_party")), "score": score,
            "bars": [{"key": p["key"], "text": p["text"], "count": p["count"], "background": p["background_count"],
                      "denied": p["denied"], "cleartext": p.get("cleartext", 0), "level": p["level"]} for p in parts],
            "sections": [{"key": p["key"], "title": TITLE[p["key"]], "summary": p["summary"], "columns": p["columns"],
                          "rows": p["rows"][:ROWS_MAX], "more": max(0, len(p["rows"]) - ROWS_MAX)} for p in parts],
            "downloads": []}


def rank(apps: list) -> list:
    """Most notable first: score, then the larger sum of the bars' counts, then the package name."""
    return sorted(apps, key=lambda a: (-a["score"], -sum(b["count"] for b in a["bars"]), a["package"]))


def detail(facts: dict) -> dict:
    """detail.json: every row behind the app's sections, untruncated, with the technical names."""
    return {"format": 1, "package": facts["package"], "uid": facts.get("uid"), "label": facts.get("label"),
            "sections": [{"key": p["key"], "title": TITLE[p["key"]], "columns": p["columns"], "rows": p["rows"]}
                         for p in _parts(facts, technical=True)],
            "network": facts.get("network") or {}}


# -- downloads ---------------------------------------------------------------------------------------------

def _iso(time, utc_offset):
    if not time:
        return ""
    t = time.replace(" ", "T")
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", (utc_offset or "").strip())
    return t + (f"{m.group(1)}{m.group(2)}:{m.group(3)}" if m else "")


def _nv(pairs):
    return [{"name": str(k), "value": "" if v is None else str(v)} for k, v in pairs or []]


def _body_note(body):
    if not body:
        return None
    return {k: body.get(k) for k in ("size", "sha256", "kind", "encoding", "encoding_detected", "decoded", "truncated",
                                     "preview_hex")}


def har(exchanges, utc_offset=None) -> dict:
    """HAR 1.2 of decrypted exchanges, with every header, query and body value as recorded. The exchange records keep
    text bodies (up to 64 KiB) but not the bytes of binary bodies: those have no text here, and the entry's
    `_stakeout` note gives their size, sha256 and first bytes. utc_offset ("-0500"): the phone's, for the times."""
    entries = []
    for x in sorted(exchanges, key=lambda x: x.get("time") or ""):
        req, resp = x.get("request") or {}, x.get("response")
        version = _HTTP_VERSION.get(x.get("protocol"), x.get("protocol") or "")
        url = f"{x.get('scheme') or 'https'}://{x.get('host') or x.get('server') or 'unknown'}{x.get('path') or '/'}"
        if x.get("query"):
            url += "?" + urlencode([(k, "" if v is None else v) for k, v in x["query"]], quote_via=quote)
        rbody = req.get("body")
        request = {"method": x.get("method") or "", "url": url, "httpVersion": version, "cookies": [],
                   "headers": _nv(req.get("headers")), "queryString": _nv(x.get("query")), "headersSize": -1,
                   "bodySize": (rbody or {}).get("size") or 0}
        if rbody:
            request["postData"] = {"mimeType": header(req.get("headers"), "content-type") or "",
                                   "text": rbody.get("text") or ""}
        if resp is None:
            response = {"status": 0, "statusText": "", "httpVersion": version, "cookies": [], "headers": [],
                        "content": {"size": 0, "mimeType": ""}, "redirectURL": "", "headersSize": -1, "bodySize": -1}
        else:
            body = resp.get("body") or {}
            content = {"size": body.get("size") or 0, "mimeType": header(resp.get("headers"), "content-type") or ""}
            if body.get("text") is not None:
                content["text"] = body["text"]
                if not body.get("truncated"):
                    content["size"] = len(body["text"].encode("utf-8"))
            response = {"status": resp.get("status") or 0, "statusText": "", "httpVersion": version, "cookies": [],
                        "headers": _nv(resp.get("headers")), "content": content,
                        "redirectURL": header(resp.get("headers"), "location") or "", "headersSize": -1,
                        "bodySize": body.get("size") or 0}
        entries.append({"startedDateTime": _iso(x.get("time"), utc_offset), "time": 0, "request": request,
                        "response": response, "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
                        "_stakeout": {"source": x.get("source"), "server": x.get("server"),
                                      "connection": x.get("connection"), "partial": x.get("partial") or [],
                                      "front": x.get("front"), "request_body": _body_note(rbody),
                                      "response_body": _body_note((resp or {}).get("body"))}})
    return {"log": {"version": "1.2", "creator": {"name": "Stakeout", "version": __version__}, "entries": entries}}


def _contents(detail_doc, exchanges, utc_offset):
    out = {}
    if exchanges:
        out["requests.har"] = json.dumps(har(exchanges, utc_offset), ensure_ascii=False, indent=1).encode("utf-8")
    out["detail.json"] = json.dumps(detail_doc, ensure_ascii=False, indent=1).encode("utf-8")
    return out


def _download(kind, size):
    return {"kind": kind, "title": DOWNLOAD_TITLE[kind], "bytes": size, "private": True}


def write_downloads(run_dir, package, detail, exchanges, utc_offset=None) -> list:
    """Write <run dir>/apps/<package>/requests.har (when there are exchanges) and detail.json; [DOWNLOAD].
    Without utc_offset, the run's meta.json gives it."""
    run_dir = Path(run_dir)
    if utc_offset is None and (run_dir / "meta.json").is_file():
        utc_offset = json.loads((run_dir / "meta.json").read_text(encoding="utf-8")).get("utc_offset")
    d = run_dir / "apps" / package
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for kind, data in _contents(detail, exchanges, utc_offset).items():
        (d / kind).write_bytes(data)
        out.append(_download(kind, len(data)))
    return out


# -- one-app runs ----------------------------------------------------------------------------------------

class _Front:
    """Whether the app was in front, from the result's timeline: each "front" row starts a span that lasts until
    the next one; the app is in front when the row names it (analyze marks it 本应用). A row saying no front
    activity was recorded counts as not in front, as in analyze. None before the first row."""

    def __init__(self, timeline):
        rows = sorted((d, t.get("text") or "") for t in timeline if t.get("kind") == "front" and (d := _dt(t.get("time"))))
        self.times = [d for d, _ in rows]
        self.top = [text.endswith("（本应用）") for _, text in rows]
        self.unknown_s = sum((self.times[i + 1] - d).total_seconds() if i + 1 < len(rows) else 1.0
                             for i, (d, text) in enumerate(rows) if text == "没有记录到前台界面")

    def at(self, t):
        d = _dt(t)
        i = bisect.bisect_right(self.times, d) - 1 if d is not None else -1
        return self.top[i] if i >= 0 else None

    def span(self, a, b):
        """(in front at some time in [a, b], not in front at some time in it)."""
        da, db = _dt(a), _dt(b) or _dt(a)
        if da is None:
            return False, False
        i, j = bisect.bisect_right(self.times, da) - 1, bisect.bisect_right(self.times, db) - 1
        states = set(self.top[max(i, 0):j + 1]) if j >= 0 else set()
        return True in states, False in states


_PERM_TEXT = re.compile(r"(.*)（([A-Z][A-Z0-9_]*)）：(使用|被拒绝)(，不在前台|，无法判断当时是否在前台)?")


def _op_what(zh, op):
    """The Chinese name of an operation; one aw.parse_appops does not know gets a plain description instead."""
    if zh and zh != op:
        return zh
    key = category_of(op)
    return "一项其他权限" if key == "other" else f"{TITLE[key]}相关的一项权限"


def _addr(ip, port):
    return f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}"


def _program(cmdline, package):
    """How the page names a process: its name when it is the app's (package or package:…), else the program's
    file name without its arguments."""
    if re.fullmatch(re.escape(package) + r"(:\S*)?", cmdline or ""):
        return cmdline
    first = (cmdline or "").split()[0] if (cmdline or "").split() else ""
    return first.rsplit("/", 1)[-1]


def _start_events(result, front, package, uid):
    """background_start: the app's processes started while it was not in front, and what started them. Starts
    to open one of its screens are left out: that is the app being opened (in fixtures/live_xhs_keylog_1119 the
    owner opening it from the launcher, which was still in front)."""
    proc = result.get("processes") or {}
    starts = {int(s["pid"]): s for s in proc.get("starts") or []}
    app_starts = {int(s["pid"]): s for s in proc.get("app_starts") or []}
    first_block = front.times[0].strftime("%Y-%m-%d %H:%M:%S") if front.times else None
    events = []
    for p in proc.get("procs") or []:
        pid = p["pid"]
        s, a = starts.get(pid), app_starts.get(pid)
        if s and s.get("reason") in _ACTIVITY_REASONS:
            continue
        t = (s or a or {}).get("time") or p.get("first_seen")
        if not (s or a) and (p.get("source") != "poll" or p.get("first_seen") == first_block):
            continue        # already running when the poll started, or no start time known
        if front.at(t) is not False:
            continue
        name = _program(p.get("cmdline") or (s or {}).get("process"), package)
        if s:
            c = s.get("caller") or {}
            who = ("它自己发出的" if c.get("uid") == uid or c.get("package") == package
                   else f"{c['package']} 发出的" if c.get("package") else "")
            reason = _REASON_ZH.get(s.get("reason"), "")
            what = f"系统启动了它的进程 {name}" + (f"，起因：{who}{reason or '请求'}" if who or reason else "")
            code = f"pid {pid}; {s.get('process')}; reason {s.get('reason')}; component {s.get('component')}; caller {c}"
            at_least = False
        elif a:
            what = f"它自己运行了一个程序（{name}）" if name else "它自己运行了一个程序"
            code = f"pid {pid}; app_process; main {a.get('main')}"
            at_least = False
        else:
            what = f"出现了它的新进程 {name}" if name == p.get("cmdline") else f"它运行了程序 {name}"
            code = f"pid {pid}; {p.get('cmdline')}"
            at_least = True
        events.append({"category": "background_start", "time": t, "what": what, "code": code, "front": False,
                       "denied": False, "count": 1, "at_least": at_least})
    return events


def _third_party(run_dir, package):
    """False when the run's package_dump.txt flags the app as part of the system image; True otherwise (a one-app
    run watches an app picked from the user-installed list)."""
    path = Path(run_dir) / "package_dump.txt"
    if not path.is_file():
        return True
    inside = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("  Package ["):
            inside = line.startswith(f"  Package [{package}]")
        elif inside and line.strip().startswith("pkgFlags=["):
            return " SYSTEM " not in line
    return True


def _facts_of_result(result, run_dir=None):
    """The facts record (docs/CONTRACT_PHONE.md, aw/overview.py) of a one-app run's result."""
    meta = result["meta"]
    package, uid = meta["package"], meta.get("uid")
    timeline = result.get("timeline") or []
    front = _Front(timeline)
    events = []

    def event(category, time, what, code, fr, denied=False, count=1, at_least=True):
        events.append({"category": category, "time": time, "what": what, "code": code, "front": fr,
                       "denied": denied, "count": count, "at_least": at_least})

    # Permissions: one timeline row per occurrence (analyze); the clipboard ones come from "clipboard" below.
    for t in timeline:
        m = _PERM_TEXT.fullmatch(t.get("text") or "") if t.get("kind") == "perm" else None
        if m:
            zh, op, verb, state = m.groups()
            event(category_of(op), t["time"], _op_what(zh, op), op,
                  None if state == "，无法判断当时是否在前台" else state is None, denied=verb == "被拒绝")
    for e in (result.get("clipboard") or {}).get("events") or []:
        if e.get("op") != "read":       # writing takes nothing from the phone (as aw.phonewide)
            continue
        event("clipboard", e.get("time"), "读取剪贴板", "READ_CLIPBOARD",
              None if e.get("background") is None else not e["background"], denied=e.get("result") == "blocked",
              at_least=e.get("source") == "appops")
    files = result.get("files") or {}
    for a in files.get("other_app_apks") or []:
        event("installed_apps", a.get("first_time"), f"读取 {a['package']} 的安装包",
              f"{a['package']} base.apk; pids {a.get('pids')}",
              None if a.get("background") is None else not a["background"], count=a.get("reads") or 1)
    for d in files.get("other_app_data") or []:
        event("other_app_data", None, f"读写 {d['package']} 的数据（读 {d.get('reads') or 0} 次、写 {d.get('writes') or 0} 次）",
              "; ".join(d.get("paths") or []) or d["package"], None,
              count=(d.get("reads") or 0) + (d.get("writes") or 0) or 1)
    for s in files.get("shared_storage") or []:
        event("photos", None, f"读写 {s['dir']} 里的文件（读 {s.get('reads') or 0} 次、写 {s.get('writes') or 0} 次）",
              "; ".join([s["dir"]] + list(s.get("files") or [])), None,
              count=(s.get("reads") or 0) + (s.get("writes") or 0) or 1)
    events += _start_events(result, front, package, uid)

    # Network: the app's endpoints; its TLS connections per server address (key route), at least one per endpoint.
    dec = result.get("decrypted") or {}
    kl = dec.get("keylog") or {}
    cov = kl.get("coverage") or {}
    ids = {i for g in ("decrypted", "before_capture", "no_key", "key_no_content") for i in (cov.get(g) or {}).get("ids") or []}
    per_server = Counter(c.get("server") for c in kl.get("connections") or [] if c.get("id") in ids)
    endpoints = []
    for e in (result.get("network") or {}).get("endpoints") or []:
        addr = _addr(e.get("ip"), e.get("port"))
        f, b = front.span(e.get("first_seen"), e.get("last_seen"))
        endpoints.append({"host": e.get("host"), "address": addr,
                          "connections": max(1, per_server.get(addr, 0) if e.get("proto") == "tcp" else 1),
                          "bytes": (e.get("bytes_out") or 0) + (e.get("bytes_in") or 0), "front": f, "background": b})
    not_decrypted = sum((cov.get(g) or {}).get("connections") or 0 for g in ("before_capture", "no_key", "key_no_content"))
    network = {"endpoints": endpoints, "connections": sum(e["connections"] for e in endpoints),
               "bytes": sum(e["bytes"] for e in endpoints), "not_decrypted": not_decrypted}

    # A proxy's HAR can hold other apps' requests: those are not the app's. The cleartext requests are the app's
    # own already (analyze: by its sockets).
    requests = [dict(x, front=front.at(x.get("time"))) for x in dec.get("exchanges") or [] if x.get("source") != "har"]
    requests += [dict(x, front=front.at(x.get("time"))) for x in (result.get("cleartext") or {}).get("exchanges") or []]
    return {"package": package, "uid": uid, "label": None,
            "third_party": _third_party(run_dir, package) if run_dir is not None else True,
            "events": events, "network": network, "requests": requests}


def _app_limits(result, facts, front):
    """Plain sentences: what a one-app run could not see."""
    captured = result.get("captured") or {}
    net = result.get("network") or {}
    dec = result.get("decrypted") or {}
    limits = [f"这次只观察了 {facts['package']} 这一个应用，手机上其他应用做了什么没有记录。"]
    if captured.get("poll") or captured.get("appops"):
        limits.append("权限的使用来自系统的记录，每 1–2 秒查一次：连着很快发生的几次可能只算成一次，所以次数写的是“至少”。")
    if front.unknown_s >= 1:
        limits.append(f"有约 {round(front.unknown_s)} 秒没有记录到手机前台是哪个应用（例如屏幕关着的时候），"
                      "这段时间算作你没打开它。")
    if captured.get("trace"):
        limits.append("文件的读写只记录得到真正读写手机存储的那些，系统已经放在内存里的内容再读一次是看不到的，所以写的是“至少”。")
    else:
        limits.append("这次没有记录文件的读写。")
    if captured.get("pcap"):
        limits.append("收发的数据量是大约的数字。"
                      + ("它的网络连接每 1–2 秒查看一次，很快就断开的连接可能没有看到。" if net.get("sockets_sampled") else ""))
    else:
        limits.append("这次没有抓取网络数据，不知道它连了哪些服务器、传了多少。")
    cov = (dec.get("keylog") or {}).get("coverage") or {}
    if dec.get("keylog"):
        before, no_key, empty = ((cov.get(g) or {}).get("connections") or 0
                                 for g in ("before_capture", "no_key", "key_no_content"))
        parts = ([f"{before} 个在开始观察之前就已经连上了"] if before else []) \
            + ([f"{no_key} 个没有记录到解开它所需的密钥（通常是因为它用了自己带的加密方式）"] if no_key else []) \
            + ([f"{empty} 个连上之后没有传内容就断开了，或者数据没有抓全"] if empty else [])
        if parts:
            limits.append(f"它有 {before + no_key + empty} 个加密连接没能解开内容：" + "；".join(parts) + "。"
                          + ("想看得更全：先在手机上彻底关掉这个应用，开始观察以后再打开它。" if before else ""))
    elif dec.get("ecapture"):
        limits.append("这次的解密只看得到它通过手机系统自带的加密方式收发的内容。")
    elif not any(not _cleartext(x) for x in facts["requests"]):
        limits.append("这次没有解密，看不到它加密发出去的具体内容。")
    quic = sum(1 for e in net.get("endpoints") or [] if e.get("proto") == "udp" and e.get("port") == 443)
    if quic and dec.get("keylog"):
        limits.append(f"它有 {quic} 个连接用的是另一种加密传输方式，这种连接现在解不开。")
    decrypted = [x for x in facts["requests"] if not _cleartext(x)]
    partial = sum(1 for x in decrypted if x.get("partial"))
    if partial:
        limits.append(f"解开的 {len(decrypted)} 个请求中，有 {partial} 个没有记录完整。")
    limits += _cleartext_limits(result.get("cleartext"))
    har_n = sum(1 for x in dec.get("exchanges") or [] if x.get("source") == "har")
    if har_n:
        limits.append(f"导入的代理录制文件里有 {har_n} 个请求，分不清是哪个应用发的，没有算进来。")
    return limits


def _cleartext_limits(clear):
    """What a one-app run's cleartext check (analyze: result["cleartext"]) could not see."""
    if not clear:
        return []
    if not clear.get("checked"):
        return [f"没有检查它有没有没加密就发出去的请求（{clear['error'].rstrip('。')}）。"] if clear.get("error") else []
    if not clear.get("attributed"):
        return ["没有轮询到它的连接：抓包里没加密的请求对不上它，没有列出。"]
    return ["没加密的请求（明文 HTTP）是直接从抓包里读出来的：它的连接每 1–2 秒查看一次，很快就断开的连接对不上它，"
            "这样的请求没有列出；不是 HTTP 的没加密内容也没有列出。"]


def _device(meta):
    dev = meta.get("device") or {}
    name = " ".join(str(dev[k]) for k in ("brand", "model") if dev.get(k))
    return " · ".join(p for p in (name, f"Android {dev['android']}" if dev.get("android") else "") if p)


def _cleartext_note(clear):
    if clear.get("checked") and clear.get("attributed"):
        return None
    if clear.get("error"):
        return clear["error"]
    if clear.get("checked"):
        return "没有轮询到这个应用的连接，抓包里的请求对不上它。"
    return "没有抓包。"


def _app_run(result, run_dir, write):
    run_dir = Path(run_dir)
    meta = result["meta"]
    facts = _facts_of_result(result, run_dir)
    app = build_app(facts)
    det = detail(facts)
    report = run_dir / "report.html"
    if write:
        app["downloads"] = write_downloads(run_dir, facts["package"], det, facts["requests"], meta.get("utc_offset") or "")
        if report.is_file():
            dest = run_dir / "apps" / facts["package"] / "report.html"
            shutil.copyfile(report, dest)
            app["downloads"].append(_download("report.html", dest.stat().st_size))
    else:
        app["downloads"] = [_download(k, len(v)) for k, v in
                            _contents(det, facts["requests"], meta.get("utc_offset") or "").items()]
        if report.is_file():
            app["downloads"].append(_download("report.html", report.stat().st_size))
    overview = {"format": 1,
                "run": {"id": run_dir.name, "scope": "app", "package": facts["package"], "device": _device(meta),
                        "start_time": meta.get("start_time"), "end_time": meta.get("end_time"),
                        "seconds": meta.get("duration_s"), "net": bool((result.get("captured") or {}).get("pcap")),
                        "decrypt": any(not _cleartext(x) for x in facts["requests"])},
                # the one app is listed even when nothing was observed: its detailed report is still there
                "apps": rank([app]),
                "limits": _app_limits(result, facts, _Front(result.get("timeline") or []))}
    clear = result.get("cleartext")
    if clear is not None:       # results made before the cleartext check have none
        overview["cleartext"] = cleartext_summary([facts], clear.get("checked") and clear.get("attributed"),
                                                  _cleartext_note(clear))
    if write:
        (run_dir / "overview.json").write_text(json.dumps(overview, ensure_ascii=False, indent=1), encoding="utf-8")
    return overview


def from_app_result(result: dict, run_dir) -> dict:
    """OVERVIEW of a one-app run from its result.json content (one APP); writes nothing."""
    return _app_run(result, run_dir, write=False)


def write_app_run(result: dict, run_dir) -> dict:
    """The same, also writing <run dir>/overview.json and apps/<package>/{requests.har, detail.json, report.html}
    (the report is copied from the run directory when it is there)."""
    return _app_run(result, run_dir, write=True)
