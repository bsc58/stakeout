"""Render a Stakeout result as one self-contained HTML report in Simplified Chinese.

render(result, show_secrets=False) -> str. The page has no external resources and no JavaScript;
long lists fold into <details>. Everything that comes from the phone is escaped. Unless show_secrets,
values in decrypted traffic are masked by the functions of aw.exchange (is_sensitive, value_spans,
url_spans, body_spans, …), which replace the hidden values only and leave the rest as sent; the content of
binary bodies is not shown, and every other occurrence in the decrypted-content section of a value hidden
somewhere in it is hidden too (SPREAD_MIN); the rest of the page is never changed by it.
"""

import re
from html import escape

from aw import __version__
from aw.analyze import (DECRYPT_SOURCE_ZH, KEYLOG_GROUP_ZH, PARTIAL_ZH, RESULT_ZH,   # the same words as the
                        TRACE_CLOCK_S, coverage_text, decrypted_summary,          # highlights and timeline
                        keylog_coverage_text, start_cause)
from aw.exchange import (apply_spans, body_spans, canon_map, hide, is_sensitive, mask, mask_path, mask_value,
                         note_parts)
from aw.parse_appops import STATE_ZH  # unknown states are shown raw

KIND_ZH = {"access": "已使用", "reject": "被系统拒绝"}
SOURCE_ZH = {"dump": "系统权限记录", "poll": "轮询", "both": "系统权限记录、轮询"}
UNKNOWN_STATE_ZH = "无法判断"    # analyze's state "unknown": the front state is not known for that occurrence
CLIP_OP_ZH = {"read": "读取", "write": "写入"}
CLIP_SOURCE_ZH = {"logcat": "系统日志", "appops": "轮询"}
TIMELINE_KIND_ZH = {"front": "前台切换", "screen": "屏幕", "proc": "进程", "perm": "权限", "clipboard": "剪贴板",
                    "file": "文件", "net": "网络", "decrypted": "解密内容"}
HOST_SOURCE_ZH = {"sni": "加密握手（SNI）", "dns": "域名解析（DNS）"}
STARTED_BY_ZH = {"system": "系统启动", "app": "应用自己启动（app_process）"}

SECTIONS = [  # (id, heading); order fixed by the contract
    ("highlights", "要点"),
    ("permissions", "权限使用"),
    ("clipboard", "剪贴板"),
    ("files", "文件访问"),
    ("processes", "进程与唤醒"),
    ("network", "网络"),
    ("decrypted", "解密内容"),
    ("timeline", "时间线"),
    ("limits", "采集说明与局限"),
]

COLLAPSE_AT = 10  # tables with more rows than this fold into <details>
EXCHANGES_SHOWN = 300   # exchanges shown in full; the rest are one table row each
BODY_SHOWN = 4096       # bytes of a text body shown (UTF-8); result.json keeps up to 64 KiB of text
BODY_KIND_ZH = {"json": "JSON", "form": "表单", "text": "文本", "binary": "二进制"}
# What a report made without --show-secrets hides, and what it does not (aw.exchange: is_sensitive,
# value_spans, url_spans, body_spans; _body, _hide_elsewhere).
SECRETS_NOTE = (
    "这一节默认隐藏下面这些值，名称照常显示，值换成它的长度。"
    "一、名称表示登录凭据、签名、设备或账号标识、客户端 IP 地址的值（例如 Cookie、Authorization、token、sid、sign、"
    "deviceId、uid、ip），不论它在哪里：请求头和响应头、查询参数、网址 # 后面的部分、路径里的“;名称=值”、"
    "请求头的值里用 & ; , 空格或换行隔开的字段、表单、文本正文、任意一层的 JSON，以及 JSON 字符串里的网址和“名称=值”；"
    "值加了引号或经过编码（例如 %2F、&quot;）时，先还原再判断；JSON 里这样的值是数组或对象时，整个隐藏。"
    "二、不论名称是什么、看起来像令牌或编号的值（JWT，或 32 个以上同时含字母和数字的 base64、十六进制字符），"
    "在句子中间也隐藏。"
    "三、上面隐藏的值有 8 个以上字符时，它在这一节其他地方出现（例如在更长的路径、请求头或正文里，"
    "或换成 %2F 这样的写法）也换掉。"
    "四、二进制正文只显示类型和大小，sha256 和开头字节的十六进制不显示。"
    "正文没有记录完整时，末尾没记完的那个值不显示，原处写着“没有记录完整”。"
    "不隐藏的有：名称、域名、路径的其余部分、方法、状态码、大小、时间、access-control-* 头部的值，"
    "以及不属于上面这些形式的文字，程序不检查它们：例如名称不在名单里、又不到 32 个字符的令牌，"
    "名称不在名单里的手机号、昵称、位置，User-Agent 里的手机型号。"
    "所以这份报告里仍可能有账号、设备和其他个人信息，转给别人之前请自己从头看一遍。"
    "生成报告时加 --show-secrets 可以显示原值。")

CSS = """
:root {
  color-scheme: light dark;
  --bg: #f7f6f3;
  --surface: #ffffff;
  --text: #1d2125;
  --muted: #5b626a;
  --faint: #868c94;
  --border: #e2dfd8;
  --head: #f1efea;
  --accent: #2a6478;
  --note-bg: #fbf1e2;
  --note-fg: #874a00;
  --note-line: #d49a4f;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #15171a;
    --surface: #1c1f23;
    --text: #e3e3e0;
    --muted: #a2a8af;
    --faint: #7c828a;
    --border: #2f3338;
    --head: #24282d;
    --accent: #84bdd4;
    --note-bg: #2c2418;
    --note-fg: #efb772;
    --note-line: #a8732f;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.7 -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB",
        "Microsoft YaHei", "Noto Sans CJK SC", "Source Han Sans SC", "Segoe UI", Roboto, sans-serif;
}
main { max-width: 60rem; margin: 0 auto; padding: 2rem 1rem 4rem; overflow-wrap: anywhere; }
a { color: var(--accent); }
.kicker { margin: 0; color: var(--muted); font-size: .9rem; letter-spacing: .05em; }
h1 { font-size: 1.75rem; line-height: 1.3; margin: .2rem 0 .75rem; overflow-wrap: anywhere; }
h2 { font-size: 1.35rem; line-height: 1.4; margin: 0 0 .4rem; }
h3 { font-size: 1.05rem; line-height: 1.4; margin: 1.75rem 0 .4rem; }
p { margin: .5rem 0; }
.lead { font-size: 1.05rem; }
.note { color: var(--muted); font-size: .92rem; }
.empty {
  color: var(--muted); background: var(--surface); border: 1px dashed var(--border);
  border-radius: 8px; padding: .7rem 1rem; margin: .75rem 0;
}
code, .id {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: .84em; overflow-wrap: anywhere;
}
.id { display: block; color: var(--muted); }
.facts { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1.25rem; margin: 1.25rem 0; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; min-width: 0; }
.toc ol { list-style: none; padding: 0; margin: 1.25rem 0 0; display: flex; flex-wrap: wrap; gap: .4rem; }
.toc a {
  display: inline-block; padding: .15rem .7rem; border: 1px solid var(--border); border-radius: 999px;
  background: var(--surface); text-decoration: none; font-size: .9rem;
}
section { margin-top: 2.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border); }
.scroll {
  overflow-x: auto; -webkit-overflow-scrolling: touch; max-width: 100%; overflow-wrap: normal;
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin: .75rem 0;
}
table { border-collapse: collapse; width: 100%; font-size: .92rem; }
th, td { padding: .55rem .8rem; text-align: left; vertical-align: top; border-bottom: 1px solid var(--border); }
thead th { background: var(--head); color: var(--muted); font-weight: 600; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
td.n { text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums; }
td.t { white-space: nowrap; font-variant-numeric: tabular-nums; }
td.w { min-width: 14rem; }
details { margin: .75rem 0; }
summary { cursor: pointer; color: var(--accent); padding: .2rem 0; }
.highlights { list-style: none; padding: 0; margin: .75rem 0; }
.highlights li {
  background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--border);
  border-radius: 6px; padding: .6rem .9rem; margin: .5rem 0;
}
.highlights li.notable { border-left-color: var(--note-line); }
.badge {
  display: inline-block; font-size: .78rem; line-height: 1.6; padding: 0 .55rem; margin-right: .5rem;
  border-radius: 999px; background: var(--note-bg); color: var(--note-fg); white-space: nowrap;
}
ul.ids { columns: 2 18rem; padding-left: 1.2rem; margin: .5rem 0; }
ul.plain { padding-left: 1.2rem; }
ul.plain li { margin: .3rem 0; }
details.x {
  background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: .3rem .8rem; margin: .4rem 0;
}
details.x > summary { color: var(--text); font-size: .92rem; }
details.x h4 { font-size: .95rem; margin: 1rem 0 .3rem; }
h4.host { font-size: 1rem; margin: 1.5rem 0 .3rem; overflow-wrap: anywhere; }
h4.host .note { font-weight: normal; }
pre {
  margin: .4rem 0; padding: .6rem .8rem; background: var(--bg); border: 1px solid var(--border);
  border-radius: 6px; max-height: 24rem; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere;
  font: .84em/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
footer { margin-top: 3rem; color: var(--faint); font-size: .85rem; }
@media (max-width: 34rem) {
  main { padding-top: 1.25rem; }
  h1 { font-size: 1.45rem; }
  .facts { grid-template-columns: 1fr; gap: 0; }
  .facts dd { margin-bottom: .6rem; }
}
"""


# ---------------------------------------------------------------- helpers

def _e(value) -> str:
    """Escaped text; '—' for a missing value."""
    if value is None or value == "":
        return "—"
    return escape(str(value), quote=True)


def _id(value) -> str:
    """A raw identifier (package, op, path) on its own line in a secondary style."""
    return f'<span class="id">{_e(value)}</span>'


def _num(n) -> str:
    return f"{n:,}" if isinstance(n, int) else _e(n)


def _bytes(n) -> str:
    if n is None:
        return "—"
    if n == 0:
        return "0"
    if n < 1024:
        return f"约 {n} 字节"
    size = float(n)
    for unit in ("KB", "MB", "GB"):
        size /= 1024
        if size < 1024 or unit == "GB":
            return f"约 {size:.1f} {unit}"


def _seconds(ticks) -> str:
    """CPU ticks (100 per second) as seconds."""
    if ticks == 0:
        return "0 秒"
    return f"约 {ticks / 100:.1f} 秒"


def _duration(seconds) -> str:
    seconds = int(round(seconds))
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    if h:
        return f"{h} 小时 {m} 分 {s} 秒"
    if m:
        return f"{m} 分 {s} 秒"
    return f"{s} 秒"


def _utc(offset) -> str:
    s = str(offset or "")
    if len(s) == 5 and s[0] in "+-" and s[1:].isdigit():
        return f"UTC{s[0]}{s[1:3]}:{s[3:]}"
    return f"UTC{s}" if s else ""


def _time_formatter(meta):
    """Times are shown without the date when the whole capture is on one day."""
    start, end = str(meta.get("start_time") or ""), str(meta.get("end_time") or "")
    day = start[:10] if start[:10] and start[:10] == end[:10] else ""

    def fmt(value) -> str:
        if not value:
            return "—"
        s = str(value)
        if day and s.startswith(day + " "):
            s = s[len(day) + 1:]
        return escape(s)

    return fmt


def _empty(text) -> str:
    return f'<p class="empty">{escape(text)}</p>'


def _note(text) -> str:
    return f'<p class="note">{escape(text)}</p>'


def _table(headers, rows, cls=(), fold=None, collapse_at=COLLAPSE_AT) -> str:
    """headers: plain-text column names; rows: lists of ready HTML cells;
    cls: per-column CSS class ('t' time, 'n' number, 'w' wide raw text).
    More than `collapse_at` rows fold into <details> with the summary `fold`."""
    cls = tuple(cls) + ("",) * (len(headers) - len(cls))
    head = "".join(f'<th scope="col">{escape(h)}</th>' for h in headers)
    body = []
    for row in rows:
        cells = "".join(f'<td class="{c}">{v}</td>' if c else f"<td>{v}</td>" for c, v in zip(cls, row))
        body.append(f"<tr>{cells}</tr>")
    html = (f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')
    if len(rows) > collapse_at:
        summary = fold or f"显示全部 {len(rows)} 条"
        html = f"<details><summary>{escape(summary)}</summary>{html}</details>"
    return html


def _filetrace_ran(files) -> bool:
    return files.get("backend", "none") != "none" and "events" in files


def _pcap_ran(net, meta) -> bool:
    return not (meta.get("net") is False or net.get("pcap") is False)


def _section(sid, lead, body) -> str:
    title = dict(SECTIONS)[sid]
    return (f'<section id="{sid}" aria-labelledby="{sid}-h">'
            f'<h2 id="{sid}-h">{escape(title)}</h2>'
            f'<p class="lead">{escape(lead)}</p>{body}</section>')


# ---------------------------------------------------------------- sections

def _header(meta, fmt, filetrace, pcap, decrypt) -> str:
    methods = "、".join(["系统记录"] + (["内核文件跟踪"] if filetrace else []) + (["网络抓包"] if pcap else [])
                       + (["eCapture 解密"] if "ecapture" in decrypt else [])
                       + (["密钥解密"] if "keylog" in decrypt else [])
                       + (["代理录制的 HAR 文件"] if "har" in decrypt else []))
    dev = meta.get("device") or {}
    app = [f"<code>{_e(meta['package'])}</code>"]
    if meta.get("version_name"):
        app.append(f"版本 {_e(meta['version_name'])}")
    if meta.get("uid") is not None:
        app.append(f"uid {_e(meta['uid'])}")

    device = " ".join(_e(dev[k]) for k in ("brand", "model") if dev.get(k))
    if dev.get("android"):
        device += f" · Android {_e(dev['android'])}"
        if dev.get("sdk"):
            device += f"（SDK {_e(dev['sdk'])}）"
    if dev.get("kernel"):
        device += _id(f"内核 {dev['kernel']}")

    window = f"{_e(meta['start_time'])} 至 {fmt(meta['end_time'])}"
    if meta.get("duration_s") is not None:
        window += f"，共 {_duration(meta['duration_s'])}"
    tz = _utc(meta.get("utc_offset"))
    window += f"（手机本地时间{'，' + tz if tz else ''}）"

    toc = "".join(f'<li><a href="#{sid}">{escape(title)}</a></li>' for sid, title in SECTIONS)
    return (
        '<header>'
        '<p class="kicker">Stakeout 应用行为报告</p>'
        f"<h1>{_e(meta['package'])}</h1>"
        '<p class="lead">这份报告记录了这个应用在下面这段时间里在手机上做了什么。'
        f'所有观察都在应用外部进行（{methods}），没有改动应用本身。</p>'
        '<dl class="facts">'
        f'<dt>应用</dt><dd>{" · ".join(app)}</dd>'
        f'<dt>设备</dt><dd>{device or "—"}</dd>'
        f'<dt>采集时间</dt><dd>{window}</dd>'
        '</dl>'
        f'<nav class="toc" aria-label="目录"><ol>{toc}</ol></nav>'
        '</header>'
    )


def _highlights(items) -> str:
    lead = "这一节用几句话概括本次观察到的主要情况，详细内容在后面各节。"
    lis = []
    for h in items:
        if h.get("level") == "notable":
            lis.append(f'<li class="notable"><span class="badge">值得注意</span>{_e(h["text"])}</li>')
        else:
            lis.append(f'<li>{_e(h["text"])}</li>')
    return _section("highlights", lead, f'<ul class="highlights">{"".join(lis)}</ul>')


def _permissions(perm, fmt, captured) -> str:
    lead = ("这一节列出应用在采集期间用到的敏感能力（例如位置、相机、剪贴板），"
            "包括被系统拒绝的尝试，以及当时应用是否在前台。")
    used = perm.get("used") or []
    granted = perm.get("granted") or []
    parts = []
    if used:
        n_bg = sum(1 for u in used if u["background"])
        if n_bg:
            parts.append(f"<p>共 {len(used)} 项记录，其中 {n_bg} 项发生在应用不在前台的时候。</p>")
        else:
            parts.append(f"<p>共 {len(used)} 项记录，其中没有一项被观察到发生在应用不在前台的时候。</p>")
        rows = []
        for u in used:
            states = "、".join(escape(UNKNOWN_STATE_ZH if s == "unknown" else STATE_ZH.get(s, s))
                              for s in u["states"]) or "—"
            if u["background"]:
                states = f'<span class="badge">不在前台</span>{states}'
            count = f"{u['count']} 次" if u["count"] is not None else "至少 1 次"
            rows.append([
                f"<strong>{_e(u['zh'])}</strong>{_id(u['op'])}",
                _e(u["category"]),
                _e(KIND_ZH.get(u["kind"], u["kind"])),
                count,
                fmt(u["last_time"]),
                states,
                _e(SOURCE_ZH.get(u["source"], u["source"])),
            ])
        parts.append(_table(["能力", "类别", "结果", "次数", "最近一次", "当时应用状态", "数据来源"],
                            rows, cls=("", "", "", "n", "t")))
        if any(u["count"] is None for u in used):
            parts.append(_note("“至少 1 次”：系统在每种应用状态下只保留最后一次记录，实际次数可能更多。"))
        if any("unknown" in u["states"] for u in used):
            parts.append(_note("“无法判断”：这一次发生在前台切换前后，或轮询开始之前，不知道当时应用是否在前台。"))
    elif not (captured.get("poll", True) or captured.get("appops", True)):
        parts.append(_empty("没有采集到权限使用记录（既没有轮询记录，也没有采集结束时的系统权限记录）。"))
    else:
        parts.append(_empty("本次采集期间没有观察到应用使用或尝试使用敏感权限。"))

    if granted:
        items = "".join(f"<li><code>{_e(g)}</code></li>" for g in granted)
        parts.append(
            f"<details><summary>应用已获得的运行时权限（{len(granted)} 项）</summary>"
            "<p class=\"note\">这些是用户曾经允许过的权限，不代表本次都用到了。</p>"
            f'<ul class="ids">{items}</ul></details>')
    else:
        parts.append(_note("没有读取到应用已获得的运行时权限。"))
    return _section("permissions", lead, "".join(parts))


def _clipboard(clip, fmt, captured) -> str:
    lead = "这一节说明应用是否读取或写入了剪贴板。剪贴板里存放的是你最近复制的内容。"
    reads, blocked, writes = clip.get("reads", 0), clip.get("blocked", 0), clip.get("writes", 0)
    events = clip.get("events") or []
    if not (reads or writes or events):
        if not (captured.get("logcat", True) or captured.get("poll", True)):
            return _section("clipboard", lead, _empty("没有采集到剪贴板记录（既没有系统日志，也没有轮询记录）。"))
        return _section("clipboard", lead, _empty("本次采集期间没有观察到应用读取或写入剪贴板。"))
    text = f"应用读取剪贴板 {reads} 次"
    if blocked:
        text += f"，其中 {blocked} 次{RESULT_ZH['blocked']}（应用拿到的是空内容）"
    text += f"；写入剪贴板 {writes} 次。"
    parts = [f"<p>{escape(text)}</p>"]
    if events:
        rows = []
        for ev in events:
            bg = ev.get("background")
            raw = ev.get("raw")
            rows.append([
                fmt(ev.get("time")),
                _e(CLIP_OP_ZH.get(ev.get("op"), ev.get("op"))),
                _e(RESULT_ZH.get(ev.get("result"), ev.get("result"))),
                "—" if bg is None else ("不在前台" if bg else "前台"),
                _e(CLIP_SOURCE_ZH.get(ev.get("source"), ev.get("source"))),
                (f"<code>{_e(raw)}</code>" if raw else "—")
                + (_id(f"连续 {ev['checks']} 条访问检查，算作 1 次") if (ev.get("checks") or 1) > 1 else "")
                + (f"<br><code>{_e(ev['block_raw'])}</code>" if ev.get("block_raw") else ""),
            ])
        parts.append(_table(["时间", "操作", "结果", "当时应用", "数据来源", "原始记录"], rows,
                            cls=("t", "", "", "", "", "w")))
    return _section("clipboard", lead, "".join(parts))


def _open_files(files, fmt) -> list:
    """Shared-storage files the poll saw open (aw_poll.sh's FD lines)."""
    rows = files.get("open_files") or []
    if not rows:
        return []
    return ["<h3>轮询时看到打开着的公共存储文件</h3>",
            _table(["进程号", "文件", "首次看到", "最后看到"],
                   [[_e(r.get("pid")), f"<code>{_e(r.get('path'))}</code>", fmt(r.get("first_seen")),
                     fmt(r.get("last_seen"))] for r in rows], cls=("n", "w", "t", "t"))]


def _files(files, fmt) -> str:
    lead = "这一节说明应用读写了哪些文件，重点是其他应用的文件和手机的公共存储（照片、下载、文档等）。"
    if not _filetrace_ran(files):
        if files.get("backend", "none") == "none":
            text = "本次采集没有进行文件跟踪，所以没有文件访问的数据。"
        else:
            text = "没有可用的文件跟踪数据，所以没有文件访问的数据（原因见“采集说明与局限”）。"
        return _section("files", lead, _empty(text) + "".join(_open_files(files, fmt)))

    own = files.get("own") or {}
    parts = [
        f"<p>采集期间，内核共记录了全手机 {_num(files['events'])} 次文件读写，其中 "
        f"{_num(files['target_events'])} 次来自这个应用。应用读取自己的文件（自己的安装包和数据）"
        f"{_num(own.get('reads', 0))} 次，写入 {_num(own.get('writes', 0))} 次。</p>"
    ]
    sync = files.get("sync")
    if sync is None:
        parts.append(_note("文件跟踪缺少对时信息，下面的时刻无法换算成手机时间。"))
    elif sync.get("approx") and files.get("clock_lag_s"):
        parts.append(_note(f"文件跟踪的时刻是换算出来的，已按应用进程的启动时刻（系统日志）推后 "
                           f"{files['clock_lag_s']:.2f} 秒，仍可能比实际早约 {max(0.0, TRACE_CLOCK_S - files['clock_lag_s']):.1f} 秒。"))
    elif sync.get("approx"):
        parts.append(_note("文件跟踪的时刻是换算出来的，可能比实际早 1 秒左右。"))

    apks = files.get("other_app_apks") or []
    parts.append("<h3>其他应用的安装包</h3>")
    if apks:
        times = sorted(a["first_time"] for a in apks if a["first_time"])
        text = (f"应用读取了 {len(apks)} 个其他应用的安装包。安装包（base.apk）是应用的安装文件，"
                "里面是那个应用的程序和资源。")
        if times:
            text += f"对各个安装包的首次读取发生在 {fmt(times[0])} 至 {fmt(times[-1])} 之间"
            n_bg = sum(1 for a in apks if a.get("background"))
            text += f"，其中 {n_bg} 个是在应用不在前台时首次读取的。" if n_bg else "。"
        parts.append(f"<p>{text}</p>")
        rows = [[f"<code>{_e(a['package'])}</code>", _num(a["reads"]),
                 fmt(a["first_time"]) + ("" if a.get("background") is None else
                                         _id("不在前台" if a["background"] else "前台")),
                 _e("、".join(str(p) for p in a.get("pids") or []))] for a in apks]
        parts.append(_table(["应用（包名）", "读取次数", "首次读取", "读取的进程号"], rows, cls=("", "n", "t", "n"),
                            fold=f"查看全部 {len(apks)} 个应用"))
    else:
        parts.append(_empty("本次采集期间没有观察到应用读取其他应用的安装包。"))

    data = files.get("other_app_data") or []
    parts.append("<h3>其他应用的数据</h3>")
    if data:
        parts.append(f"<p>应用读写了 {len(data)} 个其他应用的数据目录。数据目录里存放的是那个应用自己的设置和记录。</p>")
        rows = [[f"<code>{_e(d['package'])}</code>", _num(d["reads"]), _num(d["writes"]),
                 "<br>".join(f"<code>{_e(p)}</code>" for p in d["paths"]) or "—"] for d in data]
        parts.append(_table(["应用（包名）", "读取", "写入", "涉及的文件（部分）"], rows,
                            cls=("", "n", "n", "w")))
    else:
        parts.append(_empty("本次采集期间没有观察到应用读写其他应用的数据目录。"))

    shared = files.get("shared_storage") or []
    parts.append("<h3>公共存储（照片、下载、文档等）</h3>")
    if shared:
        parts.append(f"<p>应用在公共存储的 {len(shared)} 个目录里读写了文件。</p>")
        rows = [[f"<code>{_e(s['dir'])}</code>", _num(s["reads"]), _num(s["writes"]),
                 "<br>".join(f"<code>{_e(f)}</code>" for f in s["files"]) or "—"] for s in shared]
        parts.append(_table(["目录", "读取", "写入", "涉及的文件（部分）"], rows, cls=("", "n", "n", "w")))
    else:
        parts.append(_empty("本次采集期间没有观察到应用读写公共存储（照片、下载、文档等）。"))

    system = files.get("system") or {}
    parts.append("<h3>系统文件</h3>")
    s_reads, s_writes = system.get("reads", 0), system.get("writes", 0)
    if s_reads or s_writes:
        parts.append(f"<p>应用读取系统文件 {_num(s_reads)} 次，写入 {_num(s_writes)} 次。"
                     "系统文件是手机系统自身的程序和配置。</p>")
        top = system.get("top") or []
        if top:
            rows = [[f"<code>{_e(path)}</code>", _num(n)] for path, n in top]
            parts.append(_table(["路径", "次数"], rows, cls=("w", "n"),
                                fold=f"最常访问的 {len(top)} 个系统文件", collapse_at=0))
    else:
        parts.append(_empty("本次采集期间没有观察到应用读写系统文件。"))

    procs = files.get("by_process") or []
    if procs:
        parts.append("<h3>各进程的读写次数</h3>")
        # name: the process name from the poll, logcat or ps; thread: only the trace's 15-character
        # name of the process's main thread, which a process can set to anything.
        rows = [[_e(p["pid"]),
                 (f"<code>{_e(p['name'])}</code>" if p.get("name") else "（名称未知）")
                 + (_id(f"线程名 {p['thread']}") if p.get("thread") and p.get("thread") != p.get("name") else ""),
                 _num(p["reads"]), _num(p["writes"])]
                for p in procs]
        parts.append(_table(["进程号", "进程", "读取", "写入"], rows, cls=("n", "", "n", "n")))
    parts += _open_files(files, fmt)
    return _section("files", lead, "".join(parts))


def _processes(proc, bg, meta, fmt, captured) -> str:
    lead = "这一节列出应用在手机上运行的进程、它们是被什么启动的，以及应用不在前台时还做了什么。"
    uid, pkg = meta.get("uid"), meta.get("package")
    logcat = captured.get("logcat", True)
    parts = ["<h3>应用的进程</h3>"]
    procs = proc.get("procs") or []
    if procs:
        parts.append("<p>下面是采集期间以这个应用的身份运行的进程。CPU 时间是进程实际占用处理器的时间。</p>")
        rows = []
        for p in procs:
            ticks, rb = p.get("cpu_ticks"), p.get("read_bytes")
            rows.append([
                _e(p.get("pid")),
                (f"<code>{_e(p.get('cmdline'))}</code>" if p.get("cmdline") else "（名称未知）")
                + (_id(f"app_process 入口 {p['main']}") if p.get("main") else ""),
                _e(STARTED_BY_ZH.get(p.get("started_by"))),
                fmt(p.get("first_seen")), fmt(p.get("last_seen")),
                _seconds(ticks) if ticks is not None else "—",
                _bytes(rb),
            ])
        parts.append(_table(["进程号", "进程", "启动方式", "首次出现", "最后出现", "CPU 时间", "从存储读取"], rows,
                            cls=("n", "w", "", "t", "t", "n", "n")))
        if any(p.get("source") == "logcat" and p.get("started_by") == "app" and not p.get("cmdline") for p in procs):
            parts.append(_note("应用自己通过 app_process 启动、又没有被轮询看到的进程，系统日志里没有它们的名称；"
                               "这些进程也没有 CPU 时间和读取量。“首次出现”是系统日志里它启动的时刻。"))
    elif not (captured.get("poll", True) or logcat or captured.get("ps", True)):
        parts.append(_empty("没有采集到进程记录（既没有轮询记录、系统日志，也没有进程表）。"))
    else:
        parts.append(_empty("本次采集期间没有观察到这个应用的进程。"))

    starts, kills = proc.get("starts") or [], proc.get("kills") or []
    parts.append("<h3>启动与结束</h3>")
    app_starts = proc.get("app_starts") or []
    if app_starts:
        parts.append(f"<p>采集期间，应用自己通过 app_process 启动了 {len(app_starts)} 个进程"
                     f"（进程号 {escape('、'.join(str(s['pid']) for s in app_starts))}），"
                     "它们不是系统启动的，所以不在下表中。</p>")
    if starts:
        parts.append(f"<p>采集期间，系统启动了应用的进程 {len(starts)} 次。</p>")
        parts.append(_start_table(starts, pkg, uid, fmt))
    elif not logcat:
        parts.append(_empty("没有系统日志，看不到进程的启动和结束。"))
    else:
        parts.append(_empty("本次采集期间没有观察到应用的进程被启动。"))
    if kills:
        # kind "kill": a "Killing …" line, the system ended the process;
        # kind "died": only "has died" / am_proc_died, the log does not say who ended it.
        n_died = sum(1 for k in kills if k.get("kind") == "died")
        n_kill = len(kills) - n_died
        if n_kill and n_died:
            text = f"采集期间，系统结束了应用的进程 {n_kill} 次；另有 {n_died} 次应用的进程结束，系统日志没有写明是谁结束的。"
        elif n_kill:
            text = f"采集期间，系统结束了应用的进程 {n_kill} 次。"
        else:
            text = f"采集期间，应用的进程结束了 {n_died} 次，系统日志没有写明是谁结束的。"
        parts.append(f"<p>{escape(text)}</p>")
        rows = [[fmt(k["time"]), _e(k["pid"]), f"<code>{_e(k['process'])}</code>",
                 "进程结束" if k.get("kind") == "died" else "被系统结束",
                 f"<code>{_e(k['reason'])}</code>" if k.get("reason") else "—"] for k in kills]
        parts.append(_table(["时间", "进程号", "进程", "情况", "系统原文"], rows, cls=("t", "n", "", "", "w")))
    elif logcat:
        parts.append(_empty("本次采集期间没有观察到应用的进程结束。"))

    caused = proc.get("caused_starts") or []
    if caused:
        parts.append("<h3>应用使系统启动的其他应用的进程</h3>")
        parts.append(f"<p>采集期间，系统因为这个应用的请求启动了其他应用的进程 {len(caused)} 次"
                     "（例如应用调用了其他应用的数据接口或服务）。</p>")
        parts.append(_start_table(caused, pkg, uid, fmt))

    acts = proc.get("activity_starts") or []
    parts.append("<h3>被打开的界面</h3>")
    if acts:
        n_self = sum(1 for a in acts if uid is not None and a.get("caller_uid") == uid)
        n_unknown = sum(1 for a in acts if a.get("caller_uid") is None)
        n_other = len(acts) - n_self - n_unknown
        who = [f"{label} {n} 次" for label, n in (("应用自己打开", n_self), ("系统或其他应用打开", n_other),
                                                  ("发起方不明", n_unknown)) if n]
        parts.append(f"<p>采集期间，这个应用的界面被打开了 {len(acts)} 次：{'，'.join(who)}。</p>")
        rows = []
        for a in acts:
            caller = a.get("caller_uid")
            if caller is None:
                who_cell = "—"
            elif caller == uid:
                who_cell = f"应用自己{_id(f'uid {caller}')}"
            else:
                who_cell = _e(f"uid {caller}")
            rows.append([fmt(a["time"]), f"<code>{_e(a['component'])}</code>", f"<code>{_e(a['action'])}</code>",
                         f"<code>{_e(a['data'])}</code>", who_cell])
        parts.append(_table(["时间", "界面", "动作", "数据", "发起方"], rows, cls=("t", "w", "", "w", "")))
    elif not logcat:
        parts.append(_empty("没有系统日志，看不到界面被打开的记录。"))
    else:
        parts.append(_empty("本次采集期间没有观察到这个应用的界面被打开。"))

    cmds = proc.get("commands") or []
    parts.append("<h3>以应用身份运行的其他程序</h3>")
    if cmds:
        parts.append("<p>下面这些程序以这个应用的身份运行，但名字不是应用自己的进程名。</p>")
        rows = [[_e(c["pid"]), f"<code>{_e(c['cmdline'])}</code>"] for c in cmds]
        parts.append(_table(["进程号", "命令"], rows, cls=("n", "w")))
    elif not (captured.get("poll", True) or captured.get("ps", True)):
        parts.append(_empty("没有轮询记录和进程表，看不到以应用身份运行的程序。"))
    else:
        parts.append(_empty("本次采集期间没有观察到应用运行其他程序。"))

    parts.append("<h3>前台与后台</h3>")
    s_top, s_not = bg.get("seconds_top", 0), bg.get("seconds_not_top", 0)
    if s_top or s_not:
        cpu = _seconds(bg.get("cpu_ticks_not_top", 0))
        unseen = bg.get("procs_not_polled")
        cpu = f"至少{cpu}（不含轮询没有看到的 {unseen} 个进程）" if unseen and bg.get("cpu_ticks_not_top") else cpu
        parts.append(f"<p>采集期间，应用在前台约 {_num(s_top)} 秒，不在前台约 {_num(s_not)} 秒。"
                     f"不在前台时，它的进程共占用处理器{cpu}。</p>")
        events = bg.get("events_not_top") or []
        if events:
            rows = [[fmt(ev["time"]), _e(ev["what"])] for ev in events]
            parts.append(_table(["时间", "应用不在前台时发生的事"], rows, cls=("t", ""),
                                fold=f"查看全部 {len(events)} 件事"))
        else:
            parts.append(_empty("本次采集期间没有观察到应用在不位于前台时有其他活动。"))
    else:
        parts.append(_empty("本次采集期间没有记录到应用何时在前台。"))
    return _section("processes", lead, "".join(parts))


def _start_table(starts, pkg, uid, fmt) -> str:
    """Process starts by the system (proc_starts or caused_starts) with what triggered them."""
    rows = []
    for s in starts:
        caller = s.get("caller") or {}
        rows.append([fmt(s["time"]), _e(s["pid"]), f"<code>{_e(s['process'])}</code>",
                     f"{_e(start_cause(s, pkg, uid))}{_id(s['reason'])}",
                     f"<code>{_e(s['component'])}</code>"
                     + (_id(f"动作 {caller['action']}") if caller.get("action") else "")])
    return _table(["时间", "进程号", "进程", "启动原因", "触发的组件"], rows, cls=("t", "n", "", "", "w"))


def _system_hosts(hosts, prefix="") -> list:
    """The system-wide host list (rows are host + port), shown for reference only."""
    n_hosts = len({h["host"] for h in hosts})
    pairs = f"（共 {len(hosts)} 个服务器和端口的组合）" if n_hosts != len(hosts) else ""
    rows = [[f"<strong>{_e(h['host'])}</strong>", _e(h["port"]),
             _e(HOST_SOURCE_ZH.get(h.get("host_source"), h.get("host_source"))), _bytes(h["bytes"])]
            for h in hosts]
    return [
        f"<p>{escape(prefix)}下面是整部手机在采集期间连接过的 {n_hosts} 个服务器{pairs}，包括其他应用的，仅供参考。</p>",
        _table(["服务器", "端口", "域名来自", "数据量"], rows, cls=("w", "n", "", "n"),
               fold=f"查看全部 {len(hosts)} 个服务器和端口"),
        _note("数据量是约数：抓包同时在多个网络接口上进行，同一个数据包可能被记录不止一次。"),
    ]


def _network(net, meta, fmt, decrypted) -> str:
    lead = "这一节列出应用连接过的网络服务器，以及大约收发了多少数据。"
    eps = net.get("endpoints") or []
    hosts = net.get("hosts_unattributed") or []
    pcap = _pcap_ran(net, meta)
    parts = []
    if net.get("attributed") and eps:
        parts.append(f"<p>采集期间，应用连接了 {len(eps)} 个服务器地址。</p>")
        rows = []
        for ep in eps:
            name = f"<strong>{_e(ep['host'])}</strong>" if ep["host"] else "（未识别域名）"
            rows.append([
                f"{name}{_id(ep['ip'])}",
                f"{_e(str(ep['proto']).upper())} {_e(ep['port'])}",
                _e(HOST_SOURCE_ZH.get(ep["host_source"], ep["host_source"])),
                fmt(ep["first_seen"]), fmt(ep["last_seen"]),
                _bytes(ep["bytes_out"]), _bytes(ep["bytes_in"]),
            ])
        parts.append(_table(["服务器", "协议与端口", "域名来自", "首次", "最后", "发出", "收到"], rows,
                            cls=("w", "", "", "t", "t", "n", "n"), fold=f"查看全部 {len(eps)} 个服务器地址"))
        if pcap:
            parts.append(_note("数据量是约数：抓包同时在多个网络接口上进行，同一个数据包可能被记录不止一次。"
                               + ("解密到的传输内容在“解密内容”一节。" if decrypted else
                                  "本报告只记录连到了哪里、传了多少，没有记录传输的内容。")))
        else:
            parts.append(_note("本次采集没有抓取网络数据包，所以只有应用连接的地址和端口，没有域名和数据量。"))
    elif net.get("sockets_sampled"):
        # the poll looked at the app's sockets every second and saw none
        parts.append(_empty("本次采集期间没有观察到应用的网络连接。"))
        if hosts:
            parts += _system_hosts(hosts)
    elif hosts:
        parts += _system_hosts(hosts, "本次采集没有记录应用自己的网络连接，无法分辨哪些流量属于这个应用。")
    elif not pcap:
        parts.append(_empty("本次采集没有抓取网络数据，所以没有网络部分的结果。"))
    else:
        parts.append(_empty("本次采集期间没有观察到网络连接。"))
    return _section("network", lead, "".join(parts))


def _shown_value(name, value, show_secrets, header=False, found=None) -> str:
    """A header or query value as the report shows it: masked wholly when is_sensitive(name, value) holds
    (Cookie, Set-Cookie, a token-shaped value), otherwise as aw.exchange.mask_value shows it (Xiaohongshu's
    `xy-common-params` carries `sid` and `id_token`, fixtures/tls_xhs_0119). The values of access-control-*
    headers are never hidden (`access-control-allow-credentials` would otherwise be, by its name)."""
    value = "" if value is None else str(value)
    if show_secrets or (header and str(name).lower().startswith("access-control-")):
        return value
    if is_sensitive(name, value):
        note_parts(str(name), value, found)     # what it holds counts as hidden too (a cookie's value)
        return hide(value, found)
    return mask_value(value, found)


def _shown_path(path, show_secrets, found=None) -> str:
    """A path (with its query and fragment when the request line had them) as aw.exchange.url_spans masks it."""
    return path if show_secrets or not path else mask_path(path, found)


SPREAD_MIN = 8      # a hidden value this long is hidden wherever else it occurs in the default report


def _host_names(result) -> str:
    """Every host name the result knows, lower case, one per line."""
    dec, net = result.get("decrypted") or {}, result.get("network") or {}
    names = [n for x in dec.get("exchanges") or [] for n in (x.get("host"), x.get("connection_host_tail"))]
    names += [e.get("host") for e in (net.get("endpoints") or []) + (net.get("hosts_unattributed") or [])]
    names += [c.get("sni") for c in (dec.get("keylog") or {}).get("connections") or []]
    return "\n".join(str(n).lower() for n in names if n)


def _hide_elsewhere(html, found, hosts) -> str:
    """Every other occurrence in the section's text (not its markup) of a value hidden somewhere in it, when
    the value has SPREAD_MIN characters or more, becomes the placeholder too. The text is searched decoded
    (aw.exchange.canon_map: the page's own escaping, percent escapes, HTML entities, JSON escapes), so that a
    value written in another form (/ as %2F) is found too. A value that is a host name or a part of one stays:
    host names are never hidden."""
    values = {v for v in found if len(v) >= SPREAD_MIN and v.lower() not in hosts}
    if not values:
        return html
    parts = re.split(r"(<[^>]*>)", html)            # text at even indexes, markup at odd ones
    texts = [(k, *canon_map(parts[k])) for k in range(0, len(parts), 2) if parts[k]]
    every = "\0".join(t for _, t, _ in texts)
    values = [v for v in values if v in every]
    if not values:
        return html
    pattern = re.compile("|".join(re.escape(v) for v in sorted(values, key=len, reverse=True)))
    for k, text, off in texts:
        spans = [(m.start(), m.end(), escape(mask(m[0]))) for m in pattern.finditer(text)]
        if spans:
            parts[k] = apply_spans(parts[k], [(a, b, rep) if off is None else (off[a], off[b], rep)
                                              for a, b, rep in spans])
    return "".join(parts)


def _size(n) -> str:
    return "—" if n is None else f"{n:,} 字节"


def _sum(n, unknown) -> str:
    """A per-host sum of body sizes; with bodies not recorded in full it is a lower bound."""
    if not unknown:
        return _size(n)
    return f"至少 {_size(n or 0)}" + _id(f"{unknown} 个正文没有记录到或不完整")


def _body_size(part) -> str:
    return _size(((part or {}).get("body") or {}).get("size"))


def _pairs_table(pairs, show_secrets, header=False, found=None) -> str:
    rows = [[f"<code>{_e(n)}</code>", f"<code>{_e(_shown_value(n, v, show_secrets, header, found))}</code>"]
            for n, v in pairs]
    return _table(["名称", "值"], rows, cls=("", "w"), collapse_at=len(rows))    # never folded: inside <details>


def _order_withheld(x, side):
    """parse_tls leaves out the body of a side whose records' order is unknown (record_order_unknown):
    True when that is this side (the other side is complete or absent), None when it may be either."""
    if "record_order_unknown" not in (x.get("partial") or []):
        return False
    other = x.get("response") if side == "request" else x.get("request")
    return True if other is None or other.get("complete") is not False else None


def _body(body, show_secrets, source=None, complete=True, withheld=False, found=None) -> str:
    if not body:
        if complete:
            return _note("没有正文。")
        if withheld:
            return _note("有记录，但记录的先后顺序无法确定，正文没有显示。")
        if withheld is None:
            return _note("没有显示正文：可能没有记录到，也可能是记录的先后顺序无法确定而没有使用。")
        return _note("没有记录到正文。")
    if body.get("size") is None:        # parse_har: the HAR file's text could not be turned back into bytes
        return _note("有正文，但无法还原成发送时的字节，大小不明，不显示内容。")
    kind = body.get("kind")
    # A HAR file keeps the content after the proxy removed Content-Encoding (aw/parse_har.py): its size
    # is not what travelled when the headers say gzip.
    size = (f"大小 {body['size']:,} 字节（代理保存的内容，原来有压缩时是解压后的大小）" if source == "har"
            else f"传输大小 {body['size']:,} 字节")
    facts = [f"{BODY_KIND_ZH.get(kind, kind)}，{size}"]
    if body.get("encoding_detected"):
        facts.append("头部里的压缩方式（Content-Encoding）没能还原，从内容认出是 gzip 压缩，校验和正确，已解压")
    elif body.get("encoding"):
        facts.append(f"压缩方式 {body['encoding']}，" + ("已解压" if body.get("decoded") else "没有解码"))
    elif body.get("decoded") is False:
        # make_body(encoding_known=False): neither text nor a verified gzip member
        facts.append("头部里的压缩方式（Content-Encoding）没能还原，内容不是文本，也不是校验通过的 gzip 数据，"
                     "可能经过了压缩，没有解码")
    text = body.get("text")
    if text is None:
        # the content of a binary body is not examined: by default only its kind and size are shown
        sha = body.get("sha256") or ""
        facts.append(f"sha256 {sha if show_secrets else mask(sha)}")
        out = _note("；".join(facts) + "。")
        preview = body.get("preview_hex")
        if preview:
            how = "，解压后" if body.get("encoding") and body.get("decoded") else (
                "，传输时的原样" if body.get("decoded") is False else "")
            out += (_note(f"开头 {len(preview) // 2} 字节（十六进制{how}）：")
                    + f"<pre>{escape(preview if show_secrets else mask(preview))}</pre>")
        return out
    data = text.encode("utf-8")
    end = len(data[:BODY_SHOWN].decode("utf-8", "ignore"))     # the characters shown
    if show_secrets:
        shown = text[:end]
    else:
        # the whole text is judged (and its hidden values noted in found), then the same beginning is shown
        # as with --show-secrets. Cut at BODY_TEXT_MAX, or the side was not recorded to its end: what is left
        # open at the end is not shown (a part of a value cannot be judged by its shape).
        cut = bool(body.get("truncated")) or not complete
        shown = apply_spans(text, body_spans(text, kind, cut, found), end)
    if len(data) > BODY_SHOWN or body.get("truncated"):
        facts.append(f"这里只显示开头 {len(text[:end].encode('utf-8')):,} 字节")
    return _note("；".join(facts) + "。") + f"<pre>{escape(shown)}</pre>"


def _host_label(x) -> str:
    """An exchange's host; without one, the server name of its connection as far as the reader
    thread's name tells it (parse_tls: connection_host_tail; that server can differ from the request's
    own host on a shared connection)."""
    if x.get("host"):
        return x["host"]
    tail = x.get("connection_host_tail")
    return f"域名未知（所在连接的服务器名以 {tail} 结尾）" if tail else "（域名未知）"


def _exchange(x, fmt, show_secrets, found=None) -> str:
    """One request with its response, folded into a <details> block."""
    req, resp = x.get("request") or {}, x.get("response")
    status = "没有找到响应" if resp is None else _e(resp.get("status"))
    target = f"{_host_label(x)}{_shown_path(x.get('path') or '', show_secrets, found)}"
    summary = f"{fmt(x.get('time'))} <strong>{_e(x.get('method'))}</strong> {escape(target)} → {status}"
    partial = "、".join(PARTIAL_ZH.get(p, p) for p in x.get("partial") or [])
    who = "、".join(s for s in (f"进程 {x['pid']}" if x.get("pid") is not None else "",
                                f"线程 {x['thread']}" if x.get("thread") else "") if s)
    facts = [("编号", _e(f"#{x.get('id')}")),
             ("来源", _e(" · ".join(str(v) for v in (DECRYPT_SOURCE_ZH.get(x.get("source"), x.get("source")),
                                                      x.get("protocol"), x.get("scheme")) if v))),
             ("发出 / 收到的正文", f"{_body_size(req)} / {_body_size(resp)}")]
    if x.get("connection") is not None:      # the key route: the TCP connection it travelled on
        facts.append(("所在连接", _e(f"#{x['connection']}（服务器 {x.get('server')}）")))
    if who:
        facts.append(("发起的进程", _e(who)))
    facts.append(("不完整或不确定的部分", _e(partial) if partial else "无"))
    parts = [f'<details class="x"><summary>{summary}</summary>',
             '<dl class="facts">' + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts) + "</dl>"]
    # "complete" covers the whole side; mostly it is the body that was not seen to the end (parse_tls:
    # no END_STREAM; parse_har: body left out), so the headers are not called incomplete.
    if "hpack_state_unknown" in (x.get("partial") or []):
        parts.append(_note("这个请求所在连接的开头没有记录到：请求头和响应头中无法还原的字段没有列出。"))
    if req.get("complete") is False:
        parts.append(_note("这个请求没有完整记录到：下面的请求头或请求正文可能缺了一部分。"))
    parts.append("<h4>请求头</h4>")
    parts.append(_pairs_table(req["headers"], show_secrets, True, found) if req.get("headers")
                 else _note("没有请求头。"))
    if x.get("query"):
        parts.append("<h4>查询参数</h4>" + _pairs_table(x["query"], show_secrets, found=found))
    parts.append("<h4>请求正文</h4>" + _body(req.get("body"), show_secrets, x.get("source"),
                                         req.get("complete") is not False, _order_withheld(x, "request"), found))
    if resp is None:
        parts.append(_note("没有找到这个请求的响应。"))
    else:
        if resp.get("complete") is False:
            parts.append(_note("这个响应没有完整记录到：下面的响应头或响应正文可能缺了一部分。"))
        parts.append("<h4>响应头</h4>")
        parts.append(_pairs_table(resp["headers"], show_secrets, True, found) if resp.get("headers")
                     else _note("没有响应头。"))
        parts.append("<h4>响应正文</h4>" + _body(resp.get("body"), show_secrets, x.get("source"),
                                             resp.get("complete") is not False, _order_withheld(x, "response"),
                                             found))
    parts.append("</details>")
    return "".join(parts)


def _keylog_coverage(kl) -> list:
    """The key route's coverage: the app's TLS connections in three groups, with the servers of each."""
    cov = kl["coverage"]
    rows = []
    for g in ("decrypted", "before_capture", "no_key", "key_no_content"):
        grp = cov.get(g) or {}
        if not grp.get("connections"):
            continue
        named = [f"<code>{_e(h)}</code>（{n}）" for h, n in grp["hosts"] if h]
        nameless = sum(n for h, n in grp["hosts"] if not h)
        if nameless:
            named.append(f"只知道 IP 地址的（{nameless}）")
        rows.append([_e(KEYLOG_GROUP_ZH[g]), _num(grp["connections"]), "、".join(named) or "—"])
    out = ["<h3>解密的覆盖范围</h3>", f"<p>{escape(keylog_coverage_text(kl, listed=False))}</p>"]
    if rows:
        out.append(_table(["情况", "连接数", "连到的服务器（连接数）"], rows, cls=("", "n", "w")))
    return out


def _decrypted(dec, meta, fmt, show_secrets, endpoints=(), found=None) -> str:
    lead = "这一节列出解密后的 HTTPS 请求：应用发给了哪个服务器、发了什么、收到了什么。"
    ecap, har, kl = dec.get("ecapture"), dec.get("har"), dec.get("keylog")
    if ecap is None and har is None and kl is None:
        if dec.get("keylog_error"):
            text = (f"本次有加密连接的密钥记录（tls_keys.log），但没能用它解密抓包：{dec['keylog_error'].rstrip('。')}。"
                    "所以没有解密内容（见“采集说明与局限”）。")
        elif "ecapture" in (meta.get("unavailable") or []):
            text = "本次要求了解密，但 eCapture 没有在手机上启动，所以没有解密内容（原因见“采集说明与局限”）。"
        elif meta.get("decrypt") == "keylog":
            text = "本次要求了解密，但运行目录里没有 tls_keys.log（密钥记录），所以没有解密内容（见“采集说明与局限”）。"
        elif meta.get("decrypt") == "ecapture":
            text = "本次用 eCapture 解密，但运行目录里没有 tls_events.log，所以没有解密内容（见“采集说明与局限”）。"
        else:
            text = "本次采集没有解密 HTTPS 内容（没有使用 --decrypt，也没有用 --har 导入代理录制的文件）。"
        return _section("decrypted", lead, _empty(text))

    xs, hosts = dec.get("exchanges") or [], dec.get("hosts") or []
    parts = []
    if not xs:
        used = "、".join(DECRYPT_SOURCE_ZH[s] for s, v in (("ecapture", ecap), ("keylog", kl), ("har", har))
                        if v is not None)
        parts.append(_empty(f"进行了解密（{used}），但没有解密到任何请求。"))
    else:
        parts.append(f"<p>{escape(decrypted_summary(dec) + '。')}</p>")
    if kl is not None:
        parts.append(_note("密钥解密是这样做的：手机上的 eCapture 在应用建立加密连接时记下这次连接的密钥，"
                           "采集结束后，电脑上的 tshark 用这些密钥解开抓到的数据包。记下了密钥的连接才能解开，"
                           "解开的内容就是当时实际收发的内容。"))
        parts += _keylog_coverage(kl)
    else:
        nc = dec.get("not_covered") or []
        coverage = coverage_text(dec, endpoints, listed=False)
        if coverage:
            parts.append("<h3>解密的覆盖范围</h3>")
            parts.append(f"<p>{escape(coverage)}</p>")
        if nc:
            parts.append(_table(["没有解密到内容的域名", "数据量（抓包）"],
                                [[f"<strong>{_e(h['host'])}</strong>", _bytes(h.get("bytes"))] for h in nc],
                                cls=("w", "n"), fold=f"查看全部 {len(nc)} 个没有解密到内容的域名"))

    if xs:
        parts.append("<h3>按域名汇总</h3>")
        rows = []
        for h in hosts:
            methods = "、".join(f"{m} {n}" for m, n in (h.get("methods") or {}).items()) or "—"
            paths = "<br>".join(f"<code>{_e(_shown_path(p, show_secrets, found))}</code> {n} 次"
                                for p, n in h.get("paths") or []) or "—"
            rows.append([f"<strong>{_e(h.get('host') or '（域名未知）')}</strong>", _num(h.get("exchanges")),
                         _e(methods), _e("、".join(DECRYPT_SOURCE_ZH.get(s, s) for s in h.get("sources") or [])),
                         _sum(h.get("request_bytes"), h.get("request_bodies_unknown")),
                         _sum(h.get("response_bytes"), h.get("response_bodies_unknown")), paths])
        parts.append(_table(["域名", "请求数", "方法", "来源", "发出的正文", "收到的正文", "最常见的路径"], rows,
                            cls=("w", "n", "", "", "n", "n", "w"), fold=f"查看全部 {len(hosts)} 个域名"))

        parts.append("<h3>每个请求</h3>")
        if show_secrets:
            parts.append(_note("这份报告显示了 Cookie、令牌、设备标识等值的原值（生成时用了 --show-secrets）。"
                               "别人拿到这些值可能登录你的账号，请不要转发这份报告。"))
        else:
            parts.append(_note(SECRETS_NOTE))
        # Grouped by host in the order of the summary table, by time within a host. Shown in full: each
        # host's first request, then each host's second, … up to EXCHANGES_SHOWN, so that every host has
        # requests shown before one host fills the page.
        by_host = {}
        for x in xs:
            by_host.setdefault(x.get("host"), []).append(x)
        order = list(dict.fromkeys([h.get("host") for h in hosts if h.get("host") in by_host] + list(by_host)))
        rank = {x["id"]: k for group in by_host.values() for k, x in enumerate(group)}
        full = {x["id"] for x in sorted(xs, key=lambda x: (rank[x["id"]], x["id"]))[:EXCHANGES_SHOWN]}
        more = len(xs) > EXCHANGES_SHOWN
        parts.append(f"<p>按域名分组，同一域名的请求按时间排列"
                     f"{f'；共 {len(xs)} 个，下面完整列出 {EXCHANGES_SHOWN} 个（每个域名都列出一部分），其余的在最后的摘要表里' if more else ''}。"
                     "点开一行可以看到请求和响应的头部与正文。</p>")
        for host in order:
            group = by_host[host]
            shown = [x for x in group if x["id"] in full]
            if not shown:
                continue
            count = f"{len(group)} 个请求" + (f"，其中 {len(group) - len(shown)} 个在最后的摘要表里" if len(shown) < len(group) else "")
            parts.append(f'<h4 class="host">{_e(host or "（域名未知）")} <span class="note">{escape(count)}</span></h4>')
            parts += [_exchange(x, fmt, show_secrets, found) for x in shown]
        rest = [x for host in order for x in by_host[host] if x["id"] not in full]
        if rest:
            parts.append(f"<p>其余 {len(rest)} 个请求只列出摘要，完整内容在 result.json 里。</p>")
            rows = [[_e(f"#{x.get('id')}"), fmt(x.get("time")), _e(x.get("method")),
                     f"<code>{_e(_host_label(x) + _shown_path(x.get('path') or '', show_secrets, found))}</code>",
                     "没有找到响应" if x.get("response") is None else _e(x["response"].get("status")),
                     _body_size(x.get("request")), _body_size(x.get("response")),
                     _e(DECRYPT_SOURCE_ZH.get(x.get("source"), x.get("source")))] for x in rest]
            parts.append(_table(["编号", "时间", "方法", "域名与路径", "状态", "发出的正文", "收到的正文", "来源"], rows,
                                cls=("n", "t", "", "w", "n", "n", "n", ""), fold=f"查看其余 {len(rest)} 个请求"))
    return _section("decrypted", lead, "".join(parts))


def _timeline(items, fmt) -> str:
    lead = "这一节把前面各类事情按发生时间排在一起，方便看清先后顺序。"
    if not items:
        return _section("timeline", lead, _empty("本次采集期间没有观察到可以排进时间线的事情。"))
    rows = [[fmt(it["time"]), _e(TIMELINE_KIND_ZH.get(it["kind"], it["kind"])), _e(it["text"])]
            for it in items]
    body = (f"<p>共 {len(items)} 条记录。</p>"
            + _table(["时间", "类别", "内容"], rows, cls=("t", "", ""), fold=f"显示全部 {len(items)} 条记录"))
    return _section("timeline", lead, body)


def _limits(limits, filetrace, pcap, decrypt) -> str:
    lead = "这一节说明数据是怎么采集的，以及哪些内容没有采到、结论受哪些限制。"
    how = "读取系统的权限使用记录，每 1–2 秒查看一次前台应用、应用的进程和权限状态"
    if filetrace:
        how += "，用内核跟踪全手机的文件读写"
    if pcap:
        how += "，并抓取网络数据包"
    if "ecapture" in decrypt:
        how += "；用 eCapture 记录应用通过系统 TLS 库收发的 HTTPS 内容"
    if "keylog" in decrypt:
        how += "；用 eCapture 在应用建立加密连接时记下密钥，再在电脑上用 tshark 解开抓到的数据包"
    if "har" in decrypt:
        how += "；读取你自己用代理录制的 HAR 文件"
    parts = [f"<p>采集方式：{how}。这些都在应用外部进行，不改动应用。</p>",
             '<ul class="plain">' + "".join(f"<li>{_e(x)}</li>" for x in limits) + "</ul>"]
    return _section("limits", lead, "".join(parts))


# ---------------------------------------------------------------- entry point

def render(result: dict, show_secrets: bool = False) -> str:
    """One self-contained HTML document for an analyze() result. show_secrets: show credentials in
    decrypted traffic instead of their length."""
    meta = result["meta"]
    fmt = _time_formatter(meta)
    files, net = result.get("files") or {}, result.get("network") or {}
    filetrace, pcap = _filetrace_ran(files), _pcap_ran(net, meta)
    captured = result.get("captured") or {}     # which sources had data; a missing key counts as captured
    dec = result.get("decrypted") or {}         # absent in results made before v0.2
    decrypt = [s for s in ("ecapture", "keylog", "har") if dec.get(s) is not None]    # the sources that were read
    found = set()                               # the values the default report hides
    decrypted = _decrypted(dec, meta, fmt, show_secrets, net.get("endpoints") or [], found)
    if not show_secrets:      # inside this section only: the header's package name, the network's addresses stay
        decrypted = _hide_elsewhere(decrypted, found, _host_names(result))
    body = "".join([
        _header(meta, fmt, filetrace, pcap, decrypt),
        _highlights(result.get("highlights") or []),
        _permissions(result.get("permissions") or {}, fmt, captured),
        _clipboard(result.get("clipboard") or {}, fmt, captured),
        _files(files, fmt),
        _processes(result.get("processes") or {}, result.get("background") or {}, meta, fmt, captured),
        _network(net, meta, fmt, bool(dec.get("exchanges"))),
        decrypted,
        _timeline(result.get("timeline") or [], fmt),
        _limits(result.get("limits") or [], filetrace, pcap, decrypt),
    ])
    title = f"{meta['package']} 行为报告"
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f"<title>{escape(title)}</title>\n<style>{CSS}</style>\n</head>\n"
        f"<body>\n<main>\n{body}\n"
        f"<footer>由 Stakeout {escape(__version__)} 生成。</footer>\n"
        "</main>\n</body>\n</html>\n"
    )
