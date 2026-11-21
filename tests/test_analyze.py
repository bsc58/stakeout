import ast
import contextlib
import copy
import gettext
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import aw
from aw import analyze, overview, report
from aw.exchange import make_body
import stakeout

PKG = "com.example.app"
D = "2026-11-18 10:00:"


def T(s):
    return D + s


META = {
    "format": 1, "package": PKG, "uid": 10378, "app_id": "u0a378", "version_name": "1.0",
    "device": {"brand": "X", "model": "Y", "android": "15", "sdk": 35, "kernel": "6.6"},
    "start_time": T("00"), "end_time": "2026-11-18 10:01:00",
    "start_epoch": 1795014000, "end_epoch": 1795014060, "utc_offset": "-0500",
    "filetrace_backend": "f2fs", "trace_sync": {"trace_ts": 1.0, "epoch": 1795014000, "approx": True},
    "net": True, "missing": ["OT lines in poll.txt", "ps_after.txt"],
}

POLL = {
    "blocks": 6, "first_time": T("05"), "last_time": T("30"),
    "top": [{"start": T("05"), "end": T("10"), "component": f"{PKG}/.Main", "package": PKG, "task": "t1"},
            {"start": T("15"), "end": T("30"), "component": "com.other/.Main", "package": "com.other", "task": "t2"}],
    "procs": {
        "381": {"cmdline": PKG, "first_seen": T("05"), "last_seen": T("30"), "ppid": None,
                "cpu_ticks": 100, "adj": [0, 900], "read_bytes": 10},
        "1457": {"cmdline": "ping -c 1 example.com", "first_seen": T("20"), "last_seen": T("20"), "ppid": None,
                 "cpu_ticks": 1, "adj": [0], "read_bytes": 0},
        "2828": {"cmdline": f"{PKG}:widget", "first_seen": T("20"), "last_seen": T("25"), "ppid": None,
                 "cpu_ticks": 3, "adj": [700], "read_bytes": 0},
        "1669": {"cmdline": "", "first_seen": T("10"), "last_seen": T("10"), "ppid": None,
                 "cpu_ticks": 0, "adj": [], "read_bytes": 0},
    },
    "cpu": [{"time": T("05"), "ticks": 0, "target_top": True}, {"time": T("10"), "ticks": 50, "target_top": True},
            {"time": T("15"), "ticks": 20, "target_top": False}, {"time": T("20"), "ticks": 30, "target_top": False},
            {"time": T("25"), "ticks": 5, "target_top": False}, {"time": T("30"), "ticks": 0, "target_top": False}],
    "sockets": [],
    "ops": {
        "FINE_LOCATION": {"mode": "allow", "events": [{"kind": "access", "time": T("07"), "target_top": True},
                                                      {"kind": "access", "time": T("22"), "target_top": False}]},
        "READ_CLIPBOARD": {"mode": "mode=5", "events": [{"kind": "reject", "time": T("02"), "target_top": True},
                                                        {"kind": "reject", "time": T("08"), "target_top": True}]},
        "GET_USAGE_STATS": {"mode": "default", "events": [{"kind": "reject", "time": T("26"), "target_top": False}]},
    },
    "fds": [],
}

LOGCAT = {
    "lines": 100, "first_time": T("01.000"), "last_time": T("59.000"),
    "proc_starts": [{"time": T("21.500"), "pid": 2864, "process": f"{PKG}:widget", "reason": "broadcast",
                     "component": f"{PKG}/.Widget"}],
    "proc_kills": [{"time": T("50.000"), "pid": 2864, "process": f"{PKG}:widget", "reason": "cached"}],
    "activity_starts": [],
    "clipboard": [{"time": T("08.386"), "op": "read", "result": "blocked", "raw": "r1"},
                  {"time": T("08.387"), "op": "read", "result": "unknown", "raw": "r2"}],
    "pid_map": {"2864": {"process": f"{PKG}:widget", "app_id": "u0a378", "time": T("21.500")},
                "5000": {"process": "com.tencent.mm", "app_id": "u0a382", "time": T("30.000")},
                "5001": {"process": f"{PKG}:push", "app_id": "u0a378", "time": T("40.000")}},
}

# parse_logcat's app_process runs under the app's uid
APP_PROCESS_STARTS = [{"time": T("19.500"), "pid": 2828, "main": "com/example/Daemon"},
                      {"time": T("23.000"), "pid": 6000, "main": None}]

DUMP_DIFF = [
    {"op": "FINE_LOCATION", "kind": "access", "state": "top", "time": T("07.120"), "duration_ms": None},
    {"op": "CAMERA", "kind": "access", "state": "cch", "time": T("40.000"), "duration_ms": 500},
]

FILES = {
    "events": 1000, "target_events": 200, "first_ts": 1.0, "last_ts": 60.0,
    "sync": {"trace_ts": 1.0, "epoch": 1795014000, "approx": True},
    "own": {"reads": 100, "writes": 10},
    "other_app_apks": [{"package": "com.eg.android.AlipayGphone", "reads": 20, "first_time": T("16.500")},
                       {"package": "com.tencent.mm", "reads": 30, "first_time": T("12.000")}],
    "other_app_data": [], "shared_storage": [],
    "system": {"reads": 5, "writes": 0, "top": []}, "by_process": [],
}

PCAP = {"packets": 50, "linktype": 276, "first_epoch": 1795014001.0, "last_epoch": 1795014059.0, "sni": {}, "dns": {}, "endpoints": {}}
UNATTRIBUTED = [{"host": "a.example.com", "port": 443, "bytes": 1000, "host_source": "sni"},
                {"host": "b.example.com", "port": 443, "bytes": 5000, "host_source": "dns"},
                {"host": "2404:2280:1b9:0:3::22", "port": 443, "bytes": 9000, "host_source": None},
                {"host": "b.example.com", "port": 80, "bytes": 10, "host_source": "dns"}]

OPS = {"FINE_LOCATION": ("精确位置", "位置", True), "CAMERA": ("相机", "相机", True),
       "READ_CLIPBOARD": ("读取剪贴板", "剪贴板", True), "GET_USAGE_STATS": ("使用情况访问", "其他", False)}

PS = """  PID  PPID USER           NAME
  381  2027 u0_a378        com.example.app
  777  2027 u0_a382        com.tencent.mm
  888   381 u0_a378        sh
"""

PACKAGE_DUMP = """Packages:
  Package [com.other] (1):
    User 0: installed=true
      runtime permissions:
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET]
  Package [com.example.app] (2):
    versionName=1.0
    install permissions:
      android.permission.INTERNET: granted=true
    User 0: installed=true
      gids=[3003]
      runtime permissions:
        android.permission.ACCESS_FINE_LOCATION: granted=true, flags=[ USER_SET]
        android.permission.READ_CONTACTS: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED]
        android.permission.CAMERA: granted=true, flags=[ USER_SET]
      disabledComponents:
        com.example.app.Foo

Queries:
  com.example.app:
    android.permission.SEND_SMS: granted=true
"""


def file_stub(value):
    """A parser stand-in: FileNotFoundError when the file is absent (like the real parsers), else a copy of value."""
    def f(path, *args, **kwargs):
        if not Path(path).exists():
            raise FileNotFoundError(path)
        f.calls.append((path, args, kwargs))
        return copy.deepcopy(value)
    f.calls = []
    return f


def value_stub(value):
    f = mock.Mock(side_effect=lambda *a, **k: copy.deepcopy(value))
    return f


class KeylogError(Exception):
    """Stands for aw.parse_keylog.KeylogError."""


NO_CLEARTEXT = {"tshark": "TShark (Wireshark) 4.6.10.", "connections": [], "exchanges": [],
                "undecoded": {"bytes": 0, "reasons": {}}}


class Harness:
    """Patches the five parser modules inside aw.analyze, and the three decrypted-traffic parsers
    (imported by analyze only when a run has their files), for one test. cleartext: what
    parse_cleartext returns (a run with a capture and no key file)."""

    def __init__(self, poll=POLL, logcat=LOGCAT, dump_diff=DUMP_DIFF, files=FILES, pcap=PCAP,
                 attributed=None, unattributed=UNATTRIBUTED, tls=None, har=None, keylog=None, cleartext=NO_CLEARTEXT):
        self.poll = file_stub(poll)
        self.logcat = file_stub(logcat)
        self.dump = file_stub({"uid_state": "cch", "uid_modes": {}, "ops": {}})
        self.diff = value_stub(dump_diff)
        self.trace = file_stub(files)
        self.pcap = file_stub(pcap)
        self.attribute = value_stub(attributed or [])
        self.unattributed = value_stub(unattributed)
        self.tls = file_stub(tls)
        self.har = har if callable(har) else file_stub(har)
        self.keylog = keylog if callable(keylog) else file_stub(keylog)
        self.cleartext = cleartext if callable(cleartext) else file_stub(cleartext)

    def __enter__(self):
        info = lambda op: dict(zip(("zh", "category", "sensitive"), OPS.get(op, (op, "其他", False))))  # noqa: E731
        self.stack = contextlib.ExitStack()
        for name, ns in (
                ("parse_poll", SimpleNamespace(parse_poll=self.poll)),
                ("parse_logcat", SimpleNamespace(parse_logcat=self.logcat)),
                ("parse_appops", SimpleNamespace(parse_appops_dump=self.dump, diff_appops=self.diff, op_info=info)),
                ("parse_filetrace", SimpleNamespace(parse_f2fs_trace=self.trace)),
                ("parse_net", SimpleNamespace(parse_pcap=self.pcap, attribute=self.attribute,
                                              hosts_unattributed=self.unattributed))):
            self.stack.enter_context(mock.patch.object(analyze, name, ns))
        for name, ns in (("parse_tls", SimpleNamespace(parse_tls_events=self.tls)),
                         ("parse_har", SimpleNamespace(parse_har=self.har)),
                         ("parse_keylog", SimpleNamespace(parse_keylog=self.keylog, parse_cleartext=self.cleartext,
                                                          KeylogError=KeylogError))):
            self.stack.enter_context(mock.patch.object(aw, name, ns, create=True))
        return self

    def __exit__(self, *exc):
        self.stack.close()


def make_run(tmp, meta=META, files=("poll.txt", "logcat.txt", "appops_before.txt", "appops_after.txt",
                                     "filetrace_f2fs.txt", "net.pcap", "package_dump.txt", "ps_before.txt")):
    run = Path(tmp) / "run"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    for name in files:
        content = {"ps_before.txt": PS, "package_dump.txt": PACKAGE_DUMP}.get(name, "stub\n")
        (run / name).write_text(content, encoding="utf-8")
    return run


class AnalyzeFullRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = make_run(cls.tmp.name)
        cls.out = Path(cls.tmp.name) / "out"
        with Harness() as h:
            cls.h = h
            cls.r = analyze.analyze(cls.run_dir, cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_parsers_called_with_contract_arguments(self):
        self.assertEqual(self.h.poll.calls[0][1], (PKG,))
        self.assertEqual(self.h.logcat.calls[0][1], (PKG, 10378))
        self.assertEqual(self.h.logcat.calls[0][2], {"year": 2026})
        before, after, start, end = self.h.diff.call_args.args
        self.assertEqual((start, end), (META["start_time"], META["end_time"]))
        kwargs = self.h.trace.calls[0][2]
        self.assertEqual(kwargs["sync"], META["trace_sync"])
        self.assertEqual(kwargs["utc_offset"], "-0500")

    def test_target_pids_from_poll_logcat_pidmap_and_ps(self):
        _, args, kwargs = self.h.trace.calls[0]
        self.assertEqual(args[0], PKG)
        self.assertEqual(args[1], {381, 1457, 2828, 1669, 2864, 5001, 888})
        names = kwargs["pid_names"]
        self.assertEqual(names[1457], "ping -c 1 example.com")
        self.assertEqual(names[888], "sh")
        self.assertEqual(names[5001], f"{PKG}:push")
        self.assertNotIn(1669, names)          # empty cmdline gives no name
        self.assertNotIn(777, names)           # another app's ps row
        self.assertNotIn(5000, names)          # another app's pid_map entry

    def test_result_json_written_to_out_dir(self):
        saved = json.loads((self.out / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, json.loads(json.dumps(self.r)))
        self.assertFalse((self.run_dir / "result.json").exists())

    def test_meta_and_granted(self):
        self.assertEqual(self.r["meta"]["duration_s"], 60)
        self.assertEqual(self.r["meta"]["package"], PKG)
        self.assertEqual(self.r["permissions"]["granted"],
                         ["android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA"])

    def test_permission_merge(self):
        used = {(u["op"], u["kind"]): u for u in self.r["permissions"]["used"]}
        loc = used[("FINE_LOCATION", "access")]
        self.assertEqual(loc["source"], "both")
        self.assertEqual(loc["count"], 2)               # poll 07 is the dump's 07.120; poll 22 is another
        self.assertEqual(loc["last_time"], T("22"))
        self.assertEqual(loc["states"], ["top", "bg"])
        self.assertTrue(loc["background"])
        self.assertEqual((loc["zh"], loc["category"], loc["sensitive"]), ("精确位置", "位置", True))
        cam = used[("CAMERA", "access")]
        self.assertEqual((cam["source"], cam["count"], cam["states"], cam["background"]), ("dump", None, ["cch"], True))
        clip = used[("READ_CLIPBOARD", "reject")]
        self.assertEqual((clip["source"], clip["count"], clip["background"]), ("poll", 2, False))
        self.assertTrue(used[("GET_USAGE_STATS", "reject")]["background"])
        order = [u["background"] for u in self.r["permissions"]["used"]]
        self.assertEqual(order, sorted(order, reverse=True))     # background records first

    def test_clipboard_merge(self):
        c = self.r["clipboard"]
        self.assertEqual((c["reads"], c["blocked"], c["writes"]), (3, 3, 0))
        self.assertEqual([(e["time"], e["source"]) for e in c["events"]],
                         [(T("02"), "appops"), (T("08.386"), "logcat"), (T("08.387"), "logcat")])
        self.assertEqual(c["events"][2]["result"], "blocked")    # "unknown" settled by the appops reject

    def test_processes(self):
        p = self.r["processes"]
        self.assertEqual(p["commands"], [{"pid": 1457, "cmdline": "ping -c 1 example.com"},
                                         {"pid": 888, "cmdline": "sh"}])
        by_pid = {x["pid"]: x for x in p["procs"]}
        self.assertEqual(set(by_pid), {381, 1457, 2828, 1669, 2864, 5001, 888})
        self.assertEqual(by_pid[2864]["source"], "logcat")
        self.assertEqual(by_pid[2864]["first_seen"], T("21.500"))
        self.assertEqual((by_pid[888]["source"], by_pid[888]["ppid"]), ("ps", 381))
        self.assertEqual(len(p["starts"]), 1)
        self.assertEqual(len(p["kills"]), 1)

    def test_background(self):
        b = self.r["background"]
        # A block's state lasts until the next block, and a block's ticks were used since the
        # previous one: the 20 ticks of block 15 were used in 10-15, while the app was in front.
        self.assertEqual((b["seconds_top"], b["seconds_not_top"], b["cpu_ticks_not_top"]), (10, 16, 35))
        whats = [e["what"] for e in b["events_not_top"]]
        self.assertIn("精确位置（FINE_LOCATION）：使用，不在前台", whats)
        self.assertIn("相机（CAMERA）：使用，不在前台", whats)              # from the dump state, not the time
        self.assertIn("出现进程 ping -c 1 example.com（pid 1457）", whats)
        self.assertIn("首次读取 com.eg.android.AlipayGphone 的安装包（共 20 次）", whats)
        self.assertNotIn("首次读取 com.tencent.mm 的安装包（共 30 次）", whats)   # 10:00:12 the app was in front
        self.assertFalse(any("剪贴板" in w for w in whats))
        self.assertFalse(any(w.startswith("前台") or w.startswith("进程") for w in whats))
        times = [analyze._dt(e["time"]) for e in b["events_not_top"]]
        self.assertEqual(times, sorted(times))

    def test_timeline(self):
        tl = self.r["timeline"]
        times = [analyze._dt(e["time"]) for e in tl]
        self.assertEqual(times, sorted(times))
        kinds = {e["kind"] for e in tl}
        self.assertEqual(kinds, {"front", "proc", "perm", "clipboard", "file"})
        self.assertEqual(tl[0], {"time": T("02"), "kind": "clipboard", "text": "读取剪贴板：被系统拒绝"})
        self.assertIn({"time": T("05"), "kind": "front", "text": f"前台：{PKG}/.Main（本应用）"}, tl)
        self.assertFalse(any(e["kind"] == "perm" and "READ_CLIPBOARD" in e["text"] for e in tl))
        starts = [e for e in tl if "2864" in e["text"] and "启动" in e["text"]]
        self.assertEqual(starts[0]["text"], f"系统启动进程 {PKG}:widget（pid 2864），原因：广播 {PKG}/.Widget")
        self.assertFalse(any("出现进程" in e["text"] and "2864" in e["text"] for e in tl))

    def test_highlights(self):
        hl = self.r["highlights"]
        notable = [h["text"] for h in hl if h["level"] == "notable"]
        info = [h["text"] for h in hl if h["level"] == "info"]
        self.assertEqual([h["level"] for h in hl], ["notable"] * len(notable) + ["info"] * len(info))
        self.assertIn("读取了 2 个其他应用的安装包，如 com.tencent.mm、com.eg.android.AlipayGphone；"
                      "首次读取的时间在 10:00:12 至 10:00:16 之间，其中 1 个是在应用不在前台时首次读取的。", notable)
        self.assertIn("不在前台时使用了精确位置（FINE_LOCATION），记录到 1 次，最后一次在 10:00:22。", notable)
        self.assertIn("不在前台时使用了相机（CAMERA），记录到 1 次，最后一次在 10:00:40。", notable)
        self.assertIn("不在前台时尝试使用使用情况访问（GET_USAGE_STATS），被系统拒绝，记录到 1 次，最后一次在 10:00:26。",
                      notable)
        self.assertIn("读取剪贴板 3 次（10:00:02 至 10:00:08），其中 3 次被系统拒绝，没有拿到内容。", notable)
        self.assertIn("应用的身份（u0a378）下运行了 2 个进程名不是应用自己的程序：ping -c 1 example.com（pid 1457）、sh（pid 888）。",
                      notable)
        procs = [t for t in notable if t.startswith("不在前台时新出现了")]
        self.assertEqual(len(procs), 1)
        self.assertIn("3 个应用进程", procs[0])
        self.assertIn(f"{PKG}:widget（pid 2864，10:00:21，系统启动，原因：广播，组件 {PKG}/.Widget）", procs[0])
        # 2864, 5001 and 888 were never in a poll block: their CPU time is not counted
        self.assertIn("采集 60 秒（10:00:00 至 10:01:00）；应用在前台约 10 秒，不在前台约 16 秒，"
                      "不在前台时用了至少约 0.3 秒 CPU 时间（不含轮询没有看到的 3 个进程）。", info)
        self.assertIn("在前台时使用了：精确位置（FINE_LOCATION）1 次。", info)
        self.assertIn("没有访问其他应用的数据目录，也没有访问共享存储（/sdcard 下的照片、下载等公共文件）。", info)
        self.assertIn("全系统抓包中出现了 2 个域名（不能确定哪些属于该应用），流量最多的是：b.example.com、a.example.com；"
                      "另有 1 个只有 IP 地址的服务器。", info)
        self.assertIn("系统结束了应用的进程 1 次。", info)

    def test_network_unattributed(self):
        n = self.r["network"]
        self.assertEqual((n["attributed"], n["pcap"], n["packets"], n["endpoints"]), (False, True, 50, []))
        self.assertEqual(n["hosts_unattributed"], UNATTRIBUTED)
        self.h.attribute.assert_not_called()

    def test_files(self):
        self.assertEqual(self.r["files"]["backend"], "f2fs")
        self.assertEqual(self.r["files"]["target_events"], 200)

    def test_limits(self):
        lim = self.r["limits"]
        self.assertIn("未采集到 ps_after.txt", lim)
        self.assertIn("文件跟踪的时间是换算出来的，可能比实际早 1 秒左右；"
                      "前台切换前后这段时间里的文件访问，不判断当时应用是否在前台", lim)
        # the poll looked at the sockets in every block (no "S lines in poll.txt" in meta.missing) and saw none
        self.assertIn("轮询时一次也没有看到应用的网络连接：网络部分列出的是全手机抓包里的服务器，不能确定哪些属于该应用", lim)
        self.assertIn("应用的网络连接每 1–2 秒查看一次：持续不到 2 秒的连接可能没有记录到", lim)
        # the stub poll's last block is 10:00:30, the capture ends 10:01:00
        self.assertIn("轮询在 10:00:30 就结束了，此后 30 秒不知道前台应用和应用进程", lim)
        self.assertIn("采集记录注明：poll.txt 里没有权限查询时刻（OT 行），由轮询推算的权限使用时间可能相差几秒", lim)
        self.assertFalse(any("轮询从" in x or "系统日志从" in x or "系统日志在" in x for x in lim))   # within 5 s / 10 s
        self.assertFalse(any("数据包在采集" in x for x in lim))
        self.assertFalse(any("进程号" in x or "没有任何记录" in x or "poll.txt 里没有记录" in x for x in lim))


class AnalyzeVariants(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_only_meta(self):
        run = make_run(self.tmp.name, files=())
        with Harness() as h:
            r = analyze.analyze(run)
        self.assertTrue((run / "result.json").exists())
        self.assertEqual(r["files"], {"backend": "f2fs", "open_files": []})     # meta says f2fs; nothing to read
        self.assertEqual(r["permissions"], {"granted": [], "used": []})
        self.assertEqual(r["captured"], {"poll": False, "logcat": False, "appops": False, "ps": False,
                                         "trace": False, "pcap": False, "decrypted": False, "cleartext": False})
        self.assertEqual(r["cleartext"], {"checked": False, "error": None, "attributed": False, "tshark": None,
                                          "connections": [], "exchanges": [],
                                          "others": {"connections": 0, "requests": 0}})
        self.assertEqual(r["clipboard"], {"reads": 0, "blocked": 0, "writes": 0, "events": []})
        self.assertEqual(r["processes"]["procs"], [])
        self.assertEqual(r["timeline"], [])
        self.assertEqual(r["network"]["pcap"], False)
        self.assertEqual(r["highlights"], [{"level": "info", "text": "采集 60 秒（10:00:00 至 10:01:00）。"}])
        h.diff.assert_not_called()
        self.assertEqual(h.trace.calls, [])
        lim = r["limits"]
        for expected in ("未采集到 appops_after.txt，轮询也没有记录：没有权限使用记录",
                         "未采集到 ps_before.txt、ps_after.txt：应用进程只来自轮询和系统日志",
                         "未采集到 net.pcap：没有域名和流量数据",
                         "未采集到 poll.txt：无法判断应用何时在前台，也没有轮询得到的进程、连接和权限记录",
                         "未采集到 logcat.txt：没有进程启动原因和剪贴板日志",
                         "未采集到 filetrace_f2fs.txt：没有文件访问记录",
                         "未采集到 package_dump.txt：不知道应用已获得哪些权限",
                         "未采集到 appops_before.txt"):
            self.assertIn(expected, lim)
        self.assertEqual(lim[-1], "采集记录注明：poll.txt 里没有权限查询时刻（OT 行），由轮询推算的权限使用时间可能相差几秒")

    def test_poll_only_permissions_and_late_sources(self):
        meta = dict(META, filetrace_backend="none", net=False, missing=[])
        poll = dict(POLL, first_time=T("20"), cpu=POLL["cpu"][3:])
        logcat = dict(LOGCAT, first_time=T("12.000"))
        run = make_run(self.tmp.name, meta=meta, files=("poll.txt", "logcat.txt"))
        with Harness(poll=poll, logcat=logcat):
            r = analyze.analyze(run)
        self.assertIn("未采集到 appops_after.txt：权限使用仅来自轮询", r["limits"])
        self.assertIn("本次没有抓包：没有域名和流量数据", r["limits"])
        self.assertIn("本次没有启用文件跟踪：没有文件访问记录", r["limits"])
        self.assertIn("轮询从 10:00:20 才开始，此前 20 秒不知道前台应用和应用进程", r["limits"])
        self.assertIn("系统日志从 10:00:12 才开始，此前 12 秒看不到进程启动和剪贴板记录", r["limits"])
        self.assertFalse(any("filetrace" in x for x in r["limits"]))
        self.assertTrue(all(u["source"] == "poll" for u in r["permissions"]["used"]))
        self.assertEqual(r["files"], {"backend": "none", "open_files": []})

    def test_sockets_attributed(self):
        sockets = [{"proto": "tcp", "ip": "1.2.3.4", "port": 443, "first_seen": T("21"), "last_seen": T("29")}]
        records = [{"proto": "tcp", "ip": "1.2.3.4", "port": 443, "host": "edith.example.com", "host_source": "sni",
                    "first_seen": T("21"), "last_seen": T("29"), "bytes_out": 1024, "bytes_in": 9216, "plaintext": None}]
        run = make_run(self.tmp.name)
        with Harness(poll=dict(POLL, sockets=sockets), attributed=records) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        self.assertEqual(h.attribute.call_args.args[1], sockets)
        h.unattributed.assert_not_called()
        n = r["network"]
        self.assertEqual((n["attributed"], n["endpoints"], n["hosts_unattributed"]), (True, records, []))
        self.assertIn({"time": T("21"), "kind": "net", "text": "连接 edith.example.com（1.2.3.4:443，tcp）"}, r["timeline"])
        self.assertIn({"time": T("21"), "what": "连接 edith.example.com（1.2.3.4:443，tcp）"},
                      r["background"]["events_not_top"])
        self.assertIn({"level": "info", "text": "应用连接了 1 个远程地址，其中 1 个域名：edith.example.com；收发约 10 KB。"},
                      r["highlights"])
        self.assertFalse(any("网络连接记录" in x for x in r["limits"]))

    def test_sockets_without_pcap(self):
        sockets = [{"proto": "udp", "ip": "5.6.7.8", "port": 443, "first_seen": T("06"), "last_seen": T("09")}]
        run = make_run(self.tmp.name, files=("poll.txt",))
        with Harness(poll=dict(POLL, sockets=sockets)) as h:
            r = analyze.analyze(run)
        h.attribute.assert_not_called()
        self.assertEqual(r["network"]["endpoints"], [
            {"proto": "udp", "ip": "5.6.7.8", "port": 443, "host": None, "host_source": None, "first_seen": T("06"),
             "last_seen": T("09"), "bytes_out": None, "bytes_in": None, "plaintext": None}])
        self.assertTrue(r["network"]["attributed"])

    def test_other_app_data_and_shared_storage(self):
        files = dict(FILES, other_app_apks=[],
                     other_app_data=[{"package": "com.tencent.mm", "reads": 3, "writes": 0, "paths": ["/x"]}],
                     shared_storage=[{"dir": "/sdcard/Pictures", "reads": 4, "writes": 1, "files": ["/sdcard/Pictures/a.jpg"]}],
                     sync=None)
        run = make_run(self.tmp.name)
        with Harness(files=files):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        hl = r["highlights"]
        self.assertIn({"level": "notable", "text": "访问了 1 个其他应用的数据目录（读 3 次、写 0 次）：com.tencent.mm（/x）。"}, hl)
        self.assertIn({"level": "info", "text": "访问了共享存储中 1 个目录的文件（读 4 次、写 1 次），如 /sdcard/Pictures。"}, hl)
        self.assertFalse(any("没有访问其他应用的数据目录" in h["text"] for h in hl))
        self.assertIn("文件跟踪没有可用的时钟对照：文件访问没有具体时间", r["limits"])

    def test_app_process_pids(self):
        run = make_run(self.tmp.name)
        with Harness(logcat=dict(LOGCAT, app_process_starts=APP_PROCESS_STARTS)) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        _, args, kwargs = h.trace.calls[0]
        self.assertEqual(args[1], {381, 1457, 2828, 1669, 2864, 5001, 888, 6000})
        self.assertNotIn(6000, kwargs["pid_names"])          # no name known
        p = r["processes"]
        self.assertEqual(p["app_starts"], APP_PROCESS_STARTS)
        by_pid = {x["pid"]: x for x in p["procs"]}
        self.assertEqual((by_pid[6000]["source"], by_pid[6000]["started_by"], by_pid[6000]["first_seen"]),
                         ("logcat", "app", T("23.000")))
        self.assertEqual((by_pid[2828]["source"], by_pid[2828]["started_by"], by_pid[2828]["main"]),
                         ("poll", "app", "com/example/Daemon"))
        self.assertEqual(by_pid[2864]["started_by"], "system")
        self.assertIsNone(by_pid[381]["started_by"])
        self.assertFalse(any(c["pid"] == 6000 for c in p["commands"]))
        tl = r["timeline"]
        self.assertIn({"time": T("23.000"), "kind": "proc", "text": "应用自己通过 app_process 启动进程（pid 6000）"}, tl)
        self.assertIn({"time": T("19.500"), "kind": "proc",
                       "text": "应用自己通过 app_process 启动进程（pid 2828，入口 com/example/Daemon）"}, tl)
        self.assertFalse(any(e["text"].startswith("出现进程") and "pid 2828" in e["text"] for e in tl))
        procs = [h["text"] for h in r["highlights"] if h["text"].startswith("不在前台时新出现了")][0]
        self.assertIn("4 个应用进程", procs)
        self.assertIn("2 个是应用自己通过 app_process 启动的（pid 2828、6000，10:00:19 至 10:00:23）", procs)

    def test_trace_clock_from_process_starts(self):
        """A process's first file event cannot come before logcat's start of it: the converted
        trace times are moved later by the largest such gap, at most the clock's error."""
        sync = {"trace_ts": 100.0, "epoch": 1795014000, "approx": True}      # 100.0 = 10:00:00 at -0500
        by_process = [{"pid": 2828, "name": None, "thread": ":w", "reads": 1, "writes": 0, "first_ts": 119.0},
                      {"pid": 6000, "name": None, "thread": ":w", "reads": 1, "writes": 0, "first_ts": 122.2},
                      {"pid": 381, "name": PKG, "thread": PKG, "reads": 1, "writes": 0, "first_ts": 101.0}]
        apks = [{"package": "com.a", "reads": 4, "first_time": T("14.700"), "first_ts": 114.7, "pids": [6000]}]
        files = dict(FILES, sync=sync, by_process=by_process, other_app_apks=apks)
        poll = dict(POLL, cpu=[{"time": T("05"), "ticks": 0, "target_top": True},
                               {"time": T("15"), "ticks": 0, "target_top": False}])
        run = make_run(self.tmp.name)
        with Harness(poll=poll, files=files, logcat=dict(LOGCAT, app_process_starts=APP_PROCESS_STARTS)):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        f = r["files"]
        # 2828: logcat 19.500, first event 19.000 -> 0.5 s; 6000: 23.000 vs 22.200 -> 0.8 s
        self.assertEqual(f["clock_lag_s"], 0.8)
        a = f["other_app_apks"][0]
        self.assertEqual(a["first_time"], T("15.500"))
        self.assertIs(a["background"], True)     # 15.5 to 15.7 is after the switch at 15
        self.assertIn("首次读取 com.a 的安装包（共 4 次）", [e["what"] for e in r["background"]["events_not_top"]])
        self.assertIn("文件跟踪的时间是换算出来的：已按应用进程的启动时刻（系统日志）推后 0.80 秒，仍可能比实际早约 0.2 秒；"
                      "前台切换前后这段时间里的文件访问，不判断当时应用是否在前台", r["limits"])
        # a gap larger than the clock can be off (pid reuse) is not used
        by_process[1]["first_ts"] = 110.0
        with tempfile.TemporaryDirectory() as tmp:
            with Harness(poll=poll, files=files, logcat=dict(LOGCAT, app_process_starts=APP_PROCESS_STARTS)):
                r = analyze.analyze(make_run(tmp), Path(tmp) / "o")
        self.assertEqual(r["files"]["clock_lag_s"], 0.5)

    def test_deaths_and_caused_starts(self):
        """A death without a kill line reaches the result as kind "died"; other apps' processes the
        app made the system start are listed; a start by the app's own broadcast says so."""
        logcat = dict(LOGCAT, proc_deaths=[{"time": T("55.000"), "pid": 2828, "process": f"{PKG}:widget",
                                            "state": "cch+25 CEM"}],
                      caused_starts=[{"time": T("21.000"), "pid": 1952, "process": "com.oplus.cosa", "reason": "service",
                                      "component": "com.oplus.cosa/.Boost",
                                      "caller": {"package": PKG, "uid": None, "action": None}}],
                      proc_starts=[dict(LOGCAT["proc_starts"][0],
                                        caller={"package": None, "uid": 10378, "action": "x.UPDATE"})])
        run = make_run(self.tmp.name)
        with Harness(logcat=logcat):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        p = r["processes"]
        self.assertEqual([(k["pid"], k["kind"], k["reason"]) for k in p["kills"]],
                         [(2864, "kill", "cached"), (2828, "died", "cch+25 CEM")])
        self.assertEqual(p["caused_starts"], logcat["caused_starts"])
        tl = [e["text"] for e in r["timeline"]]
        self.assertIn(f"进程 {PKG}:widget（pid 2828）结束（系统日志没有写明原因）：cch+25 CEM", tl)
        self.assertIn("系统启动其他应用的进程 com.oplus.cosa（pid 1952），原因：应用自己（uid 10378）发起的服务 "
                      "com.oplus.cosa/.Boost", tl)
        self.assertIn(f"系统启动进程 {PKG}:widget（pid 2864），原因：应用自己（uid 10378）发起的广播 {PKG}/.Widget", tl)
        info = [h["text"] for h in r["highlights"]]
        self.assertIn("系统结束了应用的进程 1 次。", info)
        self.assertIn("应用的进程另有 1 次结束，系统日志没有写明原因。", info)

    def test_unknown_front_state_and_kept_processes(self):
        poll = copy.deepcopy(POLL)
        poll["ops"]["FINE_LOCATION"]["events"].append({"kind": "access", "time": T("15"), "target_top": None})
        poll["procs"]["1604"] = {"cmdline": f"{PKG}:widget", "first_seen": T("06"), "last_seen": T("30"),
                                 "ppid": 381, "cpu_ticks": 2, "adj": [0], "read_bytes": 0}
        run = make_run(self.tmp.name)
        with Harness(poll=poll, logcat=dict(LOGCAT, app_process_starts=[{"time": T("05.500"), "pid": 1604,
                                                                          "main": "a/b/C"}])):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        loc = [u for u in r["permissions"]["used"] if u["op"] == "FINE_LOCATION"][0]
        self.assertEqual(loc["states"], ["top", "unknown", "bg"])
        hl = [h["text"] for h in r["highlights"]]
        self.assertIn("在前台时使用了：精确位置（FINE_LOCATION）1 次。", hl)
        self.assertIn("无法判断当时应用是否在前台（发生在前台切换前后，或轮询开始之前）：精确位置（FINE_LOCATION）1 次（10:00:15）。", hl)
        self.assertIn({"time": T("15"), "kind": "perm", "text": "精确位置（FINE_LOCATION）：使用，无法判断当时是否在前台"},
                      r["timeline"])
        # not listed among the things done while not in front, though the poll says "not in front" at 15
        self.assertFalse(any("无法判断" in e["what"] for e in r["background"]["events_not_top"]))
        # 1604 ran from 10:00:06 to the last block with adj 0 only, the app not in front at the end;
        # 1457 (adj 0 too) was gone before that, 381 went to 900
        self.assertIn(f"应用不在前台时，有 1 个应用进程一直运行到采集结束，它们的内存回收优先级（oom_score_adj）始终是 0，"
                      f"与前台应用相同：{PKG}:widget（pid 1604，应用自己通过 app_process 启动，10:00:06 起）。", hl)

    def test_screen_off_and_sources_ending_early(self):
        poll = dict(POLL, top=POLL["top"] + [{"start": T("31"), "end": T("40"), "component": None, "package": None,
                                              "task": None}],
                    last_time=T("40"))
        logcat = dict(LOGCAT, last_time=T("45.000"),
                      screen=[{"time": T("30.500"), "on": False}, {"time": T("38.000"), "on": True}])
        meta = dict(META, missing=[])
        run = make_run(self.tmp.name, meta=meta)
        files = dict(FILES, last_ts=40.0)        # sync: trace 1.0 = 10:00:00
        pcap = dict(PCAP, last_epoch=1795014030.0)
        with Harness(poll=poll, logcat=logcat, files=files, pcap=pcap):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        lim = r["limits"]
        # blocks 31 to 40 have no front activity: 10 s, 7 of them with the screen off (31 to 38)
        self.assertIn("轮询中有约 10 秒没有记录到前台界面（没有 topResumedActivity），其中约 7 秒屏幕是关闭的"
                      "（系统日志 screen_toggled）；这段时间按应用不在前台计算", lim)
        self.assertIn("轮询在 10:00:40 就结束了，此后 20 秒不知道前台应用和应用进程", lim)
        self.assertIn("系统日志在 10:00:45 就结束了，此后 15 秒看不到进程启动和剪贴板记录", lim)
        self.assertIn("抓包里的最后一个数据包在采集结束前 30 秒，此后的网络流量没有记录", lim)
        self.assertIn("文件跟踪的最后一条记录在采集结束前 21 秒，此后的文件访问没有记录", lim)
        self.assertIn({"time": T("30.500"), "kind": "screen", "text": "屏幕关闭"}, r["timeline"])

    def test_unreadable_pcap_and_phone_side_notes(self):
        """net.pcap in a format parse_pcap refuses, what aw_ctl.sh found missing on the phone,
        a capture the phone stopped by itself, and an empty file collect listed in meta.missing."""
        meta = dict(META, filetrace_backend="none", unavailable=["f2fs_events"], autostop="disk",
                    missing=["logcat.txt", "kernel.txt", "utc_offset"])

        def bad_pcap(path):
            raise ValueError(f"not a classic pcap file: {path}")

        run = make_run(self.tmp.name, meta=meta)
        with Harness() as h:
            h.pcap = bad_pcap
            with mock.patch.object(analyze, "parse_net", SimpleNamespace(parse_pcap=bad_pcap, attribute=h.attribute,
                                                                         hosts_unattributed=h.unattributed)):
                r = analyze.analyze(run, Path(self.tmp.name) / "o")
        lim = r["limits"]
        self.assertFalse(r["network"]["pcap"])
        self.assertIn("net.pcap 的格式无法识别（只能读取 classic pcap，链路类型 1、113、276）：没有域名和流量数据", lim)
        self.assertIn(analyze.UNAVAILABLE_ZH["f2fs_events"], lim)
        self.assertNotIn("本次没有启用文件跟踪：没有文件访问记录", lim)
        self.assertIn("手机存储空间不足 1 GB，采集由手机在 10:01:00 自行停止", lim)
        self.assertIn("未采集到 logcat.txt：没有进程启动原因和剪贴板日志", lim)       # present here, but empty
        self.assertIn("采集记录注明：没有记录内核版本（kernel.txt）；没有记录手机的时区（utc_offset）："
                      "文件访问的时间按 UTC 换算，可能与手机时间相差几个小时", lim)

        meta = dict(META, net=False, unavailable=["tcpdump"], missing=[])
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, meta=meta, files=("poll.txt",))
            with Harness():
                r = analyze.analyze(run, Path(tmp) / "o")
        self.assertIn(analyze.UNAVAILABLE_ZH["tcpdump"], r["limits"])
        self.assertFalse(any("net.pcap" in x for x in r["limits"]))

    def test_last_block_ends_at_capture_end(self):
        meta = dict(META, end_time=T("30"))
        run = make_run(self.tmp.name, meta=meta)
        with Harness():
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        b = r["background"]
        self.assertEqual((b["seconds_top"], b["seconds_not_top"]), (10, 15))

    def test_nothing_attributable(self):
        """No pid of the app known, or a trace without events: no claim that the app accessed nothing."""
        poll = dict(POLL, procs={})
        logcat = dict(LOGCAT, proc_starts=[], pid_map={})
        meta = dict(META, missing=[])
        run = make_run(self.tmp.name, meta=meta, files=("poll.txt", "logcat.txt", "filetrace_f2fs.txt"))
        with Harness(poll=poll, logcat=logcat, files=dict(FILES, other_app_apks=[], target_events=0)) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o1")
        self.assertEqual(h.trace.calls[0][1][1], set())
        self.assertFalse(any("没有访问其他应用的数据目录" in x["text"] for x in r["highlights"]))
        self.assertIn("没有找到应用的进程号：文件跟踪里的访问无法归到这个应用，没有文件访问记录", r["limits"])

        with Harness(files=dict(FILES, events=0, target_events=0, other_app_apks=[])):
            r = analyze.analyze(run, Path(self.tmp.name) / "o2")
        self.assertFalse(any("没有访问其他应用的数据目录" in x["text"] for x in r["highlights"]))
        self.assertIn("文件跟踪里没有任何记录：没有文件访问记录", r["limits"])
        self.assertFalse(any("进程号" in x for x in r["limits"]))

    def test_empty_poll(self):
        poll = {"blocks": 0, "first_time": None, "last_time": None, "top": [], "procs": {}, "cpu": [],
                "sockets": [], "ops": {}, "fds": []}
        meta = dict(META, missing=[])
        run = make_run(self.tmp.name, meta=meta, files=("poll.txt", "net.pcap"))
        with Harness(poll=poll):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        info = [x["text"] for x in r["highlights"] if x["level"] == "info"]
        self.assertEqual(info[0], "采集 60 秒（10:00:00 至 10:01:00）。")
        self.assertIn("poll.txt 里没有记录：无法判断应用何时在前台，也没有轮询得到的进程、连接和权限记录", r["limits"])
        self.assertIn("未采集到 appops_after.txt，轮询也没有记录：没有权限使用记录", r["limits"])
        self.assertFalse(any("网络连接" in x for x in r["limits"]))

    def test_only_ip_hosts(self):
        meta = dict(META, missing=[])
        run = make_run(self.tmp.name, meta=meta, files=("net.pcap",))
        hosts = [{"host": "1.2.3.4", "port": 443, "bytes": 10, "host_source": None},
                 {"host": "1.2.3.4", "port": 80, "bytes": 10, "host_source": None},
                 {"host": "5.6.7.8", "port": 443, "bytes": 10, "host_source": None}]
        with Harness(unattributed=hosts):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        self.assertIn({"level": "info", "text": "全系统抓包中没有域名，只有 2 个服务器的 IP 地址（不能确定哪些属于该应用）。"},
                      r["highlights"])

    def test_file_access_near_front_change(self):
        """With an approximate trace clock (times up to 1 s early) an access within 1 s before a front
        change is not said to be in front or not; with an exact clock it is."""
        poll = dict(POLL, cpu=[{"time": T("05"), "ticks": 0, "target_top": True},
                               {"time": T("10"), "ticks": 0, "target_top": False},
                               {"time": T("15"), "ticks": 0, "target_top": True}])
        apks = [{"package": "com.a", "reads": 1, "first_time": T("10.200")},
                {"package": "com.b", "reads": 1, "first_time": T("14.500")}]
        for approx, expected in ((True, ["com.a"]), (False, ["com.a", "com.b"])):
            files = dict(FILES, other_app_apks=apks, sync=dict(FILES["sync"], approx=approx))
            with tempfile.TemporaryDirectory() as tmp:
                run = make_run(tmp)
                with Harness(poll=poll, files=files):
                    r = analyze.analyze(run, Path(tmp) / "o")
            listed = [w for e in r["background"]["events_not_top"] if (w := e["what"]).startswith("首次读取")]
            self.assertEqual(listed, [f"首次读取 {p} 的安装包（共 1 次）" for p in expected], approx)


def xchg(time, host, path="/a", method="GET", source="ecapture", partial=(), req_body=None, resp_body=None,
         response=True):
    """A synthetic exchange record (docs/CONTRACT_DECRYPT.md)."""
    return {"source": source, "time": time, "protocol": "h2", "method": method, "scheme": "https", "host": host,
            "path": path, "query": [],
            "request": {"headers": [[":method", method]], "body": req_body, "complete": True},
            "response": {"status": 200, "headers": [], "body": resp_body, "complete": True} if response else None,
            "pid": 381 if source == "ecapture" else None, "thread": "OkHttp w" if source == "ecapture" else None,
            "partial": list(partial)}


JSON_BODY = make_body(b'{"ok": true}', "application/json")                     # 12 bytes
BR_BODY = make_body(b"\x1b\x03\x00\xf8", "application/json", "br")              # 4 bytes, not decoded
# what parse_har gives for a body whose HAR text cannot be turned back into bytes
HAR_UNRESTORABLE = {"size": None, "sha256": None, "encoding": None, "decoded": False, "kind": "binary",
                    "text": None, "truncated": False, "preview_hex": None}
TLS = {"records": 20, "bytes": 5000, "first_time": T("06.000"), "last_time": T("40.000"), "out_of_order": 0,
       "cut_off": False, "threads": [{"pid": 381, "tid": 400, "comm": "OkHttp w", "reads": 3, "writes": 4}],
       "exchanges": [xchg(T("21.100"), "api.example.com", resp_body=JSON_BODY),
                     xchg(T("21.900"), "api.example.com", "/b", "POST", req_body=JSON_BODY, resp_body=BR_BODY),
                     xchg(T("08.000"), "img.example.com", "/i.jpg", partial=["hpack_state_unknown"]),
                     xchg(T("25.000"), "API.example.com:8443", "/a", response=False, partial=["response_not_matched"])],
       "undecoded": {"records": 3, "bytes": 120, "reasons": {"hpack_state_unknown": 2, "x_new_code": 1}}}
ENDPOINTS = [
    {"proto": "tcp", "ip": "1.2.3.4", "port": 443, "host": "api.example.com", "host_source": "sni",
     "first_seen": T("21"), "last_seen": T("29"), "bytes_out": 100, "bytes_in": 900, "plaintext": None},
    {"proto": "tcp", "ip": "1.2.3.5", "port": 443, "host": "api.example.com", "host_source": "sni",
     "first_seen": T("22"), "last_seen": T("23"), "bytes_out": 10, "bytes_in": 20, "plaintext": None},
    {"proto": "tcp", "ip": "5.6.7.8", "port": 443, "host": "cdn.example.com", "host_source": "dns",
     "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 300, "bytes_in": 7000, "plaintext": None},
    {"proto": "udp", "ip": "9.9.9.9", "port": 443, "host": None, "host_source": None,
     "first_seen": T("06"), "last_seen": T("07"), "bytes_out": 5, "bytes_in": 5, "plaintext": None},
]
SOCKETS = [{"proto": e["proto"], "ip": e["ip"], "port": e["port"], "first_seen": e["first_seen"],
            "last_seen": e["last_seen"]} for e in ENDPOINTS]
EMPTY_DECRYPTED = {"sources": [], "ecapture": None, "keylog": None, "keylog_error": None, "har": None,
                   "exchanges": [], "hosts": [], "not_covered": []}


class AnalyzeDecrypt(unittest.TestCase):
    """result["decrypted"], endpoint plaintext, timeline, highlights and limits, with synthetic
    exchanges standing in for parse_tls_events / parse_har."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_with(self, files=("poll.txt", "net.pcap", "tls_events.log"), meta=None, har_arg=None, **harness):
        run = make_run(self.tmp.name, meta=meta or dict(META, missing=[]), files=files)
        harness.setdefault("attributed", copy.deepcopy(ENDPOINTS))
        with Harness(poll=dict(POLL, sockets=SOCKETS), **harness) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o", har=har_arg)
        return run, h, r

    def test_no_source(self):
        run, h, r = self.run_with(files=("poll.txt", "net.pcap"), tls=TLS)
        self.assertEqual(r["decrypted"], EMPTY_DECRYPTED)
        self.assertFalse(r["captured"]["decrypted"])
        self.assertEqual((h.tls.calls, h.har.calls), ([], []))
        self.assertTrue(all(e["plaintext"] is None for e in r["network"]["endpoints"]))
        self.assertFalse(any(e["kind"] == "decrypted" for e in r["timeline"]))
        self.assertFalse(any(w in x for x in r["limits"] for w in ("eCapture", "HAR", "tls_events")))
        self.assertFalse(any("解密" in x["text"] for x in r["highlights"]))

    def test_ecapture(self):
        # meta has no "decrypt" key (as in fixtures/live_xhs_tls_0120): tls_events.log decides
        run, h, r = self.run_with(tls=TLS)
        self.assertEqual(h.tls.calls[0][2], {"utc_offset": "-0500"})
        self.assertEqual(h.har.calls, [])
        self.assertTrue(r["captured"]["decrypted"])
        d = r["decrypted"]
        self.assertEqual(d["sources"], ["ecapture"])
        self.assertIsNone(d["har"])
        self.assertEqual(d["ecapture"], {"records": 20, "bytes": 5000, "first_time": T("06.000"),
                                         "last_time": T("40.000"), "out_of_order": 0, "cut_off": False,
                                         "undecoded": TLS["undecoded"]})
        self.assertEqual([(x["id"], x["time"]) for x in d["exchanges"]],
                         [(1, T("08.000")), (2, T("21.100")), (3, T("21.900")), (4, T("25.000"))])
        self.assertEqual(d["exchanges"][1]["request"], TLS["exchanges"][0]["request"])
        self.assertEqual(d["hosts"], [
            {"host": "api.example.com", "exchanges": 2, "methods": {"GET": 1, "POST": 1}, "sources": ["ecapture"],
             "request_bytes": 12, "response_bytes": 16, "request_bodies_unknown": 0, "response_bodies_unknown": 0,
             "paths": [["/a", 1], ["/b", 1]]},
            # no response matched: what came back is not known, so 0 is a lower bound
            {"host": "API.example.com:8443", "exchanges": 1, "methods": {"GET": 1}, "sources": ["ecapture"],
             "request_bytes": 0, "response_bytes": 0, "request_bodies_unknown": 0, "response_bodies_unknown": 1,
             "paths": [["/a", 1]]},
            {"host": "img.example.com", "exchanges": 1, "methods": {"GET": 1}, "sources": ["ecapture"],
             "request_bytes": 0, "response_bytes": 0, "request_bodies_unknown": 0, "response_bodies_unknown": 0,
             "paths": [["/i.jpg", 1]]}])
        eps = r["network"]["endpoints"]
        # both addresses of api.example.com; the host with a port and other case is the same name
        self.assertEqual([e["plaintext"] for e in eps],
                         [{"exchanges": 3, "ids": [2, 3, 4]}, {"exchanges": 3, "ids": [2, 3, 4]}, None, None])
        self.assertEqual(d["not_covered"], [{"host": "cdn.example.com", "bytes": 7300}])

        rows = [e for e in r["timeline"] if e["kind"] == "decrypted"]
        self.assertEqual(rows, [
            {"time": T("08.000"), "kind": "decrypted", "text": "解密到发往 img.example.com 的 1 个请求（GET 1）"},
            {"time": T("21.100"), "kind": "decrypted", "text": "解密到发往 api.example.com 的 2 个请求（GET 1、POST 1）"},
            {"time": T("25.000"), "kind": "decrypted", "text": "解密到发往 API.example.com:8443 的 1 个请求（GET 1）"}])
        not_top = [e["what"] for e in r["background"]["events_not_top"]]
        self.assertIn("解密到发往 api.example.com 的 2 个请求（GET 1、POST 1）", not_top)       # 10:00:21: not in front
        self.assertNotIn("解密到发往 img.example.com 的 1 个请求（GET 1）", not_top)            # 10:00:08: in front

        info = [x["text"] for x in r["highlights"] if x["level"] == "info"]
        self.assertIn("解密了 4 个 HTTPS 请求（eCapture 4 个），发往 3 个域名；请求最多的域名是 api.example.com、"
                      "API.example.com:8443、img.example.com。", info)
        # the nameless UDP endpoint (9.9.9.9, 10 bytes) cannot be matched with a host
        self.assertIn("应用连接的 1 个域名没有解密到内容：cdn.example.com。应用另有 1 个服务器只有 IP 地址（抓包约 10 字节），"
                      "不知道解密到的请求里有没有发往它们的。没有解密到内容时，通常的原因是应用用自己的网络库收发"
                      "（eCapture 只能看到系统 TLS 库里的内容），或者连接用的不是 HTTPS；这种情况可以按 docs/MITM.md "
                      "自己设置代理录制，再用 analyze --har 导入。", info)
        lim = r["limits"]
        self.assertIn(analyze.ECAPTURE_SCOPE_ZH, lim)
        self.assertIn("eCapture 的记录中有 3 条没有归入任何请求：连接的开头没有记录到，部分请求头无法还原 2 条、"
                      "x_new_code 1 条；不属于任何请求的内容共 120 字节", lim)
        self.assertIn("解密到的 4 个请求中有 2 个不完整或不确定（连接的开头没有记录到，部分请求头无法还原：1 个；"
                      "没有找到对应的响应：1 个）：报告里只列出确定的部分，每个请求下注明了原因", lim)
        self.assertIn("有 1 个正文没有解码（br 1 个）：br、zstd 压缩无法用 Python 标准库解码；"
                      "这些正文不显示解码后的内容，报告只给出类型和大小（加 --show-secrets 时，有字节的还给出 sha256 和开头字节的十六进制）", lim)
        saved = json.loads((Path(self.tmp.name) / "o" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["decrypted"], json.loads(json.dumps(d)))

    def test_har_import(self):
        har_file = Path(self.tmp.name) / "phone.har"
        har_file.write_text('{"log": {}}', encoding="utf-8")
        har = {"creator": "mitmproxy 11.0", "entries": 4, "skipped": 1, "exchanges": [
            xchg("2026-11-18 09:59:59.500", "api.example.com", source="har"),     # before the capture
            xchg(T("21.000"), "api.example.com", source="har", req_body=HAR_UNRESTORABLE,
                 resp_body=make_body(b"\x1f\x8b\x08\x00cut", "application/json", "gzip")),
            xchg("2026-11-18 10:01:00.999", "cdn.example.com", source="har"),     # end_time 10:01:00 is truncated
            xchg("2026-11-18 10:01:01.000", "cdn.example.com", source="har")]}    # after it
        run, h, r = self.run_with(files=("poll.txt", "net.pcap"), har=har, har_arg=har_file)
        self.assertEqual(h.har.calls[0][:1] + (h.har.calls[0][2],), (har_file, {"utc_offset": "-0500"}))
        self.assertEqual((run / "mitm.har").read_text(encoding="utf-8"), '{"log": {}}')
        self.assertEqual(h.tls.calls, [])
        d = r["decrypted"]
        self.assertEqual(d["sources"], ["har"])
        self.assertEqual(d["har"], {"creator": "mitmproxy 11.0", "entries": 4, "skipped": 1, "in_window": 2,
                                    "outside_window": 2})
        self.assertEqual([x["partial"] for x in d["exchanges"]], [["outside_capture"], [], [], ["outside_capture"]])
        self.assertEqual(har["exchanges"][0]["partial"], [])            # the parser's records are not changed
        # only exchanges inside the capture tell which connections were decrypted
        self.assertEqual([e["plaintext"] for e in r["network"]["endpoints"]],
                         [{"exchanges": 1, "ids": [2]}, {"exchanges": 1, "ids": [2]}, {"exchanges": 1, "ids": [3]},
                          None])
        self.assertEqual(d["not_covered"], [])
        rows = [e for e in r["timeline"] if e["kind"] == "decrypted"]
        self.assertEqual([e["time"] for e in rows], [T("21.000"), "2026-11-18 10:01:00.999"])
        self.assertTrue(rows[0]["text"].endswith("，来自代理 HAR 文件"))
        # a HAR file can hold other apps' requests: not listed as the app's activity while not in front
        self.assertFalse(any("解密" in e["what"] for e in r["background"]["events_not_top"]))
        lim = r["limits"]
        self.assertIn("HAR 文件是你自己设置的代理录制的，里面可能有手机上其他应用的请求，Stakeout 无法区分", lim)
        self.assertIn("HAR 文件中有 2 个请求不在本次采集时间内（10:00:00 至 10:01:00），报告中标为“不在本次采集时间内”，"
                      "也不用来判断应用的哪些连接被解密了", lim)
        self.assertIn("HAR 文件中有 1 条记录没有可用的请求，没有导入", lim)
        self.assertIn("有 2 个正文没有解码（无法还原的 1 个、gzip 1 个）：gzip、deflate 压缩的正文没能解码，说明数据不完整或"
                      "已损坏；HAR 文件里的正文无法还原成发送时的字节；这些正文不显示解码后的内容，"
                      "报告只给出类型和大小（加 --show-secrets 时，有字节的还给出 sha256 和开头字节的十六进制）", lim)
        # size unknown: not counted, and the sum is a lower bound
        self.assertEqual((d["hosts"][0]["request_bytes"], d["hosts"][0]["request_bodies_unknown"]), (0, 1))
        self.assertFalse(any("eCapture" in x for x in lim))
        info = [x["text"] for x in r["highlights"]]
        self.assertIn("解密了 4 个 HTTPS 请求（代理 HAR 文件 4 个），发往 2 个域名；请求最多的域名是 api.example.com、"
                      "cdn.example.com；其中 2 个不在本次采集时间内；HAR 文件里可能有手机上其他应用的请求。", info)

        # later analyses use the copy in the run directory
        with Harness(poll=dict(POLL, sockets=SOCKETS), attributed=copy.deepcopy(ENDPOINTS), har=har) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o2")
        self.assertEqual(h.har.calls[0][0], run / "mitm.har")
        self.assertEqual(r["decrypted"]["har"]["entries"], 4)

    def test_not_a_har_file(self):
        def not_har(path, utc_offset="+0000"):
            raise ValueError("这个文件不是 HAR 格式。")

        bad = Path(self.tmp.name) / "x.har"
        bad.write_text("x", encoding="utf-8")
        run = make_run(self.tmp.name, files=("poll.txt",))
        with Harness(har=not_har):
            with self.assertRaisesRegex(ValueError, "不是 HAR"):
                analyze.analyze(run, Path(self.tmp.name) / "o", har=bad)
        self.assertFalse((run / "mitm.har").exists())          # nothing copied
        # an unreadable mitm.har already in the run directory is a limit, not a failure
        (run / "mitm.har").write_text("x", encoding="utf-8")
        with Harness(har=not_har):
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        self.assertIn("运行目录里的 mitm.har 无法读取（这个文件不是 HAR 格式。）：没有导入代理录制的内容", r["limits"])
        self.assertFalse(r["captured"]["decrypted"])
        self.assertEqual(r["decrypted"], EMPTY_DECRYPTED)

    def test_decrypt_asked_but_nothing_came_back(self):
        # meta says eCapture ran, but the file is not there
        run, h, r = self.run_with(files=("poll.txt",), meta=dict(META, decrypt="ecapture", missing=[]), tls=TLS)
        self.assertIn("未采集到 tls_events.log：没有 eCapture 解密的内容", r["limits"])
        self.assertFalse(r["captured"]["decrypted"])
        self.assertEqual(r["decrypted"], EMPTY_DECRYPTED)
        # eCapture did not start on the phone
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, meta=dict(META, decrypt="none", unavailable=["ecapture"], missing=[]),
                           files=("poll.txt",))
            with Harness(tls=TLS) as h:
                r = analyze.analyze(run, Path(tmp) / "o")
        self.assertEqual(h.tls.calls, [])
        self.assertIn(analyze.UNAVAILABLE_ZH["ecapture"], r["limits"])
        self.assertFalse(any("tls_events.log" in x for x in r["limits"]))

    def test_source_without_exchanges(self):
        tls = dict(TLS, exchanges=[], undecoded={"records": 0, "bytes": 0, "reasons": {}})
        run, h, r = self.run_with(tls=tls)
        d = r["decrypted"]
        self.assertEqual((d["sources"], d["exchanges"], d["hosts"]), ([], [], []))
        self.assertTrue(r["captured"]["decrypted"])
        self.assertEqual(d["not_covered"], [{"host": "cdn.example.com", "bytes": 7300},
                                            {"host": "api.example.com", "bytes": 1030}])
        info = [x["text"] for x in r["highlights"]]
        self.assertIn("进行了解密（eCapture），但没有解密到任何请求。", info)
        self.assertFalse(any("没有归入任何请求" in x for x in r["limits"]))

    def test_requests_of_unknown_host(self):
        # fixtures/live_xhs_tls_0120 with the real parse_tls: 27 of 33 requests have no host (their
        # :authority came from an HPACK table whose start was not captured). They may have gone to the
        # hosts in not_covered, so those are not said to have no decrypted request without that caveat.
        tls = dict(TLS, exchanges=[xchg(T("21.100"), None, "/x", "POST", partial=["hpack_state_unknown"]),
                                   xchg(T("22.000"), "api.example.com")],
                   undecoded={"records": 5, "bytes": 90, "reasons": {"h2_control": 3, "connection_closed": 2}})
        run, h, r = self.run_with(tls=tls)
        d = r["decrypted"]
        self.assertEqual(d["not_covered"], [{"host": "cdn.example.com", "bytes": 7300}])
        text = " ".join(x["text"] for x in r["highlights"])
        self.assertIn("解密了 2 个 HTTPS 请求（eCapture 2 个），其中 1 个发往 1 个域名，1 个不知道发往哪个域名"
                      "（连接的开头没有记录到，部分请求头无法还原）；请求最多的域名是 api.example.com。", text)
        # without a connection_host_tail nothing tells where it went: no host is named as possible
        self.assertIn("应用连接的 1 个域名，解密到的请求中没有一个能确定是发往它们的：cdn.example.com。"
                      "应用另有 1 个服务器只有 IP 地址（抓包约 10 字节），不知道解密到的请求里有没有发往它们的。"
                      "解密到的请求中有 1 个不知道发往哪个域名。"
                      "没有解密到内容时，通常的原因是应用用自己的网络库收发", text)
        self.assertIn({"time": T("21.100"), "kind": "decrypted", "text": "解密到 1 个不知道域名的请求（POST 1）"},
                      r["timeline"])
        # parse_tls's own reason codes are worded in Chinese
        self.assertIn("eCapture 的记录中有 5 条没有归入任何请求：HTTP/2 控制帧（连接设置、心跳、流量控制等，"
                      "不含请求内容） 3 条、连接关闭（没有内容的记录） 2 条；不属于任何请求的内容共 90 字节", r["limits"])

    def test_possible_hosts_of_requests_without_host(self):
        # A request without host read on an OkHttp reader thread carries the thread name's host part
        # (connection_host_tail). Only uncovered hosts with TLS traffic that end with it are named.
        endpoints = copy.deepcopy(ENDPOINTS) + [
            {"proto": "tcp", "ip": "5.6.7.9", "port": 80, "host": "static.example.com", "host_source": "dns",
             "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 50, "bytes_in": 60, "plaintext": None},
            {"proto": "tcp", "ip": "5.6.7.9", "port": 443, "host": "static.example.com", "host_source": "dns",
             "first_seen": T("06"), "last_seen": T("07"), "bytes_out": 0, "bytes_in": 0, "plaintext": None},
            {"proto": "tcp", "ip": "5.6.7.10", "port": 443, "host": "pay.example.org", "host_source": "sni",
             "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 40, "bytes_in": 40, "plaintext": None}]
        late = ["hpack_state_unknown", "connection_start_not_captured"]
        tailed = xchg(T("21.100"), None, "/x", "POST", partial=late + ["body_not_decoded"],
                      req_body=make_body(b"\x00\x01\x02", None, None, encoding_known=False))
        tailed["connection_host_tail"] = "Example.com"
        tls = dict(TLS, exchanges=[tailed, xchg(T("21.500"), None, "/y", partial=late),
                                   xchg(T("22.000"), "api.example.com", partial=["connection_start_not_captured"])],
                   undecoded={"records": 0, "bytes": 0, "reasons": {}})
        run, h, r = self.run_with(tls=tls, attributed=endpoints)
        d = r["decrypted"]
        self.assertEqual([n["host"] for n in d["not_covered"]], ["cdn.example.com", "static.example.com",
                                                                  "pay.example.org"])
        coverage = [x["text"] for x in r["highlights"] if x["text"].startswith("应用连接的 3 个域名")]
        self.assertEqual(len(coverage), 1)
        # static.example.com ends with the tail but had no TLS traffic (port 80; port 443 without bytes)
        self.assertIn("解密到的请求中有 2 个不知道发往哪个域名；其中有的请求所在连接的服务器名以 example.com 结尾，"
                      "可能有发往 cdn.example.com 的。", coverage[0])
        lim = r["limits"]
        self.assertIn("解密到的请求中有 3 个所在的 HTTP/2 连接，开头不在记录里（连接在 eCapture 开始之前就已建立时会这样）："
                      "记录没有连接标识，这些请求和响应是按流编号和先后顺序对上的，从同一连接上更早的请求还原的头部字段也基于"
                      "这个推断。要避免这种情况：先在手机上彻底停止这个应用，再开始采集，看到开始采集的提示后再打开应用", lim)
        # the code has its own line: the line of other open codes does not count it
        self.assertIn("解密到的 3 个请求中有 2 个不完整或不确定（连接的开头没有记录到，部分请求头无法还原：2 个）："
                      "报告里只列出确定的部分，每个请求下注明了原因", lim)
        self.assertIn("有 1 个正文没有解码（压缩方式不明的 1 个）：压缩方式不明：头部里的压缩方式（Content-Encoding）没能还原，"
                      "内容既不是文本，也不是校验通过的 gzip 数据，可能经过了别的压缩；这些正文不显示解码后的内容，"
                      "报告只给出类型和大小（加 --show-secrets 时，有字节的还给出 sha256 和开头字节的十六进制）", lim)
        self.assertIn("connection_start_not_captured", analyze.PARTIAL_ZH)


def conn(i, server, sni=None, handshake=True, decrypted=False, protocol=None, exchanges=0, client=None):
    """A synthetic CONNECTION record of parse_keylog (docs/CONTRACT_KEYLOG.md); addresses from the
    documentation ranges."""
    return {"id": i, "time": T("10.000"), "client": client or f"10.0.0.2:{40000 + i}", "server": server, "sni": sni,
            "alpn": protocol if decrypted else None, "tls": "1.3" if handshake else None,
            "handshake_seen": handshake, "decrypted": decrypted, "sent": 100 if decrypted else 0,
            "received": 900 if decrypted else 0, "protocol": protocol, "exchanges": exchanges}


def kxchg(time, conn_id, server, host, path="/a", method="GET", partial=()):
    """A synthetic key-route exchange: the record of docs/CONTRACT_DECRYPT.md with the keylog keys."""
    x = xchg(time, host, path, method, source="keylog", partial=partial)
    x.update(connection=conn_id, server=server, connection_host_tail=None)
    return x


K_ENDPOINTS = [
    {"proto": "tcp", "ip": "192.0.2.1", "port": 443, "host": "api.example.com", "host_source": "sni",
     "first_seen": T("10"), "last_seen": T("29"), "bytes_out": 500, "bytes_in": 5000, "plaintext": None},
    # the same name on another address: no decrypted exchange travelled to it
    {"proto": "tcp", "ip": "192.0.2.5", "port": 443, "host": "api.example.com", "host_source": "sni",
     "first_seen": T("12"), "last_seen": T("13"), "bytes_out": 10, "bytes_in": 20, "plaintext": None},
    {"proto": "tcp", "ip": "192.0.2.2", "port": 443, "host": "cdn.example.com", "host_source": "dns",
     "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 300, "bytes_in": 7000, "plaintext": None},
    {"proto": "tcp", "ip": "2001:db8::3", "port": 443, "host": None, "host_source": None,
     "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 40, "bytes_in": 40, "plaintext": None},
    {"proto": "udp", "ip": "192.0.2.4", "port": 443, "host": "quic.example.com", "host_source": "dns",
     "first_seen": T("06"), "last_seen": T("29"), "bytes_out": 1000, "bytes_in": 2072, "plaintext": None},
]
# the app's local addresses the poll saw on each socket (parse_poll "locals")
K_LOCALS = [["10.0.0.2:40001", "10.0.0.2:40002"], ["10.0.0.2:40007"], ["10.0.0.2:40003"], ["[2001:db8::2]:40004"],
            ["10.0.0.2:5000"]]
K_SOCKETS = [{"proto": e["proto"], "ip": e["ip"], "port": e["port"], "first_seen": e["first_seen"],
              "last_seen": e["last_seen"], "locals": locs} for e, locs in zip(K_ENDPOINTS, K_LOCALS)]
KEYLOG = {
    "tshark": "TShark (Wireshark) 4.6.10.", "keys": {"sessions": 3, "tls13": 2, "tls12": 1},
    "connections": [
        conn(1, "192.0.2.1:443", "api.example.com", decrypted=True, protocol="h2", exchanges=2),
        conn(2, "192.0.2.1:443", "api.example.com"),                  # handshake, no key
        conn(3, "192.0.2.2:443", handshake=False),                    # open before the capture
        conn(4, "[2001:db8::3]:443", handshake=False, client="[2001:db8::2]:40004"),   # known only by address
        conn(5, "192.0.2.9:443", "push.example.com", decrypted=True),   # decrypted, not HTTP; no poll socket
        conn(6, "198.51.100.7:443", "other.example.net"),             # another app's server
        conn(7, "192.0.2.5:443", "api.example.com"),
        # to one of the app's servers, but from a local port the poll never saw on the app's sockets: another
        # app on a shared address, or a connection too short for the poll; not counted
        conn(8, "192.0.2.1:443", "video.example.org"),
    ],
    "exchanges": [kxchg(T("21.100"), 1, "192.0.2.1:443", "api.example.com"),
                  kxchg(T("21.900"), 1, "192.0.2.1:443", "api.example.com", "/b", "POST",
                        partial=["response_incomplete"])],
    "undecoded": {"bytes": 300, "reasons": {"not_http": 280, "h2_control": 20}},
}


class AnalyzeKeylog(unittest.TestCase):
    """The key route (docs/CONTRACT_KEYLOG.md) with hand-built parse_keylog records."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_with(self, files=("poll.txt", "net.pcap", "tls_keys.log", "tls_events.log"), meta=None, sockets=K_SOCKETS,
                 **harness):
        run = make_run(self.tmp.name, meta=meta or dict(META, decrypt="ecapture", missing=[]), files=files)
        harness.setdefault("attributed", copy.deepcopy(K_ENDPOINTS))
        harness.setdefault("keylog", KEYLOG)
        with Harness(poll=dict(POLL, sockets=sockets), tls=TLS, **harness) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        return run, h, r

    def test_key_route(self):
        # meta says "ecapture" and tls_events.log is there (fixtures/live_xhs_keylog_1119): the keys decide
        run, h, r = self.run_with()
        self.assertEqual(h.keylog.calls, [(run / "net.pcap", (run / "tls_keys.log",), {"utc_offset": "-0500"})])
        self.assertEqual(h.tls.calls, [])
        self.assertTrue(r["captured"]["decrypted"])
        d = r["decrypted"]
        self.assertEqual((d["sources"], d["ecapture"], d["keylog_error"]), (["keylog"], None, None))
        kl = d["keylog"]
        self.assertEqual((kl["tshark"], kl["keys"], kl["undecoded"]), (KEYLOG["tshark"], KEYLOG["keys"], KEYLOG["undecoded"]))
        self.assertEqual(kl["connections"], KEYLOG["connections"])
        self.assertEqual(kl["coverage"], {
            "sockets": True,
            "decrypted": {"connections": 2, "ids": [1, 5], "not_http": 1,
                          "hosts": [["api.example.com", 1], ["push.example.com", 1]]},
            "before_capture": {"connections": 2, "ids": [3, 4], "hosts": [["cdn.example.com", 1], [None, 1]]},
            "no_key": {"connections": 2, "ids": [2, 7], "hosts": [["api.example.com", 2]]},
            "key_no_content": {"connections": 0, "ids": [], "hosts": []}})
        self.assertEqual([(x["id"], x["source"], x["connection"], x["server"]) for x in d["exchanges"]],
                         [(1, "keylog", 1, "192.0.2.1:443"), (2, "keylog", 1, "192.0.2.1:443")])
        self.assertEqual(d["hosts"][0]["sources"], ["keylog"])
        # plaintext by the connection's server address, not by host name (192.0.2.5 is api.example.com too)
        self.assertEqual([e["plaintext"] for e in r["network"]["endpoints"]],
                         [{"exchanges": 2, "ids": [1, 2]}, None, None, None, None])

        info = [x["text"] for x in r["highlights"]]
        self.assertIn("解密了 2 个 HTTPS 请求（密钥解密 2 个），发往 1 个域名；请求最多的域名是 api.example.com。", info)
        self.assertIn("抓包里有应用的 6 个加密连接（HTTPS 用的就是这种连接）：2 个解开了（如 api.example.com、push.example.com），"
                      "看得到内容，其中 1 个的内容不是 HTTP 请求，只统计了数据量；2 个在采集开始前就已建立（如 cdn.example.com），"
                      "抓包里没有建立连接时的握手，也就没有密钥，解不开；2 个是采集期间建立的（如 api.example.com），但没有记录到"
                      "密钥，解不开：通常是因为应用用了自己带的加密库（例如 Cronet），eCapture 只记录系统加密库的密钥，也可能是 "
                      "eCapture 漏记了这次握手。", info)
        self.assertFalse(any("docs/MITM.md" in t for t in info))     # the host-name coverage text is not used

        self.assertIn({"time": T("21.100"), "kind": "decrypted", "text": "解密到发往 api.example.com 的 2 个请求（GET 1、POST 1）"},
                      r["timeline"])
        self.assertIn("解密到发往 api.example.com 的 2 个请求（GET 1、POST 1）",
                      [e["what"] for e in r["background"]["events_not_top"]])      # the app's own: 10:00:21, not in front
        lim = r["limits"]
        self.assertIn(analyze.KEYLOG_SCOPE_ZH, lim)
        for text in ("采集开始前就已建立", "自带的加密库", "QUIC", "tcpdump 没有抓到的数据包"):
            self.assertIn(text, analyze.KEYLOG_SCOPE_ZH)
        self.assertIn("应用有 2 个加密连接在采集开始前就已建立，没有密钥，内容看不到。要避免这种情况：先在手机上彻底停止这个应用，"
                      "再开始采集，看到开始采集的提示后再打开应用（开始采集时应用已经在运行，run --decrypt 会提醒）", lim)
        self.assertIn("没有解开的加密连接，只算了轮询时看到属于这个应用的：轮询每 1–2 秒查看一次，很快就结束的连接可能没有算进去",
                      lim)
        self.assertIn("应用有 1 个 UDP 443 端口的连接（QUIC，HTTP/3 用的就是它，抓包约 3 KB）：密钥解密不包括这种连接，内容看不到", lim)
        self.assertIn("解开的内容中有 300 字节不属于任何请求：不是能识别的 HTTP 内容 280 字节、HTTP/2 控制帧（连接设置、心跳、"
                      "流量控制等，不含请求内容） 20 字节", lim)
        self.assertIn("解密到的 2 个请求中有 1 个不完整或不确定（响应不完整：1 个）：报告里只列出确定的部分，每个请求下注明了原因", lim)
        self.assertFalse(any("tls_events.log" in x or x == analyze.ECAPTURE_SCOPE_ZH for x in lim))
        saved = json.loads((Path(self.tmp.name) / "o" / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["decrypted"], json.loads(json.dumps(d)))

    def test_without_socket_lines(self):
        # without the app's sockets only the decrypted connections are known to be the app's
        run, h, r = self.run_with(sockets=[])
        cov = r["decrypted"]["keylog"]["coverage"]
        self.assertEqual((cov["sockets"], cov["decrypted"]["ids"], cov["before_capture"]["ids"], cov["no_key"]["ids"]),
                         (False, [1, 5], [], []))
        self.assertIn("解开了应用的 2 个加密连接（如 api.example.com、push.example.com），其中 1 个的内容不是 HTTP 请求，"
                      "只统计了数据量。轮询没有记录应用的网络连接，抓包里其他没有解开的加密连接哪些属于这个应用，无法判断。",
                      [x["text"] for x in r["highlights"]])

    def test_tshark_failing_is_a_limit(self):
        def failing(pcap, keys, utc_offset="+0000", tshark=None):
            raise KeylogError("找不到 tshark：请安装 Wireshark。")

        run, h, r = self.run_with(keylog=failing)
        self.assertEqual(h.tls.calls, [])                     # no fall-back to tls_events.log
        d = r["decrypted"]
        self.assertEqual((d["keylog"], d["keylog_error"], d["sources"]), (None, "找不到 tshark：请安装 Wireshark。", []))
        self.assertFalse(r["captured"]["decrypted"])
        self.assertIn("没能用密钥解密抓包（找不到 tshark：请安装 Wireshark）：本次没有密钥解密的内容", r["limits"])
        self.assertIn("有加密连接的密钥记录（tls_keys.log），但没能用它解密抓包：找不到 tshark：请安装 Wireshark。",
                      [x["text"] for x in r["highlights"]])
        self.assertTrue(all(e["plaintext"] is None for e in r["network"]["endpoints"]))
        self.assertTrue(r["files"] and r["processes"]["procs"])          # the rest of the result is there

    def test_keys_without_capture_and_capture_without_keys(self):
        run, h, r = self.run_with(files=("poll.txt", "tls_keys.log"))
        self.assertEqual(h.keylog.calls, [])
        self.assertEqual(r["decrypted"]["keylog_error"], "没有抓包文件 net.pcap")
        self.assertIn("没能用密钥解密抓包（没有抓包文件 net.pcap）：本次没有密钥解密的内容", r["limits"])
        with tempfile.TemporaryDirectory() as tmp:
            run = make_run(tmp, meta=dict(META, decrypt="keylog", missing=[]), files=("poll.txt", "net.pcap"))
            with Harness(keylog=KEYLOG, tls=TLS) as h:
                r = analyze.analyze(run, Path(tmp) / "o")
        self.assertEqual((h.keylog.calls, h.tls.calls), ([], []))
        self.assertIn("未采集到 tls_keys.log：没有密钥解密的内容", r["limits"])
        self.assertEqual(r["decrypted"]["keylog"], None)


def cxchg(time, conn_id, host, path="/a", query=()):
    """A synthetic cleartext exchange (parse_keylog.parse_cleartext)."""
    x = kxchg(time, conn_id, "192.0.2.8:80", host, path)
    x.update(source="cleartext", scheme="http", protocol="http/1.1", query=[list(q) for q in query])
    return x


C_SOCKETS = K_SOCKETS + [{"proto": "tcp", "ip": "192.0.2.8", "port": 80, "first_seen": T("10"), "last_seen": T("29"),
                          "locals": ["10.0.0.2:40100"]}]
CLEARTEXT = {
    "tshark": "TShark (Wireshark) 4.6.10.",
    "connections": [{"id": 30, "time": T("21.000"), "client": "10.0.0.2:40100", "server": "192.0.2.8:80",
                     "began_in_capture": True, "sent": 50, "received": 20, "protocol": "http/1.1", "exchanges": 1},
                    # to the same server from a local port the poll never saw on the app's sockets: not the app's
                    {"id": 31, "time": T("21.500"), "client": "10.0.0.2:40999", "server": "192.0.2.8:80",
                     "began_in_capture": True, "sent": 50, "received": 20, "protocol": "http/1.1", "exchanges": 1}],
    "exchanges": [cxchg(T("22.000"), 30, "ads.example.com", "/collect", [("deviceId", "d3v1c3-secret-0001")]),
                  cxchg(T("23.000"), 31, "other.example", "/b")],
    "undecoded": {"bytes": 0, "reasons": {}},
}


class AnalyzeCleartext(unittest.TestCase):
    """Cleartext HTTP (parse_cleartext, or the key route's "cleartext"): the app's by its sockets."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_with(self, files=("poll.txt", "net.pcap"), sockets=C_SOCKETS, **harness):
        run = make_run(self.tmp.name, meta=dict(META, missing=[]), files=files)
        harness.setdefault("attributed", copy.deepcopy(K_ENDPOINTS))
        with Harness(poll=dict(POLL, sockets=sockets), **harness) as h:
            r = analyze.analyze(run, Path(self.tmp.name) / "o")
        return run, h, r

    def test_server_known_by_address_only(self):
        # the highlight has no space before the Chinese words that stand for the server
        by_address = copy.deepcopy(CLEARTEXT)
        by_address["exchanges"][0]["host"] = "192.0.2.8"
        run, h, r = self.run_with(cleartext=by_address)
        notable = [x["text"] for x in r["highlights"] if x["level"] == "notable"]
        self.assertTrue(any("都能看到内容：发往只知道地址的服务器（1 个）；" in x for x in notable), notable)

    def test_without_keys(self):
        run, h, r = self.run_with(cleartext=CLEARTEXT)
        self.assertEqual((h.cleartext.calls, h.keylog.calls), ([(run / "net.pcap", (), {"utc_offset": "-0500"})], []))
        c = r["cleartext"]
        self.assertEqual((c["checked"], c["error"], c["attributed"], c["others"]),
                         (True, None, True, {"connections": 1, "requests": 1}))
        self.assertEqual([(x["id"], x["source"], x["host"], x["path"]) for x in c["exchanges"]],
                         [(1, "cleartext", "ads.example.com", "/collect")])
        self.assertEqual([x["id"] for x in c["connections"]], [30])
        self.assertTrue(r["captured"]["cleartext"])
        self.assertFalse(r["captured"]["decrypted"])
        self.assertEqual(r["decrypted"]["exchanges"], [])
        self.assertIn({"time": T("22.000"), "kind": "cleartext", "text": "没加密发往 ads.example.com 的 1 个请求（GET 1）"},
                      r["timeline"])
        notable = [x["text"] for x in r["highlights"] if x["level"] == "notable"]
        self.assertIn("有 1 个请求没加密就发了出去（明文 HTTP），同一网络里的其他人和网络运营商都能看到内容："
                      "发往 ads.example.com（1 个）；按字段名看，带了设备标识类的字段。", notable)
        self.assertTrue(any(x.startswith("没加密的 HTTP 请求是直接从抓包里读出来的") for x in r["limits"]))

        ov = overview.from_app_result(r, run)
        self.assertFalse(ov["run"]["decrypt"])
        # at 10:00:22 another app is in front
        self.assertEqual(ov["cleartext"]["apps"], [{"package": PKG, "label": None, "requests": 1, "background": 1,
                                                     "hosts": [["ads.example.com", 1]], "kinds": ["设备标识"]}])
        sent = next(b for b in ov["apps"][0]["bars"] if b["key"] == "sent_data")
        self.assertEqual((sent["count"], sent["cleartext"]), (1, 1))
        self.assertIn("这次没有解密，看不到它加密发出去的具体内容。", ov["limits"])
        self.assertNotIn("d3v1c3-secret-0001", json.dumps(ov, ensure_ascii=False))

        page = report.render(r)
        self.assertIn('<section id="cleartext"', page)
        self.assertLess(page.index('id="network"'), page.index('id="cleartext"'))
        self.assertLess(page.index('id="cleartext"'), page.index('id="decrypted"'))
        self.assertIn("没加密，直接从抓包读出 · http/1.1 · http", page)
        self.assertNotIn("d3v1c3-secret-0001", page)
        self.assertIn("d3v1c3-secret-0001", report.render(r, show_secrets=True))

    def test_report_notes_and_older_results(self):
        run, h, r = self.run_with(cleartext=CLEARTEXT)
        page = report.render(r)
        self.assertIn("没加密的请求的内容在“没加密的请求”一节。", page)
        self.assertNotIn("没有记录传输的内容", page)
        old = {k: v for k, v in r.items() if k != "cleartext"}          # a result made before the check
        page = report.render(old)
        self.assertIn('<section id="cleartext"', page)
        self.assertIn("那时还不检查没加密的请求", page)

    def test_capture_parse_net_cannot_read(self):
        def bad_pcap(path):
            raise ValueError("not a classic pcap file")
        run = make_run(self.tmp.name, meta=dict(META, missing=[]), files=("poll.txt", "net.pcap"))
        with Harness(poll=dict(POLL, sockets=C_SOCKETS), cleartext=CLEARTEXT) as h:
            with mock.patch.object(analyze, "parse_net", SimpleNamespace(parse_pcap=bad_pcap, attribute=h.attribute,
                                                                         hosts_unattributed=h.unattributed)):
                r = analyze.analyze(run, Path(self.tmp.name) / "o")
        self.assertEqual(len(h.cleartext.calls), 1)          # tshark may read what parse_net cannot
        self.assertEqual([x["path"] for x in r["cleartext"]["exchanges"]], ["/collect"])

    def test_with_the_key_route(self):
        run, h, r = self.run_with(files=("poll.txt", "net.pcap", "tls_keys.log"),
                                  keylog=dict(KEYLOG, cleartext=CLEARTEXT))
        self.assertEqual(h.cleartext.calls, [])          # read by the key route's tshark run
        self.assertEqual([x["id"] for x in r["decrypted"]["exchanges"]], [1, 2])
        self.assertEqual([x["id"] for x in r["cleartext"]["exchanges"]], [3])
        # the cleartext connections are not counted as encrypted ones
        self.assertNotIn(30, [i for g in ("decrypted", "before_capture", "no_key")
                              for i in r["decrypted"]["keylog"]["coverage"][g]["ids"]])

    def test_without_the_apps_sockets(self):
        run, h, r = self.run_with(cleartext=CLEARTEXT, sockets=[])
        self.assertEqual((r["cleartext"]["attributed"], r["cleartext"]["exchanges"]), (False, []))
        self.assertIn("轮询没有看到应用的连接：抓包里没加密的 HTTP 请求对不上它，没有列出", r["limits"])

    def test_tshark_missing(self):
        def failing(pcap, utc_offset="+0000", tshark=None):
            raise KeylogError("找不到 tshark：请安装 Wireshark。")

        run, h, r = self.run_with(cleartext=failing)
        self.assertEqual((r["cleartext"]["checked"], r["cleartext"]["error"]), (False, "找不到 tshark：请安装 Wireshark。"))
        self.assertFalse(r["captured"]["cleartext"])
        self.assertIn("没能检查应用有没有没加密就发出去的请求（找不到 tshark：请安装 Wireshark）", r["limits"])
        self.assertIn("没能检查它有没有没加密就发出去的请求：找不到 tshark：请安装 Wireshark。", report.render(r))
        ov = overview.from_app_result(r, run)
        self.assertEqual((ov["cleartext"]["checked"], ov["cleartext"]["note"]), (False, "找不到 tshark：请安装 Wireshark。"))


class Matching(unittest.TestCase):
    """A dump entry or logcat line is the same occurrence as the nearest poll occurrence only."""

    def front(self):
        return analyze._Front({"cpu": [{"time": T("00"), "ticks": 0, "target_top": True}]})

    def test_dump_entry_replaces_one_poll_occurrence(self):
        dumps = [{"op": "GET_USAGE_STATS", "kind": "reject", "state": "top", "time": T("14.900"), "duration_ms": None}]
        polls = {"GET_USAGE_STATS": {"mode": "default", "events": [
            {"kind": "reject", "time": T("10"), "target_top": True},
            {"kind": "reject", "time": T("15"), "target_top": True}]}}
        with mock.patch.object(analyze, "parse_appops", SimpleNamespace(op_info=lambda op: {"zh": op})):
            used, occ = analyze._permissions(dumps, polls, self.front())
        self.assertEqual(used[0]["count"], 2)
        self.assertEqual([o["time"] for o in occ], [T("10"), T("14.900")])

    def test_logcat_line_explains_one_poll_occurrence(self):
        log = [{"time": T("34.386"), "op": "read", "result": "blocked", "raw": "a"},
               {"time": T("34.387"), "op": "read", "result": "unknown", "raw": "b"}]
        occ = [{"op": "READ_CLIPBOARD", "kind": "reject", "time": T("29.500"), "background": False},
               {"op": "READ_CLIPBOARD", "kind": "reject", "time": T("34"), "background": False}]
        c = analyze._clipboard(log, occ, self.front())
        self.assertEqual((c["reads"], c["blocked"]), (3, 3))
        self.assertEqual([(e["time"], e["source"]) for e in c["events"]],
                         [(T("29.500"), "appops"), (T("34.386"), "logcat"), (T("34.387"), "logcat")])


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_REAL_PARSERS = all(hasattr(getattr(analyze, m), f) for m, f in (
    ("parse_poll", "parse_poll"), ("parse_logcat", "parse_logcat"), ("parse_appops", "diff_appops"),
    ("parse_filetrace", "parse_f2fs_trace"), ("parse_net", "parse_pcap")))


@unittest.skipUnless(_REAL_PARSERS and (FIXTURES / "xhs_1004").is_dir(), "real parsers or fixtures not available")
class Fixtures(unittest.TestCase):
    """analyze with the real parsers on the real captures."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.r = {name: analyze.analyze(FIXTURES / name, Path(cls.tmp.name) / name)
                 for name in ("xhs_1004", "live_aweme_2118")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_xhs_app_process_pids(self):
        r = self.r["xhs_1004"]
        # Seen only in logcat (`START com.android.internal.os.RuntimeInit uid 10378`), not in poll.
        self.assertLessEqual({1908, 2748, 2777, 3009, 3092, 3337}, {p["pid"] for p in r["files"]["by_process"]})
        self.assertEqual({p["pid"] for p in r["processes"]["procs"] if p["started_by"] == "app"},
                         {1604, 1908, 2748, 2777, 2828, 3009, 3092, 3158, 3337})
        self.assertEqual(len(r["files"]["other_app_apks"]), 121)
        procs = [h["text"] for h in r["highlights"] if h["text"].startswith("不在前台时新出现了")]
        self.assertEqual(len(procs), 1)
        self.assertTrue(procs[0].startswith("不在前台时新出现了 7 个应用进程"), procs[0])
        self.assertIn("6 个是应用自己通过 app_process 启动的（pid 2777、2828、3009、3092、3158、3337，"
                      "10:04:36 至 10:04:38）", procs[0])
        # am_proc_start names the app's own uid as the sender of the broadcast that started 2864
        self.assertIn("com.xingin.xhs:widgetProvider（pid 2864，10:04:36，系统启动，原因：应用自己（uid 10378）发起的广播",
                      procs[0])

    def test_xhs_cpu_and_clipboard(self):
        r = self.r["xhs_1004"]
        self.assertEqual(r["background"]["cpu_ticks_not_top"], 488)
        # 10:04:29 from the poll only; 10:04:34 is one access logged as two checks (.386, .387)
        self.assertEqual((r["clipboard"]["reads"], r["clipboard"]["blocked"]), (2, 2))

    def test_xhs_hosts_and_limits(self):
        r = self.r["xhs_1004"]
        rows = r["network"]["hosts_unattributed"]
        names = {h["host"] for h in rows if h["host_source"]}
        ips = {h["host"] for h in rows if not h["host_source"]}
        self.assertTrue(ips)
        text = [h["text"] for h in r["highlights"] if h["text"].startswith("全系统抓包")][0]
        self.assertIn(f"出现了 {len(names)} 个域名", text)
        self.assertIn(f"另有 {len(ips)} 个只有 IP 地址的服务器", text)
        self.assertFalse(any(" lines " in x or "marker" in x or "timestamps" in x for x in r["limits"]))

    def test_aweme_front_time_and_dump_counts(self):
        r = self.r["live_aweme_2118"]
        b = r["background"]
        self.assertLessEqual(b["seconds_top"] + b["seconds_not_top"], r["meta"]["duration_s"])
        # The appops dump entries are occurrences the poll saw too: adding the dump keeps the count.
        poll = analyze.parse_poll.parse_poll(FIXTURES / "live_aweme_2118" / "poll.txt", r["meta"]["package"])
        both = [u for u in r["permissions"]["used"] if u["source"] == "both"]
        self.assertTrue(both)
        for u in both:
            n = sum(e["kind"] == u["kind"] for e in poll["ops"][u["op"]]["events"])
            self.assertEqual(u["count"], n, u["op"])


class PackageDump(unittest.TestCase):
    def test_runtime_granted_of_the_package_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "package_dump.txt"
            p.write_text(PACKAGE_DUMP, encoding="utf-8")
            self.assertEqual(analyze._parse_granted(p, PKG),
                             ["android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA"])


class FakeDeviceError(Exception):
    pass


class FakeCaptureLeft(FakeDeviceError):
    pass


PHONE_META = {**META, "scope": "phone", "package": None, "uid": None, "app_id": None, "version_name": None}


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        from aw import collect as real
        self.collect = SimpleNamespace(
            check_package_name=mock.Mock(), CaptureLeft=FakeCaptureLeft,
            MAX_CAPTURE_S=real.MAX_CAPTURE_S, STOP_MARGIN_S=real.STOP_MARGIN_S,
            UNAVAILABLE_ZH=real.UNAVAILABLE_ZH, AUTOSTOP_ZH=real.AUTOSTOP_ZH,
            list_packages=mock.Mock(return_value=[
                {"package": "com.b", "uid": 10002, "apk": "/data/app/b/base.apk", "third_party": True},
                {"package": "android", "uid": 1000, "apk": "/system/framework/framework-res.apk", "third_party": False},
                {"package": "com.a", "uid": 10001, "apk": "/data/app/a/base.apk", "third_party": True},
                {"package": "org.x", "uid": 10003, "apk": "/data/app/x/base.apk", "third_party": True}]),
            start=mock.Mock(return_value={"version_name": "1.0", "uid": 10378, "unavailable": []}),
            stop=mock.Mock(return_value={}), pending=mock.Mock(return_value=None), fetch=mock.Mock(return_value={}))
        self.device = SimpleNamespace(DeviceError=FakeDeviceError, Device=mock.Mock(),
                                      find_tshark=mock.Mock(return_value="/opt/wireshark/tshark"),
                                      find_ecapture=mock.Mock(return_value="/opt/ecapture"),
                                      BUNDLED_ECAPTURE="/opt/ecapture-tools/ecapture")
        self.report = SimpleNamespace(render=mock.Mock(return_value="<html>ok</html>"))
        self.analyze_fn = mock.Mock(return_value={"meta": {}})
        # aw.overview, aw.phonewide and aw.ui (other owners' modules) as their interfaces in docs/CONTRACT_PHONE.md
        self.overview = SimpleNamespace(write_app_run=mock.Mock(return_value={"format": 1}),
                                        cleartext_lines=mock.Mock(return_value=[]))
        self.phonewide = SimpleNamespace(analyze_phone=mock.Mock(return_value={"format": 1}))
        self.ui = SimpleNamespace(serve=mock.Mock(return_value=0))
        for target, attr, value in ((aw, "collect", self.collect), (aw, "report", self.report),
                                    (analyze, "analyze", self.analyze_fn), (aw, "overview", self.overview),
                                    (aw, "phonewide", self.phonewide), (aw, "ui", self.ui)):
            p = mock.patch.object(target, attr, value, create=True)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.dict(sys.modules, {"aw.device": self.device, "aw.collect": self.collect,
                                          "aw.report": self.report, "aw.overview": self.overview,
                                          "aw.phonewide": self.phonewide, "aw.ui": self.ui})
        p.start()
        self.addCleanup(p.stop)

    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = stakeout.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_analyze_without_meta(self):
        code, out, err = self.call("analyze", self.tmp.name)
        self.assertEqual(code, 1)
        self.assertIn("没有 meta.json", err)
        self.analyze_fn.assert_not_called()

    def test_analyze_writes_report_to_out(self):
        run = make_run(self.tmp.name, files=())
        out_dir = Path(self.tmp.name) / "report"
        # the overview and the app's downloads are written after the report (write_app_run copies it)
        self.overview.write_app_run.side_effect = lambda result, path: self.assertTrue((path / "report.html").is_file())
        code, out, err = self.call("analyze", str(run), "--out", str(out_dir))
        self.assertEqual(code, 0, err)
        self.analyze_fn.assert_called_once_with(run, out_dir, har=None)
        self.report.render.assert_called_once_with({"meta": {}}, show_secrets=False)
        self.assertEqual((out_dir / "report.html").read_text(encoding="utf-8"), "<html>ok</html>")
        self.assertIn(str(out_dir / "report.html"), out)
        self.overview.write_app_run.assert_called_once_with({"meta": {}}, out_dir)
        self.phonewide.analyze_phone.assert_not_called()

    def test_analyze_phone_run(self):
        run = make_run(self.tmp.name, meta=PHONE_META, files=())
        code, out, err = self.call("analyze", str(run))
        self.assertEqual(code, 0, err)
        self.phonewide.analyze_phone.assert_called_once_with(run, run)
        self.assertEqual(out.strip(), f"概览已生成：{run / 'overview.json'}")
        out_dir = Path(self.tmp.name) / "elsewhere"
        code, out, err = self.call("analyze", str(run), "--out", str(out_dir))
        self.assertEqual(code, 0, err)
        self.phonewide.analyze_phone.assert_called_with(run, out_dir)
        self.assertIn(str(out_dir / "overview.json"), out)
        self.analyze_fn.assert_not_called()                 # no one-app analysis, report or overview
        self.report.render.assert_not_called()
        self.overview.write_app_run.assert_not_called()
        # a HAR file of one's own proxy cannot be given to the apps of a phone run
        har = Path(self.tmp.name) / "phone.har"
        har.write_text("{}", encoding="utf-8")
        code, out, err = self.call("analyze", str(run), "--har", str(har))
        self.assertEqual((code, err.strip()), (1, stakeout.HAR_PHONE_ZH))
        self.assertEqual(self.phonewide.analyze_phone.call_count, 2)

    def test_analyze_run_made_before_scope(self):
        # META has no "scope" (runs made before v0.4): a one-app run
        run = make_run(self.tmp.name, files=())
        code, out, err = self.call("analyze", str(run))
        self.assertEqual(code, 0, err)
        self.analyze_fn.assert_called_once_with(run, run, har=None)
        self.overview.write_app_run.assert_called_once_with({"meta": {}}, run)
        self.phonewide.analyze_phone.assert_not_called()

    def test_run_ctrl_c_still_stops_and_reports(self):
        run_dir = Path(self.tmp.name) / "r1"
        with mock.patch.object(stakeout.time, "sleep", side_effect=KeyboardInterrupt):
            code, out, err = self.call("run", PKG, "--seconds", "30", "--out", str(run_dir), "--no-net")
        self.assertEqual(code, 0, err)
        dev = self.device.Device.return_value
        self.device.Device.assert_called_once_with(serial=None)
        dev.check.assert_called_once_with()
        # the phone stops by itself 300 s after the capture should have ended
        self.collect.start.assert_called_once_with(dev, PKG, net=False, filetrace=True, max_seconds=330,
                                                   decrypt=False)
        self.collect.stop.assert_called_once_with(dev, run_dir)
        self.analyze_fn.assert_called_once_with(run_dir, run_dir, har=None)
        self.assertNotIn("解密", out)
        self.assertTrue((run_dir / "report.html").exists())

    def test_run_all(self):
        self.collect.start.return_value = {"package": None, "uid": None, "app_id": None, "version_name": None,
                                           "unavailable": [], "decrypt": False, "running": None}
        run_dir = Path(self.tmp.name) / "p1"
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", "--all", "--seconds", "30", "--out", str(run_dir))
        self.assertEqual(code, 0, err)
        dev = self.device.Device.return_value
        self.collect.check_package_name.assert_not_called()
        self.collect.start.assert_called_once_with(dev, None, net=True, filetrace=True, max_seconds=330,
                                                   decrypt=False)
        self.collect.stop.assert_called_once_with(dev, run_dir)
        self.assertIn("已开始观察整部手机", out)
        self.assertNotIn("uid", out)
        self.phonewide.analyze_phone.assert_called_once_with(run_dir, run_dir)
        self.assertIn(f"概览已生成：{run_dir / 'overview.json'}", out)
        self.analyze_fn.assert_not_called()
        self.overview.write_app_run.assert_not_called()

        # with decryption: the advice for the whole phone, not the one about a single running app
        self.collect.start.return_value = {**self.collect.start.return_value, "decrypt": True}
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", "--all", "--seconds", "30", "--out", str(Path(self.tmp.name) / "p2"),
                                       "--decrypt")
        self.assertEqual(code, 0, err)
        self.assertIn(stakeout.DECRYPTING_ZH, out)
        self.assertIn(stakeout.PHONE_DECRYPT_ZH, out)
        self.assertNotIn(stakeout.RUNNING_ZH, out)

    def test_run_all_saved_but_phone_not_cleaned(self):
        run_dir = Path(self.tmp.name) / "p3"

        def stop(dev, path):
            (path / "meta.json").write_text(json.dumps(PHONE_META), encoding="utf-8")
            raise FakeDeviceError(f"数据已保存到 {path}，但没能清理手机上的临时文件：x")

        self.collect.stop.side_effect = stop
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", "--all", "--seconds", "5", "--out", str(run_dir))
        self.assertEqual(code, 1)
        self.phonewide.analyze_phone.assert_called_once_with(run_dir, run_dir)
        self.analyze_fn.assert_not_called()

    def test_run_package_or_all(self):
        for argv, expected in ((["run", PKG, "--all"], "--all：不能和 package 一起用"),
                               (["run", "--all", PKG], "package：不能和 --all 一起用"),
                               (["run"], "缺少必填的参数：package --all 中的一个")):
            with self.subTest(argv):
                with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()) as err:
                    stakeout.main(argv)
                self.assertEqual(cm.exception.code, 2)
                self.assertEqual(err.getvalue(), f"参数有误（{expected}），用 -h 查看用法。\n")
        self.device.Device.assert_not_called()

    def test_fetch_phone_run(self):
        self.collect.pending.return_value = {"running": False, "package": None, "scope": "phone"}
        run_dir = Path(self.tmp.name) / "f2"
        code, out, err = self.call("fetch", "--out", str(run_dir))
        self.assertEqual(code, 0, err)
        self.assertIn("正在取回手机上的数据", out)
        self.collect.fetch.assert_called_once_with(self.device.Device.return_value, run_dir)
        self.phonewide.analyze_phone.assert_called_once_with(run_dir, run_dir)
        self.analyze_fn.assert_not_called()

    def test_ui(self):
        code, out, err = self.call("ui")
        self.assertEqual(code, 0, err)
        self.ui.serve.assert_called_once_with(port=8765, open_browser=True)
        code, out, err = self.call("ui", "--port", "9000", "--no-open")
        self.assertEqual(code, 0, err)
        self.ui.serve.assert_called_with(port=9000, open_browser=False)
        self.ui.serve.return_value = 1                      # the port is taken: serve said why
        self.assertEqual(self.call("ui")[0], 1)
        self.device.Device.assert_not_called()

    def test_run_device_error_is_one_sentence(self):
        self.device.Device.return_value.check.side_effect = FakeDeviceError("没有连接手机：请用 USB 连接并允许调试。")
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "r2"))
        self.assertEqual(code, 1)
        self.assertEqual(err.strip(), "没有连接手机：请用 USB 连接并允许调试。")
        self.collect.start.assert_not_called()
        self.collect.stop.assert_not_called()

    def test_run_start_failure_still_stops(self):
        # What the real collect does: start() cleans up and raises, then stop() finds nothing to stop.
        self.collect.start.side_effect = FakeDeviceError("无法在手机上开始采集：already running (run: aw_ctl.sh stop)")
        self.collect.stop.side_effect = FakeDeviceError(
            "手机上没有这次采集的数据：采集还没有真正开始。手机上的临时文件已清理，请重新运行。")
        run_dir = Path(self.tmp.name) / "r3"
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(run_dir))
        self.assertEqual(code, 1)
        self.collect.stop.assert_called_once()
        self.assertEqual(err.strip(), "无法在手机上开始采集：already running (run: aw_ctl.sh stop)")
        self.assertNotIn("正在停止采集并取回数据", out)
        self.assertFalse(run_dir.exists())             # the empty run directory is not left behind
        self.analyze_fn.assert_not_called()

    def test_run_start_failure_keeps_existing_out_dir(self):
        self.collect.start.side_effect = FakeDeviceError("推送脚本失败")
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", self.tmp.name)
        self.assertEqual((code, err.strip()), (1, "推送脚本失败"))
        self.assertTrue(Path(self.tmp.name).is_dir())

    def test_run_stop_failure(self):
        self.collect.stop.side_effect = FakeDeviceError("停止采集失败：x")
        run_dir = Path(self.tmp.name) / "r4"
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(run_dir))
        self.assertEqual((code, err.strip()), (1, "停止采集时出错：停止采集失败：x"))
        self.assertIn("正在停止采集并取回数据", out)
        self.analyze_fn.assert_not_called()
        self.assertFalse(run_dir.exists())          # nothing was saved: no empty run directory left

    def test_run_leaves_an_earlier_capture_alone(self):
        self.collect.start.side_effect = FakeCaptureLeft("手机上还有一次以前的采集……请先运行 python3 stakeout.py fetch")
        run_dir = Path(self.tmp.name) / "r6"
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(run_dir))
        self.assertEqual(code, 1)
        self.assertIn("fetch", err)
        self.collect.stop.assert_not_called()        # stop would stop and take that capture
        self.assertFalse(run_dir.exists())

    def test_run_refuses_a_directory_that_is_not_a_run(self):
        other = Path(self.tmp.name) / "Desktop"
        other.mkdir()
        (other / "logcat.txt").write_text("mine\n")
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(other))
        self.assertEqual(code, 1)
        self.assertIn("不是空目录，也不是 Stakeout 的运行目录", err)
        self.device.Device.assert_not_called()
        self.assertEqual((other / "logcat.txt").read_text(), "mine\n")

    def test_run_says_what_the_phone_lacks_and_that_it_stopped_itself(self):
        self.collect.start.return_value = {"version_name": "1.0", "uid": 10378, "unavailable": ["tcpdump"]}
        self.collect.stop.return_value = {"autostop": "deadline", "end_time": "2026-11-18 11:00:00"}
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "r7"))
        self.assertEqual(code, 0, err)
        self.assertIn("手机上没有 tcpdump 程序，本次不抓包。", out)
        self.assertIn("手机已在 11:00:00 自行停止采集：达到最长采集时间。", out)

    def test_fetch(self):
        code, out, err = self.call("fetch")
        self.assertEqual((code, out.strip()), (0, "手机上没有以前留下的采集。"))
        self.collect.fetch.assert_not_called()
        self.collect.pending.return_value = {"running": True, "package": PKG}
        run_dir = Path(self.tmp.name) / "f1"
        code, out, err = self.call("fetch", "--out", str(run_dir))
        self.assertEqual(code, 0, err)
        self.assertIn("正在停止手机上的采集并取回数据", out)
        self.collect.fetch.assert_called_once_with(self.device.Device.return_value, run_dir)
        self.analyze_fn.assert_called_once_with(run_dir, run_dir, har=None)

    def test_analyze_damaged_meta(self):
        run = Path(self.tmp.name) / "bad"
        run.mkdir()
        for text in ("{not json", json.dumps({"package": PKG})):
            (run / "meta.json").write_text(text, encoding="utf-8")
            code, out, err = self.call("analyze", str(run))
            self.assertEqual(code, 1)
            self.assertIn("meta.json 已损坏或不完整", err)
            self.assertNotIn("Traceback", err)
        self.analyze_fn.assert_not_called()

    def test_run_saved_but_phone_not_cleaned(self):
        run_dir = Path(self.tmp.name) / "r5"

        def stop(dev, path):
            (path / "meta.json").write_text(json.dumps(META), encoding="utf-8")   # saved, then clean failed
            raise FakeDeviceError(f"数据已保存到 {path}，但没能清理手机上的临时文件：x")

        self.collect.stop.side_effect = stop
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(run_dir))
        self.assertEqual(code, 1)
        self.assertIn("停止采集时出错：数据已保存到", err)
        self.analyze_fn.assert_called_once_with(run_dir, run_dir, har=None)
        self.assertIn(str(run_dir / "report.html"), out)

    def test_help_and_errors_are_chinese(self):
        for argv in (["-h"], ["run", "-h"]):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(io.StringIO()) as out:
                stakeout.main(argv)
            self.assertEqual(cm.exception.code, 0)
            text = out.getvalue()
            self.assertTrue(text.startswith("用法：stakeout.py"), text)
            self.assertIn("显示这段说明并退出", text)
            self.assertIn("选项:", text)
            for english in ("usage", "options", "positional arguments", "show this help"):
                self.assertNotIn(english, text)
        # the choices are quoted up to Python 3.12.7 ('run', 'fetch', …) and bare from 3.12.8 (run, fetch, …)
        for argv, expected in ((["foo"], "没有 'foo' 这一项，可以用的是 "),
                               (["run"], "缺少必填的参数：package --all 中的一个"),
                               (["analyze", "a", "b"], "不认识的参数：b"),
                               (["run", PKG, "--seconds"], "--seconds：后面要跟一个值")):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()) as err:
                stakeout.main(argv)
            self.assertEqual(cm.exception.code, 2)
            self.assertIn(expected, err.getvalue())
        self.assertIs(stakeout.argparse._, gettext.gettext)      # put back after parsing

    def test_no_arguments_prints_usage(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(stakeout.main([]), 2)
        self.assertTrue(out.getvalue().startswith("用法：stakeout.py"), out.getvalue())
        self.assertIn("run ", out.getvalue())
        self.assertIs(stakeout.argparse._, gettext.gettext)

    def test_too_old_python(self):
        # an older Python says which one it is and which one is needed, before anything else
        with mock.patch.object(sys, "version_info", (3, 11, 9, "final", 0)):
            code, out, err = self.call("list")
        self.assertEqual(code, 1)
        self.assertIn("需要 Python 3.12 或更新的版本，现在用的是 3.11.9", err)
        self.assertIn(sys.executable, err)
        self.device.Device.assert_not_called()
        # which it can only do while stakeout.py itself reads as an older Python's code
        ast.parse(Path(stakeout.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))

    def test_list(self):
        # user-installed packages only, sorted, filtered by the keyword (any case)
        code, out, err = self.call("list", "COM", "--serial", "abc")
        self.assertEqual(code, 0)
        self.collect.list_packages.assert_called_once_with(self.device.Device.return_value)
        self.device.Device.assert_called_once_with(serial="abc")
        self.assertEqual(out.split(), ["com.a", "com.b"])
        code, out, err = self.call("list")
        self.assertEqual(out.split(), ["com.a", "com.b", "org.x"])
        code, out, err = self.call("list", "android")
        self.assertEqual(out.strip(), "没有找到包名包含“android”的第三方应用。")

    def test_run_decrypt(self):
        self.collect.UNAVAILABLE_ZH = {"ecapture": "手机上的 eCapture 没有启动，本次不解密。"}
        self.collect.start.return_value = {"version_name": "1.0", "uid": 10378, "unavailable": [], "decrypt": True}
        run_dir = Path(self.tmp.name) / "d1"
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(run_dir), "--decrypt",
                                       "--show-secrets")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.collect.start.call_args.kwargs["decrypt"], True)
        self.assertIn(stakeout.DECRYPTING_ZH, out)
        for text in ("记录密钥", "tshark", "采集开始前已建立的连接", "自带的加密库"):
            self.assertIn(text, stakeout.DECRYPTING_ZH)
        self.assertNotIn(stakeout.RUNNING_ZH, out)
        self.assertEqual(self.report.render.call_args.kwargs, {"show_secrets": True})

        # the app already had a process when the capture began: what that costs and what to do
        self.collect.start.return_value = {"version_name": "1.0", "uid": 10378, "unavailable": [], "decrypt": True,
                                           "running": True}
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "d3"),
                                       "--decrypt")
        self.assertEqual(code, 0, err)
        self.assertIn(stakeout.RUNNING_ZH, out)
        for text in ("没有记录到密钥，解不开", "彻底停止这个应用", "再重新开始采集", "后再打开应用"):
            self.assertIn(text, stakeout.RUNNING_ZH)
        # without --decrypt a running app costs nothing that is said here
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "d4"))
        self.assertNotIn(stakeout.RUNNING_ZH, out)

        # eCapture did not start: the phone's reason, said once
        self.collect.start.return_value = {"version_name": "1.0", "uid": 10378, "unavailable": ["ecapture"],
                                           "decrypt": False}
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "d2"),
                                       "--decrypt")
        self.assertEqual(code, 0, err)
        self.assertIn("手机上的 eCapture 没有启动，本次不解密。", out)
        self.assertNotIn("正在解密", out)
        self.assertNotIn("eCapture 没有启动，本次不解密 HTTPS 内容。", out)
        self.assertEqual(self.report.render.call_args.kwargs, {"show_secrets": False})

    def test_run_decrypt_needs_capture_and_tshark(self):
        # both are said before the phone is contacted
        for argv, expected in ((["--no-net"], "--decrypt 要用抓到的数据包来解密，不能和 --no-net 一起用。"),
                               ([], stakeout.TSHARK_MISSING_ZH)):
            self.device.find_tshark.return_value = None
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "k"),
                                       "--decrypt", *argv)
            self.assertEqual((code, err.strip()), (1, expected))
        for text in ("Wireshark", "https://www.wireshark.org", "AW_TSHARK"):
            self.assertIn(text, stakeout.TSHARK_MISSING_ZH)
        # collect.start refuses a missing eCapture binary too, but cmd_run runs stop() on the phone after
        # a failed start: said here first
        self.device.find_tshark.return_value = "/opt/wireshark/tshark"
        self.device.find_ecapture.return_value = None
        code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "k"), "--decrypt")
        self.assertEqual(code, 1)
        self.assertIn("找不到 eCapture 程序", err)
        self.device.Device.assert_not_called()
        self.collect.start.assert_not_called()
        self.assertFalse((Path(self.tmp.name) / "k").exists())
        # without --decrypt tshark is not looked for
        self.device.find_tshark.reset_mock()
        with mock.patch.object(stakeout.time, "sleep"):
            code, out, err = self.call("run", PKG, "--seconds", "5", "--out", str(Path(self.tmp.name) / "k2"), "--no-net")
        self.assertEqual(code, 0, err)
        self.device.find_tshark.assert_not_called()

    def test_analyze_har(self):
        run = make_run(self.tmp.name, files=())
        har = Path(self.tmp.name) / "phone.har"
        code, out, err = self.call("analyze", str(run), "--har", str(har))
        self.assertEqual(code, 1)
        self.assertIn("找不到 HAR 文件", err)
        self.analyze_fn.assert_not_called()

        har.write_text("{}", encoding="utf-8")
        code, out, err = self.call("analyze", str(run), "--har", str(har), "--show-secrets")
        self.assertEqual(code, 0, err)
        self.analyze_fn.assert_called_once_with(run, run, har=har)
        self.report.render.assert_called_once_with({"meta": {}}, show_secrets=True)

        self.analyze_fn.side_effect = ValueError("这个文件不是 HAR 格式。")
        code, out, err = self.call("analyze", str(run), "--har", str(har))
        self.assertEqual((code, err.strip()), (1, "这个文件不是 HAR 格式。"))
        with self.assertRaises(ValueError):          # without --har a ValueError is not a user error
            self.call("analyze", str(run))

        self.analyze_fn.side_effect = None
        self.analyze_fn.reset_mock()
        with mock.patch.object(stakeout.os, "access", return_value=False):
            code, out, err = self.call("analyze", str(run), "--har", str(har))
        self.assertEqual(code, 1)
        self.assertIn("运行目录不可写", err)
        self.analyze_fn.assert_not_called()

    def test_bad_seconds(self):
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()) as err:
            stakeout.main(["run", PKG, "--seconds", "0"])
        self.assertEqual(cm.exception.code, 2)
        self.assertEqual(err.getvalue(), "参数有误（--seconds：需要一个正整数，收到的是 0），用 -h 查看用法。\n")


if __name__ == "__main__":
    unittest.main()
