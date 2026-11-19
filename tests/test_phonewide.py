"""aw/phonewide.py (docs/CONTRACT_PHONE.md, "aw/phonewide.py"): a small synthetic phone run with
stand-ins for aw.overview, aw.collect.read_packages, the pcap and the key route; and the real phone
run fixtures/phone_1119, checked for structure and for counts computed here from its own files. No
value from the fixture is written in this file."""

import calendar
import contextlib
import gzip
import json
import sys
import tempfile
import time
import types
import unittest
from collections import Counter
from datetime import datetime
from pathlib import Path
from unittest import mock

import aw
from aw import device, parse_net, parse_poll, phonewide

ROOT = Path(__file__).resolve().parent.parent
PHONE = ROOT / "fixtures" / "phone_1119"
TSHARK = device.find_tshark()

DAY = "2026-01-02 "
EPOCH0 = calendar.timegm(datetime(2026, 1, 2, 10, 0, 0).timetuple())      # utc_offset +0000

PACKAGES = [
    {"package": "com.example.alpha", "uid": 10100, "apk": "/data/app/a/base.apk", "third_party": True},
    {"package": "com.example.beta", "uid": 10200, "apk": "/data/app/b/base.apk", "third_party": True},
    {"package": "com.example.shared1", "uid": 10300, "apk": "/system/app/s1.apk", "third_party": False},
    {"package": "com.example.shared2", "uid": 10300, "apk": "/data/app/s2/base.apk", "third_party": True},
    {"package": "com.example.quiet", "uid": 10400, "apk": "/data/app/q/base.apk", "third_party": True},
    {"package": "android", "uid": 1000, "apk": "/system/framework/framework-res.apk", "third_party": False},
]

TITLES = {"location": "定位", "contacts": "通讯录", "camera": "相机", "clipboard": "剪贴板", "other": "其他权限"}
OPS = {"FINE_LOCATION": "location", "GPS": "location", "READ_CONTACTS": "contacts", "CAMERA": "camera",
       "READ_CLIPBOARD": "clipboard"}


class _Overview:
    """Stand-in for aw.overview: records what it is given."""

    def __init__(self):
        self.facts, self.downloads = [], []
        self.module = types.ModuleType("aw.overview")
        self.module.CATEGORIES = tuple((k, t, 1) for k, t in TITLES.items())
        self.module.category_of = lambda op: OPS.get(op, "other")
        self.module.build_app = self.build_app
        self.module.rank = lambda apps: sorted(apps, key=lambda a: a["package"])
        self.module.write_downloads = self.write_downloads

    def build_app(self, facts):
        self.facts.append(facts)
        return {"package": facts["package"], "uid": facts["uid"], "label": facts["label"],
                "third_party": facts["third_party"], "score": 0,
                "bars": [{"key": "network"}],       # an app with no bar is not listed
                "sections": [], "downloads": []}

    def write_downloads(self, run_dir, package, detail, exchanges):
        self.downloads.append((Path(run_dir), package, detail, exchanges))
        return [{"kind": "detail.json", "title": "明细", "bytes": 1, "private": True}]


@contextlib.contextmanager
def _standins(packages=None):
    ov = _Overview()
    col = types.ModuleType("aw.collect")
    col.read_packages = (lambda run_dir: list(packages)) if packages is not None else _read_packages
    with mock.patch.dict(sys.modules, {"aw.overview": ov.module, "aw.collect": col}), \
            mock.patch.object(aw, "overview", ov.module, create=True), \
            mock.patch.object(aw, "collect", col, create=True):
        yield ov


def _read_packages(run_dir):
    """collect.read_packages as the contract gives it, for the fixture."""
    third = {line.strip()[len("package:"):] for line in (Path(run_dir) / "packages_third.txt").read_text().splitlines()
             if line.strip().startswith("package:")}
    out = []
    for line in (Path(run_dir) / "packages.txt").read_text().splitlines():
        rest, sep, uid = line.strip().rpartition(" uid:")
        apk, _, pkg = rest[len("package:"):].rpartition("=")
        if sep and uid.isdigit():
            out.append({"package": pkg, "uid": int(uid), "apk": apk, "third_party": pkg in third})
    return out


def _dump(*uids):
    """`dumpsys appops` text: uids = [(uid string, [(package, [(op, [entry line])])])]."""
    lines = ["Current AppOps Service state:", "  Settings:", "    top_state_settle_time=+5s0ms", ""]
    for uid, packages in uids:
        lines += [f"  Uid {uid}:", "    state=top", "      FINE_LOCATION: mode=allow"]
        for pkg, ops in packages:
            lines.append(f"    Package {pkg}:")
            for op, entries in ops:
                lines += [f"      {op} (allow): ", "        null=["]
                lines += [f"          {e}" for e in entries]
                lines.append("        ]")
    lines += ["  AppOps policy location tags:", "    #0: 10100=com.example.alpha[x]"]
    return "\n".join(lines) + "\n"


def _trace_line(comm, tid, tgid, ts, write, path):
    ev = "f2fs_datawrite_start" if write else "f2fs_dataread_start"
    return (f" {comm}-{tid}    ({tgid:>7}) [002] ..... {ts:.6f}: {ev}: entry_name {path}, offset 0, bytes 4096, "
            f"cmdline {comm}, pid {tid}, i_size 100, ino 5\n")


def _flow(local, sni, out, inn, t0, t1):
    return {"local": local, "sni": sni, "bytes_out": out, "bytes_in": inn,
            "first_epoch": EPOCH0 + t0, "last_epoch": EPOCH0 + t1}


PCAP = {"packets": 50, "linktype": 276, "first_epoch": EPOCH0, "last_epoch": EPOCH0 + 29, "sni": {}, "dns": {},
        "endpoints": {
            "tcp 1.1.1.1:443": {"flows": [_flow("10.0.0.2:40000", "a.example.com", 100, 200, 2, 4)]},
            "tcp 2.2.2.2:443": {"flows": [_flow("10.0.0.2:40001", "b.example.com", 10, 20, 11, 12)]},
            "tcp 3.3.3.3:443": {"flows": [_flow("10.0.0.2:40002", None, 5, 5, 3, 4)]},
            "tcp 4.4.4.4:443": {"flows": [_flow("10.0.0.2:40003", "d.example.com", 1000, 1048, 6, 6.5)]},
            "udp 8.8.8.8:53": {"flows": [_flow("10.0.0.2:5000", None, 60, 90, 7, 7.1)]}}}

KEYLOG = {"tshark": "TShark 4", "keys": {"sessions": 2, "tls13": 2, "tls12": 0},
          "connections": [
              {"id": 0, "client": "10.0.0.2:40000", "server": "1.1.1.1:443", "sni": "a.example.com",
               "decrypted": True, "handshake_seen": True, "key": True, "protocol": "h2", "exchanges": 1},
              {"id": 1, "client": "10.0.0.2:40001", "server": "2.2.2.2:443", "sni": "b.example.com",
               "decrypted": False, "handshake_seen": True, "key": False, "protocol": None, "exchanges": 0},
              {"id": 2, "client": "10.0.0.2:40003", "server": "4.4.4.4:443", "sni": "d.example.com",
               "decrypted": True, "handshake_seen": True, "key": True, "protocol": "h2", "exchanges": 1}],
          "exchanges": [
              {"source": "keylog", "time": DAY + "10:00:02.500", "protocol": "h2", "method": "GET", "host": "a.example.com",
               "path": "/a", "query": [], "request": {"headers": [], "body": None, "complete": True},
               "response": {"status": 200, "headers": [], "body": None, "complete": True}, "partial": [],
               "connection": 0, "server": "1.1.1.1:443", "pid": None, "thread": None, "connection_host_tail": None},
              {"source": "keylog", "time": DAY + "10:00:06.200", "protocol": "h2", "method": "POST", "host": "d.example.com",
               "path": "/d", "query": [], "request": {"headers": [], "body": None, "complete": True},
               "response": None, "partial": ["response_not_matched"],
               "connection": 2, "server": "4.4.4.4:443", "pid": None, "thread": None, "connection_host_tail": None}],
          "undecoded": {"bytes": 0, "reasons": {}}}


def _make_run(d: Path, full=True):
    meta = {"format": 1, "scope": "phone", "package": None, "uid": None, "app_id": None, "version_name": None,
            "device": {"brand": "Google", "model": "Pixel", "android": "15", "sdk": 35},
            "start_time": DAY + "10:00:00", "end_time": DAY + "10:00:30",
            "start_epoch": EPOCH0, "end_epoch": EPOCH0 + 30, "utc_offset": "+0000",
            "filetrace_backend": "f2fs" if full else "none", "net": full, "decrypt": "keylog" if full else "none"}
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    poll = []
    for s in range(21):
        poll.append(f"=== {DAY}10:00:{s:02d}")
        front = "com.example.alpha" if s < 10 else "com.example.beta" if s < 20 else None
        if front:
            poll.append(f"    topResumedActivity=ActivityRecord{{abc u0 {front}/.Main t9}}")
        poll.append("P 1000 500 10100 com.example.alpha")
        poll.append("P 3000 500 10300 com.example.shared1")
        poll.append("P 4000 600 99001 com.example.alpha:sandboxed_process0")
        if s >= 5:
            poll.append("P 2000 500 10200 com.example.beta")
        if s <= 5:
            poll.append("S tcp ESTAB 0 0 10.0.0.2:40000 1.1.1.1:443 timer:(keepalive,1min,0) uid:10100 ino:1 sk:1 <->")
        if 10 <= s <= 15:
            poll.append("S tcp ESTAB 0 0 10.0.0.2:40001 2.2.2.2:443 uid:10200 ino:2 sk:2 <->")
        if s <= 6:
            poll.append("S tcp FIN-WAIT-1 0 1 10.0.0.2:40002 3.3.3.3:443 ino:0 sk:3 ---")
        if s == 18:
            poll.append("S tcp ESTAB 0 0 10.0.0.2:40005 5.5.5.5:443 uid:10100 ino:5 sk:5 <->")
        poll.append("S tcp ESTAB 0 0 127.0.0.1:5555 127.0.0.1:41000 uid:10100 ino:6 sk:6 <->")
    (d / "poll.txt").write_text("\n".join(poll) + "\n", encoding="utf-8")
    (d / "ps_before.txt").write_text("  PID  PPID USER         NAME\n    1     0 root         init\n", encoding="utf-8")

    alpha_vibrate = ("u0a100", [("com.example.alpha", [("VIBRATE", [f"Access: [top-s] {DAY}10:00:00.500 (-1s)"])])])
    (d / "appops_before.txt").write_text(_dump(alpha_vibrate), encoding="utf-8")
    sample1 = _dump(("1000", [("android", [("GPS", [f"Access: [pers-s] {DAY}10:00:07.000 (-3s)"])])]),
                    ("u0a100", [("com.example.alpha", [("FINE_LOCATION", [f"Access: [top-s] {DAY}10:00:03.000 (-7s)"]),
                                                        ("VIBRATE", [f"Access: [top-s] {DAY}10:00:00.500 (-9s)"])])]))
    sample2_uids = [
        ("u0a100", [("com.example.alpha", [("FINE_LOCATION", [f"Access: [top-s] {DAY}10:00:15.000 (-5s)"])])]),
        ("u0a200", [("com.example.beta", [("READ_CONTACTS", [f"Reject: [bg-s] {DAY}10:00:12.000 (-8s)"]),
                                          ("FINE_LOCATION", [f"Access: [top-tp] {DAY}10:00:13.000 (-7s)"])])]),
        ("u0a300", [("com.example.shared1", [("CAMERA", [f"Access: [fg-s] {DAY}10:00:14.000 (-6s)"])])]),
        ("u0a100", [("com.example.alpha", [("FINE_LOCATION", [f"Access: [top-s] {DAY}09:00:00.000 (-1h)"])])])]
    sample2 = _dump(*sample2_uids)
    if full:
        with open(d / "appops_all.txt.gz", "wb") as f:
            for epoch, hms, text in ((EPOCH0 + 10, "10:00:10", sample1), (EPOCH0 + 20, "10:00:20", sample2)):
                f.write(gzip.compress(f"=== {epoch} {DAY}{hms}\n{text}".encode()))
    after = _dump(*sample2_uids,
                  ("u0a100", [("com.example.alpha", [("READ_CLIPBOARD", [f"Access: [top-s] {DAY}10:00:05.500 (-25s)"]),
                                                      ("VIBRATE", [f"Access: [top-s] {DAY}10:00:00.500 (-30s)"])])]))
    (d / "appops_after.txt").write_text(after, encoding="utf-8")
    if not full:
        return

    (d / "logcat.txt").write_text("\n".join([
        f"{DAY}10:00:01.000  1000  1100 I chatty  : noise",
        f"{DAY}10:00:04.900  1000  1100 I am_proc_start: [0,2000,10200,com.example.beta,service,{{com.example.beta/.Push}}]",
        f"{DAY}10:00:05.400  1234  1250 D ClipboardService: clipboardAccessAllowed: op=29 result=true "
        "callingPackage=com.example.alpha",
        f"{DAY}10:00:06.000  1000  1100 I ActivityManager: Start proc 3100:com.example.shared1/u0a300 for top-activity "
        "{com.example.shared1/.Main}",
        f"{DAY}10:00:29.000  1000  1100 I chatty  : last line",
    ]) + "\n", encoding="utf-8")

    trace = [f"              sh-1    (      1) [002] ..... 100.000000: tracing_mark_write: AW_SYNC {EPOCH0}\n",
             _trace_line("RenderThread", 1000, 1000, 101.0, False, "/app/~~x/com.example.beta-abc/base.apk"),
             _trace_line("RenderThread", 1000, 1000, 101.5, False, "/app/~~x/com.example.beta-abc/split.apk"),
             _trace_line("RenderThread", 1000, 1000, 102.0, False, "/data/com.example.alpha/files/own"),
             _trace_line("Thread-7", 1001, "-------", 103.0, False, "/media/0/Pictures/p.png"),
             _trace_line("Thread-7", 1001, 1000, 103.5, False, "/data/com.example.alpha/files/own"),
             _trace_line("Prefs", 2000, 2000, 112.0, True, "/data/com.example.alpha/shared_prefs/x.xml"),
             _trace_line("RenderThread", 1000, 1000, 115.0, False, "/media/0/DCIM/Camera/IMG_1.jpg"),
             _trace_line("init", 1, 1, 116.0, False, "/app/~~y/com.example.alpha-def/base.apk"),
             _trace_line("worker", 9999, 9999, 117.0, False, "/media/0/Download/a.pdf")]
    (d / "filetrace_f2fs.txt").write_text("".join(trace), encoding="utf-8")
    (d / "net.pcap").write_bytes(b"")
    (d / "tls_keys.log").write_text("", encoding="utf-8")


class SyntheticRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = Path(cls.tmp.name) / "phone-run"
        cls.run_dir.mkdir()
        _make_run(cls.run_dir)
        cls.out = Path(cls.tmp.name) / "out"
        with _standins(PACKAGES) as ov, \
                mock.patch("aw.parse_net.parse_pcap", return_value=PCAP), \
                mock.patch("aw.parse_keylog.parse_keylog", return_value=KEYLOG):
            cls.overview = phonewide.analyze_phone(cls.run_dir, cls.out, labels={"com.example.shared2": "共享应用"})
        cls.ov = ov
        cls.facts = {f["package"]: f for f in ov.facts}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def events(self, package, category):
        return [e for e in self.facts[package]["events"] if e["category"] == category]

    def test_apps_listed_by_uid(self):
        # the quiet app has nothing; uid 1000 is the system; the shared uid is one app named after its user-installed package
        self.assertEqual(set(self.facts), {"com.example.alpha", "com.example.beta", "com.example.shared2"})
        shared = self.facts["com.example.shared2"]
        self.assertEqual((shared["uid"], shared["label"], shared["third_party"]), (10300, "共享应用", True))
        self.assertIsNone(self.facts["com.example.alpha"]["label"])
        for f in self.ov.facts:
            self.assertEqual(set(f), {"package", "uid", "label", "third_party", "events", "network", "requests"})
            for e in f["events"]:
                self.assertEqual(set(e), {"category", "time", "what", "code", "front", "denied", "count", "at_least"})

    def test_overview_written(self):
        written = json.loads((self.out / "overview.json").read_text(encoding="utf-8"))
        self.assertEqual(written, self.overview)
        run = written["run"]
        self.assertEqual(run, {"id": "phone-run", "scope": "phone", "package": None, "device": "Google Pixel · Android 15",
                               "start_time": DAY + "10:00:00", "end_time": DAY + "10:00:30", "seconds": 30,
                               "net": True, "decrypt": True})
        self.assertEqual([a["package"] for a in written["apps"]],
                         ["com.example.alpha", "com.example.beta", "com.example.shared2"])
        self.assertEqual([a["downloads"][0]["kind"] for a in written["apps"]], ["detail.json"] * 3)
        self.assertEqual({(d, p) for d, p, _, _ in self.ov.downloads},
                         {(self.out, p) for p in ("com.example.alpha", "com.example.beta", "com.example.shared2")})
        self.assertFalse((self.run_dir / "overview.json").exists())

    def test_appops_in_window_by_uid_and_front(self):
        loc = self.events("com.example.alpha", "location")
        # 10:00:03 in front; 10:00:15 the poll shows beta in front; the old entry is outside the window
        self.assertEqual([(e["time"], e["front"], e["code"], e["at_least"]) for e in loc],
                         [(DAY + "10:00:03.000", True, "FINE_LOCATION", True),
                          (DAY + "10:00:15.000", False, "FINE_LOCATION", True)])
        self.assertEqual(loc[0]["what"], "精确位置")
        # an entry already in appops_before.txt is no new access
        self.assertEqual(self.events("com.example.alpha", "other"), [])
        contacts = self.events("com.example.beta", "contacts")
        self.assertEqual([(e["denied"], e["front"]) for e in contacts], [(True, False)])
        # the proxy entry (tp) is the proxied app's, not beta's
        self.assertEqual(self.events("com.example.beta", "location"), [])
        cam = self.events("com.example.shared2", "camera")
        self.assertEqual([(e["front"], e["time"]) for e in cam], [(False, DAY + "10:00:14.000")])

    def test_clipboard_joined_with_logcat(self):
        clip = self.events("com.example.alpha", "clipboard")
        self.assertEqual([(e["time"], e["front"], e["denied"], e["at_least"], e["code"]) for e in clip],
                         [(DAY + "10:00:05.400", True, False, False, "READ_CLIPBOARD")])

    def test_background_start(self):
        starts = self.events("com.example.beta", "background_start")
        self.assertEqual(len(starts), 1)
        self.assertEqual((starts[0]["time"], starts[0]["front"]), (DAY + "10:00:04.900", False))
        self.assertIn("com.example.beta", starts[0]["what"])
        self.assertIn("服务", starts[0]["what"])
        # alpha ran from the first block; shared1's start was to open its screen
        self.assertEqual(self.events("com.example.alpha", "background_start"), [])
        self.assertEqual(self.events("com.example.shared2", "background_start"), [])

    def test_files_by_tgid(self):
        apk = self.events("com.example.alpha", "installed_apps")
        self.assertEqual([(e["what"], e["count"], e["front"], e["time"]) for e in apk],
                         [("读取 com.example.beta 的安装包", 2, True, DAY + "10:00:01.000")])
        photos = {e["what"].split(" ")[1]: e for e in self.events("com.example.alpha", "photos")}
        # the unknown-TGID line took the TGID of its thread's next line
        self.assertEqual({k: (e["front"], e["count"]) for k, e in photos.items()},
                         {"/sdcard/Pictures": (True, 1), "/sdcard/DCIM/Camera": (False, 1)})
        data = self.events("com.example.beta", "other_app_data")
        self.assertEqual([(e["what"], e["front"]) for e in data],
                         [("读写 com.example.alpha 的数据（读 0 次、写 1 次）", True)])
        detail = next(d for _, p, d, _ in self.ov.downloads if p == "com.example.alpha")
        rows = {r["target"]: r for r in detail["files"]}
        self.assertEqual(rows["/sdcard/DCIM/Camera"]["files"], ["/sdcard/DCIM/Camera/IMG_1.jpg"])
        self.assertEqual(rows["com.example.beta"]["pids"], [1000])

    def test_network_by_local_address(self):
        net = self.facts["com.example.alpha"]["network"]
        self.assertEqual(net["endpoints"], [
            {"host": "a.example.com", "address": "1.1.1.1:443", "connections": 1, "bytes": 300,
             "front": True, "background": False},
            # seen by the poll only, while beta was in front
            {"host": None, "address": "5.5.5.5:443", "connections": 1, "bytes": 0, "front": False, "background": True}])
        self.assertEqual((net["connections"], net["bytes"], net["not_decrypted"]), (2, 300, 0))
        beta = self.facts["com.example.beta"]["network"]
        self.assertEqual([(e["host"], e["front"], e["background"]) for e in beta["endpoints"]],
                         [("b.example.com", True, False)])
        self.assertEqual(beta["not_decrypted"], 1)

    def test_requests_only_on_the_apps_connections(self):
        reqs = self.facts["com.example.alpha"]["requests"]
        self.assertEqual([(x["path"], x["front"]) for x in reqs], [("/a", True)])
        self.assertEqual(self.facts["com.example.beta"]["requests"], [])
        alpha = next(x for _, p, _, x in self.ov.downloads if p == "com.example.alpha")
        self.assertEqual(alpha, reqs)

    def test_limits(self):
        text = "\n".join(self.overview["limits"])
        self.assertIn("手机上共有 4 个应用（包括系统自带的），其中 1 个", text)
        self.assertIn("1 次权限使用、1 个网络连接", text)                      # uid 1000's GPS, the uid-less socket
        self.assertIn("抓包里有 2 个网络连接（约 2 KB）不知道是哪个应用的，其中 1 个是", text)
        self.assertIn("解开了 2 个加密连接，其中 1 个不知道是哪个应用的，里面的 1 个请求", text)
        self.assertIn("有约 1 秒不知道你在用哪个应用", text)
        self.assertIn("文件跟踪里有 1 次", text)
        self.assertIn("每 10 秒", text)
        for word in ("uid", "pid", "TLS", "HTTP/2", "ClientHello"):
            self.assertNotIn(word, text)


class MissingSources(unittest.TestCase):
    def test_no_capture_no_trace_no_logcat(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            _make_run(run, full=False)
            with _standins(PACKAGES) as ov:
                result = phonewide.analyze_phone(run)
            self.assertTrue((run / "overview.json").is_file())
            self.assertFalse(result["run"]["net"])
            self.assertFalse(result["run"]["decrypt"])
            text = "\n".join(result["limits"])
            for part in ("这次没有抓包", "这次没有跟踪文件访问", "没有系统日志", "没有每 10 秒一次的权限记录"):
                self.assertIn(part, text)
            alpha = next(f for f in ov.facts if f["package"] == "com.example.alpha")
            # appops_after.txt alone: the location entry, and the clipboard read without logcat
            self.assertEqual(Counter(e["category"] for e in alpha["events"]), {"location": 1, "clipboard": 1})
            self.assertEqual(alpha["network"]["endpoints"][0]["bytes"], 0)


class Readers(unittest.TestCase):
    def test_gzip_cut_off_inside_a_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.gz"
            whole = gzip.compress(b"=== 1 x\nline one\n")
            cut = gzip.compress(b"=== 2 y\n" + b"line two\n" * 2000)
            p.write_bytes(whole + cut[:len(cut) // 2])
            lines = list(phonewide._gz_lines(p))
        self.assertEqual(lines[:2], ["=== 1 x", "line one"])
        self.assertTrue(all(x in ("=== 2 y", "line two") for x in lines[2:]))

    def test_socket_without_uid_is_uid_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "poll.txt"
            p.write_text("=== 2026-01-02 10:00:00\n"
                         "S tcp FIN-WAIT-1 0 1 [::ffff:10.0.0.2]:40002 [2001:db8::1]:443 ino:0 sk:3 ---\n"
                         "S udp 0 0 10.0.0.2%wlan0:68 10.0.0.1:67 uid:1073 ino:4 sk:4 <->\n", encoding="utf-8")
            poll = phonewide._read_poll(p)
        self.assertEqual({k: s["uids"] for k, s in poll["sockets"].items()},
                         {("tcp", "10.0.0.2:40002", "[2001:db8::1]:443"): {0},
                          ("udp", "10.0.0.2:68", "10.0.0.1:67"): {1073}})


@unittest.skipUnless(PHONE.is_dir() and TSHARK, "fixture or tshark not present")
class PhoneFixture(unittest.TestCase):
    """fixtures/phone_1119: attribution checked against the run's own poll, and the time it takes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = time.monotonic()
        with _standins() as ov:
            cls.overview = phonewide.analyze_phone(PHONE, cls.tmp.name)
        cls.seconds = time.monotonic() - t
        cls.ov = ov
        cls.packages = _read_packages(PHONE)
        # the S lines, read here: (proto, local, remote) -> uids
        cls.sockets = {}
        for line in (PHONE / "poll.txt").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("S "):
                tokens = line.split()
                uid = next((int(x[4:]) for x in tokens if x.startswith("uid:")), 0)
                addrs = [x for x in tokens[2:] if ":" in x][:2]
                ends = [parse_poll._endpoint(a) for a in addrs]
                if len(ends) == 2 and all(ends):
                    cls.sockets.setdefault((tokens[1], *(parse_poll._ipport(*e) for e in ends)), set()).add(uid)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_well_under_a_minute(self):
        self.assertLess(self.seconds, 60)

    def test_apps_are_installed_app_uids(self):
        uids = {p["uid"] for p in self.packages}
        self.assertGreater(len(self.ov.facts), 0)
        self.assertEqual(len(self.overview["apps"]), len(self.ov.facts))
        for f in self.ov.facts:
            self.assertGreaterEqual(f["uid"], 10000)
            self.assertIn(f["uid"], uids)
            self.assertTrue(f["events"] or f["network"]["endpoints"] or f["requests"])
        self.assertEqual(len({f["uid"] for f in self.ov.facts}), len(self.ov.facts))
        silent = len({p["uid"] for p in self.packages if p["uid"] >= 10000}) - len(self.ov.facts)
        self.assertIn(f"其中 {silent} 个在这次采集中没有用权限", self.overview["limits"][0])

    def test_events_shape(self):
        categories = {"location", "camera", "microphone", "contacts", "sms", "call_log", "calendar", "phone_state",
                      "photos", "clipboard", "installed_apps", "other_app_data", "sensors", "background_start", "other"}
        for f in self.ov.facts:
            for e in f["events"]:
                self.assertIn(e["category"], categories)
                self.assertIn(e["front"], (True, False, None))
                self.assertGreaterEqual(e["count"], 1)
                self.assertTrue(e["what"])
        self.assertTrue(any(e["category"] == "background_start" for f in self.ov.facts for e in f["events"]))

    def test_decrypted_requests_go_to_the_app_of_their_socket(self):
        seen = set()
        for _, package, detail, exchanges in self.ov.downloads:
            uid = detail["uid"]
            tls = {c["id"]: c for c in detail["tls_connections"]}
            for x in exchanges:
                c = tls[x["connection"]]
                client = parse_net._norm_ipport(c["client"])
                key = ("tcp", client, parse_net._norm_ipport(c["server"]))
                uids = self.sockets.get(key)
                if uids is None:        # matched by its local address alone
                    uids = set().union(*(u for k, u in self.sockets.items() if k[:2] == ("tcp", client)))
                self.assertEqual(uids, {uid})
                self.assertNotIn(x["connection"], seen)
            seen |= {x["connection"] for x in exchanges}
        self.assertGreater(len(seen), 0)

    def test_connections_counted_once(self):
        rows = [(r["proto"], r["local"], r["remote"]) for _, _, d, _ in self.ov.downloads for r in d["connections"]]
        self.assertEqual(len(rows), len(set(rows)))
        self.assertEqual(sum(f["network"]["connections"] for f in self.ov.facts), len(rows))


if __name__ == "__main__":
    unittest.main()
