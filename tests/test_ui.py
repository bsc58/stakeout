"""Tests for aw/ui.py and aw/ui_static/. No phone: the phone, aw.collect, aw.labels, aw.phonewide,
aw.overview, aw.analyze and aw.report are stood in for; the server is real, on a free port."""
import http.client
import json
import re
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from aw import device, ui
from aw.device import DeviceError

STATIC = Path(ui.__file__).resolve().parent / "ui_static"
PACKAGES = [
    {"package": "com.xingin.xhs", "uid": 10378, "apk": "/data/app/a/base.apk", "third_party": True},
    {"package": "com.tencent.mm", "uid": 10301, "apk": "/data/app/b/base.apk", "third_party": True},
    {"package": "com.example.nolabel", "uid": 10400, "apk": "/data/app/c/base.apk", "third_party": True},
    {"package": "com.android.chrome", "uid": 10120, "apk": "/product/app/Chrome/Chrome.apk", "third_party": False},
]
LABELS = {"com.xingin.xhs": "小红书", "com.tencent.mm": "微信", "com.android.chrome": "Chrome"}


def overview_of(run_id, scope, package=None, labels=None):
    """An overview.json in the contract's shape, small."""
    labels = labels or {}
    app = {"package": "com.xingin.xhs", "uid": 10378, "label": labels.get("com.xingin.xhs"),
           "third_party": True, "score": 12,
           "bars": [{"key": "location", "text": "定位 3 次", "count": 3, "background": 1, "denied": 0,
                     "level": "high"}],
           "sections": [{"key": "location", "title": "定位", "summary": "用了 3 次定位，其中 1 次是在你没打开它的时候。",
                         "columns": ["时间", "做了什么", "在前台"], "rows": [["10:01:02", "精确定位", "否"]], "more": 0}],
           "downloads": [{"kind": "detail.json", "title": "详细数据", "bytes": 2, "private": True}]}
    other = {"package": "com.example.nolabel", "uid": 10400, "label": None, "third_party": True, "score": 1,
             "bars": [{"key": "network", "text": "联网 5 次", "count": 5, "background": 0, "denied": 0,
                       "level": "low"}],
             "sections": [], "downloads": []}
    return {"format": 1,
            "run": {"id": run_id, "scope": scope, "package": package, "device": "OnePlus PKX110 · Android 15",
                    "start_time": "2026-11-19 10:00:00", "end_time": "2026-11-19 10:05:00", "seconds": 300,
                    "net": True, "decrypt": False},
            "apps": [app, other] if scope == "phone" else [dict(app, package=package)],
            "limits": ["有 2 个连接看不出是哪个应用的。"]}


def write_overview(run_dir, ov):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "overview.json").write_text(json.dumps(ov, ensure_ascii=False), encoding="utf-8")
    for app in ov["apps"]:
        for d in app["downloads"]:
            (run_dir / "apps" / app["package"]).mkdir(parents=True, exist_ok=True)
            (run_dir / "apps" / app["package"] / d["kind"]).write_text("{}", encoding="utf-8")
    return ov


class World:
    """The fake phone and the fake analysis, as modules aw.ui imports."""

    def __init__(self):
        self.calls = []
        self.check_error = None
        self.start_error = None
        self.stop_error = None
        self.unavailable = []
        self.stop_gate = threading.Event()
        self.analysis_gate = threading.Event()
        self.stop_gate.set()
        self.analysis_gate.set()
        self.scope = None

    def modules(self):
        world = self

        collect = types.ModuleType("aw.collect")
        collect.STOP_MARGIN_S = 300
        collect.MAX_CAPTURE_S = 3600
        collect.AUTOSTOP_ZH = {"deadline": "达到最长采集时间"}

        class CaptureLeft(DeviceError):
            pass

        collect.CaptureLeft = CaptureLeft

        def check_package_name(package):
            if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z]\w*(\.[A-Za-z]\w*)+", package):
                raise DeviceError(f"包名格式不对：{package}")

        def start(dev, package, net=True, filetrace=True, max_seconds=3600, decrypt=False):
            world.calls.append(("start", package, max_seconds, decrypt))
            world.scope = "phone" if package is None else "app"
            if world.start_error:
                raise world.start_error
            return {"package": package, "uid": None, "start_time": "2026-11-19 10:00:00", "net": net,
                    "filetrace": filetrace, "max_seconds": max_seconds, "decrypt": decrypt,
                    "unavailable": list(world.unavailable), "running": False}

        def stop(dev, run_dir):
            world.calls.append(("stop", Path(run_dir).name))
            world.stop_gate.wait(5)
            if world.stop_error:
                raise world.stop_error
            run_dir = Path(run_dir)
            run_dir.mkdir(parents=True, exist_ok=True)
            meta = {"format": 1, "scope": world.scope, "package": None, "uid": None,
                    "start_time": "2026-11-19 10:00:00", "end_time": "2026-11-19 10:05:00",
                    "start_epoch": 1795100000, "end_epoch": 1795100300, "decrypt": "none"}
            (run_dir / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
            return meta

        collect.check_package_name = check_package_name
        collect.start = start
        collect.stop = stop
        collect.list_packages = lambda dev: [dict(p) for p in PACKAGES]
        collect.read_packages = lambda run_dir: [dict(p) for p in PACKAGES]

        labels = types.ModuleType("aw.labels")

        def read_labels(dev, packages, cache_path):
            world.calls.append(("labels", dev is not None, sorted(p["package"] for p in packages)))
            return {p["package"]: LABELS.get(p["package"]) for p in packages}

        labels.labels = read_labels

        phonewide = types.ModuleType("aw.phonewide")

        def analyze_phone(run_dir, out_dir=None, labels=None):
            world.calls.append(("analyze_phone", labels))
            world.analysis_gate.wait(5)
            return write_overview(Path(run_dir), overview_of(Path(run_dir).name, "phone", labels=labels))

        phonewide.analyze_phone = analyze_phone

        analyze = types.ModuleType("aw.analyze")

        def run_analyze(run_dir, out_dir=None, har=None):
            world.calls.append(("analyze", Path(run_dir).name))
            return {"meta": json.loads((Path(run_dir) / "meta.json").read_text(encoding="utf-8"))}

        analyze.analyze = run_analyze

        report = types.ModuleType("aw.report")
        report.render = lambda result, show_secrets=False: "<!doctype html><title>report</title>"

        overview = types.ModuleType("aw.overview")

        def write_app_run(result, run_dir):
            world.calls.append(("write_app_run", Path(run_dir).name))
            package = result["meta"].get("package") or "com.xingin.xhs"
            return write_overview(Path(run_dir), overview_of(Path(run_dir).name, "app", package))

        overview.write_app_run = write_app_run

        return {"aw.collect": collect, "aw.labels": labels, "aw.phonewide": phonewide,
                "aw.analyze": analyze, "aw.report": report, "aw.overview": overview}

    def device_class(self):
        world = self

        class FakeDevice:
            def __init__(self, adb=None, serial=None):
                pass

            def check(self):
                if world.check_error:
                    raise world.check_error
                return {"serial": "FAKE0001", "model": "PKX110", "android": "15", "sdk": 35, "root": True}

        return FakeDevice


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "runs").mkdir()
        self.world = World()
        for p in (mock.patch.dict(sys.modules, self.world.modules()),
                  mock.patch.object(device, "Device", self.world.device_class()),
                  mock.patch.object(device, "find_tshark", lambda path=None: "/fake/tshark"),
                  mock.patch.object(device, "find_ecapture", lambda path=None: "/fake/ecapture")):
            p.start()
            self.addCleanup(p.stop)
        self.server = ui.make_server(0, self.tmp)
        self.app = self.server.app
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(self._close)

    def _close(self):
        self.world.stop_gate.set()
        self.world.analysis_gate.set()
        self.app.stop_event.set()
        if self.app.thread is not None:
            self.app.thread.join(10)
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def request(self, method, path, body=None, token=True, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"X-Stakeout-Token": self.app.token} if token is True else (
            {"X-Stakeout-Token": token} if token else {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.putrequest(method, path, skip_host=host is not None)
        if host is not None:
            conn.putheader("Host", host)
        for k, v in headers.items():
            conn.putheader(k, v)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        res = conn.getresponse()
        raw = res.read()
        result = (res.status, {k.lower(): v for k, v in res.getheaders()}, raw)
        conn.close()
        return result

    def get(self, path, **kw):
        status, _, raw = self.request("GET", path, **kw)
        return status, json.loads(raw)

    def post(self, path, body, **kw):
        status, _, raw = self.request("POST", path, body, **kw)
        return status, json.loads(raw)

    def wait_state(self, *states, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, st = self.get("/api/status")
            if st["state"] in states:
                return st
            time.sleep(0.02)
        self.fail(f"state stayed {st['state']}, expected {states}")


class SafetyTest(ServerTest):
    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertTrue(self.server.url.startswith(f"http://127.0.0.1:{self.port}/?token="))
        self.assertIn(self.app.token, self.server.url)

    def test_host_header_must_name_this_server(self):
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1", f"127.0.0.1:{self.port + 1}",
                     f"192.168.1.5:{self.port}"):
            for path in ("/", "/api/status", "/app.js"):
                status, _, _ = self.request("GET", path, host=host)
                self.assertEqual(status, 403, (host, path))
        status, _, _ = self.request("POST", "/api/start", {"scope": "phone", "seconds": None, "decrypt": False},
                                    host="evil.example")
        self.assertEqual(status, 403)
        self.assertEqual(self.world.calls, [])
        for host in (f"127.0.0.1:{self.port}", f"localhost:{self.port}"):
            self.assertEqual(self.request("GET", "/api/status", host=host)[0], 200)
            self.assertEqual(self.request("GET", "/", host=host)[0], 200)

    def test_api_needs_the_token(self):
        for token in (None, "", "wrong", self.app.token + "x"):
            for path in ("/api/status", "/api/runs", "/api/device", "/api/apps"):
                self.assertEqual(self.request("GET", path, token=token)[0], 403, (token, path))
            status, _, _ = self.request("POST", "/api/start", {"scope": "phone", "seconds": None, "decrypt": False},
                                        token=token)
            self.assertEqual(status, 403)
        self.assertEqual(self.world.calls, [])
        # the query parameter is for download links only
        self.assertEqual(self.request("GET", f"/api/status?token={self.app.token}", token=None)[0], 403)

    def test_downloads_need_the_token(self):
        write_overview(self.tmp / "runs" / "phone-1", overview_of("phone-1", "phone"))
        path = "/api/runs/phone-1/apps/com.xingin.xhs/detail.json"
        self.assertEqual(self.request("GET", path, token=None)[0], 403)
        self.assertEqual(self.request("GET", path + "?token=wrong", token=None)[0], 403)
        status, headers, raw = self.request("GET", f"{path}?token={self.app.token}", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"{}")
        self.assertTrue(headers["content-disposition"].startswith("attachment;"))
        self.assertEqual(self.request("GET", path)[0], 200)      # the header works too

    def test_download_paths_stay_inside_the_run(self):
        write_overview(self.tmp / "runs" / "phone-1", overview_of("phone-1", "phone"))
        (self.tmp / "runs" / "phone-1" / "meta.json").write_text("{}")
        (self.tmp / "secret.json").write_text("{}")
        for path in ("/api/runs/phone-1/apps/com.xingin.xhs/meta.json",
                     "/api/runs/phone-1/apps/../detail.json",
                     "/api/runs/phone-1/apps/%2E%2E/detail.json",
                     "/api/runs/..%2F..%2F/apps/com.xingin.xhs/detail.json",
                     "/api/runs/phone-1/apps/com.example.nolabel/detail.json",
                     "/api/runs/nope/apps/com.xingin.xhs/detail.json"):
            self.assertEqual(self.request("GET", path)[0], 404, path)

    def test_static_files(self):
        status, headers, raw = self.request("GET", f"/?token={self.app.token}", token=None)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["content-type"])
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertIn(b"Stakeout", raw)
        for path, kind in (("/app.js", "javascript"), ("/style.css", "text/css")):
            status, headers, _ = self.request("GET", path, token=None)
            self.assertEqual(status, 200)
            self.assertIn(kind, headers["content-type"])
        self.assertEqual(self.request("GET", "/index.html")[0], 404)
        self.assertEqual(self.request("GET", "/../aw/ui.py")[0], 404)
        self.assertEqual(self.request("GET", "/api/nothing")[0], 404)


class PageTest(unittest.TestCase):
    """The page's own files: nothing from the network, values only as text."""

    def test_no_external_resources(self):
        for name in ("index.html", "app.js", "style.css"):
            text = (STATIC / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"https?:|//[a-z0-9.-]+\.[a-z]{2,}/|@import|url\(", name)

    def test_values_go_in_as_text(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                     "new Function", "createContextualFragment"):
            self.assertNotIn(sink, js)
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r"<script>|\son[a-z]+=|style=")      # nothing inline: the CSP forbids it

    def test_page_names_every_element_the_script_uses(self):
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        ids = set(re.findall(r"\$\('([\w-]+)'\)", js))
        self.assertTrue(ids)
        for i in ids:
            self.assertIn(f'id="{i}"', html, i)


class DeviceTest(ServerTest):
    def test_ready(self):
        status, d = self.get("/api/device")
        self.assertEqual(status, 200)
        self.assertEqual(set(d), {"connected", "serial", "model", "android", "root", "tshark", "ecapture", "message"})
        self.assertTrue(d["connected"] and d["root"] and d["tshark"] and d["ecapture"])
        self.assertEqual((d["model"], d["android"]), ("PKX110", "15"))
        self.assertIn("可以开始", d["message"])

    def test_no_phone_and_no_root(self):
        self.world.check_error = DeviceError(device.NO_DEVICE)
        status, d = self.get("/api/device")
        self.assertEqual(status, 200)
        self.assertFalse(d["connected"])
        self.assertEqual(d["message"], device.NO_DEVICE)
        self.world.check_error = DeviceError(device.NO_ROOT)
        status, d = self.get("/api/device")
        self.assertTrue(d["connected"])
        self.assertFalse(d["root"])
        self.assertEqual(d["message"], device.NO_ROOT)

    def test_no_wireshark(self):
        with mock.patch.object(device, "find_tshark", lambda path=None: None):
            status, d = self.get("/api/device")
        self.assertFalse(d["tshark"])
        self.assertIn("Wireshark", d["message"])
        self.assertIn("不解密", d["message"])

    def test_apps(self):
        status, apps = self.get("/api/apps")
        self.assertEqual(status, 200)
        # user-installed first, by label (code point order: 小 before 微), unnamed after named
        self.assertEqual([a["package"] for a in apps],
                         ["com.xingin.xhs", "com.tencent.mm", "com.example.nolabel", "com.android.chrome"])
        self.assertEqual(set(apps[0]), {"package", "label", "third_party"})
        self.assertIsNone(next(a for a in apps if a["package"] == "com.example.nolabel")["label"])
        # the user's apps are read from the phone, the system's from the cache alone
        self.assertIn(("labels", True, ["com.example.nolabel", "com.tencent.mm", "com.xingin.xhs"]), self.world.calls)
        self.assertIn(("labels", False, ["com.android.chrome"]), self.world.calls)

    def test_apps_without_phone(self):
        self.world.check_error = DeviceError(device.NO_DEVICE)
        status, body = self.get("/api/apps")
        self.assertEqual(status, 409)
        self.assertEqual(body["message"], device.NO_DEVICE)


class CaptureTest(ServerTest):
    START_PHONE = {"scope": "phone", "package": None, "seconds": None, "decrypt": False}

    def test_phone_run_start_status_stop_analysis_done(self):
        self.world.stop_gate.clear()
        self.world.analysis_gate.clear()
        status, body = self.post("/api/start", self.START_PHONE)
        self.assertEqual(status, 200)
        run_id = body["run"]
        self.assertRegex(run_id, r"^phone-\d{8}-\d{6}$")
        st = self.wait_state("running")
        self.assertEqual(set(st), {"state", "run", "scope", "package", "started", "seconds", "message"})
        self.assertEqual((st["run"], st["scope"], st["package"], st["seconds"]), (run_id, "phone", None, None))
        self.assertLessEqual(abs(st["started"] - time.time()), 5)
        self.assertEqual(self.world.calls[0], ("start", None, 3600, False))

        status, body = self.post("/api/start", self.START_PHONE)       # one capture at a time
        self.assertEqual(status, 409)
        self.assertIn("已经有", body["message"])

        status, _ = self.post("/api/stop", {})
        self.assertEqual(status, 200)
        self.wait_state("stopping")
        self.world.stop_gate.set()
        self.wait_state("analyzing")
        status, body = self.get(f"/api/runs/{run_id}/overview")         # not yet: the capture's own analysis
        self.assertEqual(status, 409)
        self.world.analysis_gate.set()
        st = self.wait_state("done")
        self.assertIn("2 个应用", st["message"])

        # names: the cache's go to the analysis; the listed app it lacks is read from the phone afterwards
        self.assertEqual([c for c in self.world.calls if c[0] == "labels" and c[1]],
                         [("labels", True, ["com.example.nolabel"])])
        analysis = [c for c in self.world.calls if c[0] == "analyze_phone"]
        self.assertEqual(analysis, [("analyze_phone", {p["package"]: LABELS.get(p["package"]) for p in PACKAGES})])

        status, runs = self.get("/api/runs")
        self.assertEqual(runs[0], {"id": run_id, "scope": "phone", "package": None, "label": None,
                                   "start_time": "2026-11-19 10:00:00", "seconds": 300, "apps": 2,
                                   "decrypt": False})
        status, ov = self.get(f"/api/runs/{run_id}/overview")
        self.assertEqual(status, 200)
        self.assertEqual(ov["run"]["id"], run_id)
        self.assertEqual(ov["apps"][0]["label"], "小红书")
        status, headers, raw = self.request("GET", f"/api/runs/{run_id}/apps/com.xingin.xhs/detail.json"
                                                   f"?token={self.app.token}", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-disposition"],
                         f'attachment; filename="com.xingin.xhs-{run_id}.detail.json"')
        self.assertEqual(self.post("/api/stop", {})[0], 409)              # nothing to stop any more

    def test_a_run_in_progress_cannot_be_deleted(self):
        self.world.analysis_gate.clear()
        run_id = self.post("/api/start", self.START_PHONE)[1]["run"]
        self.wait_state("running")
        self.post("/api/stop", {})
        self.wait_state("analyzing")
        status, body = self.post(f"/api/runs/{run_id}/delete", {})
        self.assertEqual(status, 409)
        self.assertIn("还在进行", body["message"])
        self.world.analysis_gate.set()
        self.wait_state("done")
        self.assertEqual(self.post(f"/api/runs/{run_id}/delete", {})[0], 200)
        self.assertFalse((self.tmp / "runs" / run_id).exists())
        st = self.get("/api/status")[1]                    # the page is not sent to a run that is gone
        self.assertEqual((st["state"], st["run"]), ("idle", None))

    def test_timed_run_ends_by_itself(self):
        status, body = self.post("/api/start", dict(self.START_PHONE, seconds=1))
        self.assertEqual(status, 200)
        st = self.wait_state("done")
        self.assertEqual(st["seconds"], 1)
        self.assertEqual(self.world.calls[0], ("start", None, 301, False))

    def test_app_run(self):
        status, body = self.post("/api/start", {"scope": "app", "package": "com.xingin.xhs", "seconds": 1,
                                                "decrypt": True})
        self.assertEqual(status, 200)
        run_id = body["run"]
        self.assertTrue(run_id.startswith("com.xingin.xhs-"))
        st = self.wait_state("done", "error")
        self.assertEqual(st["state"], "done", st["message"])
        self.assertEqual(self.world.calls[0], ("start", "com.xingin.xhs", 301, True))
        names = [c[0] for c in self.world.calls if c[0] != "labels"]
        self.assertEqual(names, ["start", "stop", "analyze", "write_app_run"])
        self.assertTrue((self.tmp / "runs" / run_id / "report.html").is_file())
        # the app's name comes from the cache; the phone is asked only for names the cache lacks
        self.assertEqual([c for c in self.world.calls if c[0] == "labels"], [("labels", False, ["com.xingin.xhs"])])
        status, ov = self.get(f"/api/runs/{run_id}/overview")
        self.assertEqual((ov["run"]["scope"], len(ov["apps"]), ov["apps"][0]["label"]), ("app", 1, "小红书"))
        self.assertEqual(self.get("/api/runs")[1][0]["label"], "小红书")

    def test_refused_before_the_phone_is_touched(self):
        for body in ({"scope": "x", "seconds": None, "decrypt": False},
                     {"scope": "app", "package": None, "seconds": None, "decrypt": False},
                     {"scope": "app", "package": "no package", "seconds": None, "decrypt": False},
                     {"scope": "phone", "seconds": 0, "decrypt": False},
                     {"scope": "phone", "seconds": "60", "decrypt": False},
                     {"scope": "phone", "seconds": 3601, "decrypt": False},
                     {"scope": "phone", "seconds": None, "decrypt": "yes"},
                     ["phone"]):
            status, reply = self.post("/api/start", body)
            self.assertEqual(status, 400, body)
            self.assertTrue(reply["message"])
        status, _, _ = self.request("POST", "/api/start")       # no body
        self.assertEqual(status, 400)
        self.assertEqual(self.world.calls, [])
        self.assertEqual(self.get("/api/status")[1]["state"], "idle")

    def test_phone_not_ready(self):
        self.world.check_error = DeviceError(device.NO_DEVICE)
        status, body = self.post("/api/start", self.START_PHONE)
        self.assertEqual((status, body["message"]), (409, device.NO_DEVICE))
        self.world.check_error = None
        with mock.patch.object(device, "find_tshark", lambda path=None: None):
            status, body = self.post("/api/start", dict(self.START_PHONE, decrypt=True))
        self.assertEqual(status, 409)
        self.assertIn("Wireshark", body["message"])
        with mock.patch.object(device, "find_ecapture", lambda path=None: None):
            status, body = self.post("/api/start", dict(self.START_PHONE, decrypt=True))
        self.assertEqual(status, 409)
        self.assertIn("eCapture", body["message"])
        self.assertEqual(self.world.calls, [])
        self.assertEqual(self.get("/api/status")[1]["state"], "idle")

    def test_start_fails_on_the_phone(self):
        self.world.start_error = DeviceError("无法在手机上开始采集：手机上缺少采集脚本（推送没有完成）")
        self.world.stop_error = DeviceError("手机上没有这次采集的数据：采集在手机上还没有开始。")
        status, body = self.post("/api/start", self.START_PHONE)
        self.assertEqual(status, 200)
        st = self.wait_state("error")
        self.assertIn("缺少采集脚本", st["message"])
        self.assertEqual([c[0] for c in self.world.calls], ["start", "stop"])     # stop cleans the phone
        self.assertFalse((self.tmp / "runs" / body["run"]).exists())
        self.assertEqual(self.post("/api/start", self.START_PHONE)[0], 200)       # and a new start is possible

    def test_capture_left_on_the_phone(self):
        self.world.start_error = sys.modules["aw.collect"].CaptureLeft("手机上还有一次以前的采集")
        self.post("/api/start", self.START_PHONE)
        st = self.wait_state("error")
        self.assertIn("以前的采集", st["message"])
        self.assertEqual([c[0] for c in self.world.calls], ["start"])     # the earlier capture is left alone

    def test_unavailable_said_in_plain_words(self):
        self.world.unavailable = ["tcpdump", "ecapture"]
        self.post("/api/start", dict(self.START_PHONE, decrypt=True))
        st = self.wait_state("running")
        self.assertIn("抓包程序", st["message"])
        self.assertIn("这次不解密", st["message"])
        for word in ("TLS", "eCapture", "tcpdump"):
            self.assertNotIn(word, st["message"])

    def test_analysis_error_ends_in_error(self):
        sys.modules["aw.phonewide"].analyze_phone = mock.Mock(side_effect=RuntimeError("boom"))
        self.post("/api/start", dict(self.START_PHONE, seconds=1))
        with mock.patch("traceback.print_exc"):
            st = self.wait_state("error", "done")
        self.assertEqual(st["state"], "error")
        self.assertIn("boom", st["message"])
        self.assertIn("之后在“以前的观察”里打开它会再试一次", st["message"])


class RunsTest(ServerTest):
    def runs_dir(self, name):
        d = self.tmp / "runs" / name
        d.mkdir(parents=True)
        return d

    def test_listing(self):
        write_overview(self.runs_dir("phone-20261119-100000"), overview_of("phone-20261119-100000", "phone"))
        ov = overview_of("com.xingin.xhs-20261118-090000", "app", "com.xingin.xhs", LABELS)
        ov["run"]["start_time"] = "2026-11-18 09:00:00"
        write_overview(self.runs_dir("com.xingin.xhs-20261118-090000"), ov)
        old = self.runs_dir("com.ss.android.ugc.aweme-20261117-210000")      # analysed before v0.4
        (old / "meta.json").write_text(json.dumps({
            "format": 1, "package": "com.ss.android.ugc.aweme", "uid": 10200, "app_id": "u0a200",
            "start_time": "2026-11-17 21:00:00", "end_time": "2026-11-17 21:02:30", "decrypt": "keylog"}))
        copy = self.runs_dir("fixture-copy")                                 # result.json only
        (copy / "result.json").write_text(json.dumps({"meta": {
            "package": "com.xingin.xhs", "start_time": "2026-11-16 08:00:00", "end_time": "2026-11-16 08:01:00",
            "duration_s": 60}}))
        self.runs_dir("empty")
        (self.runs_dir("broken") / "overview.json").write_text("{not json")
        (self.runs_dir("half") / "meta.json").write_text(json.dumps({"package": "com.x.y"}))

        status, runs = self.get("/api/runs")
        self.assertEqual(status, 200)
        self.assertEqual([r["id"] for r in runs], ["phone-20261119-100000", "com.xingin.xhs-20261118-090000",
                                                   "com.ss.android.ugc.aweme-20261117-210000", "fixture-copy"])
        for r in runs:
            self.assertEqual(set(r), {"id", "scope", "package", "label", "start_time", "seconds", "apps", "decrypt"})
        self.assertEqual((runs[1]["label"], runs[1]["apps"]), ("小红书", 1))
        self.assertEqual(runs[2], {"id": "com.ss.android.ugc.aweme-20261117-210000", "scope": "app",
                                   "package": "com.ss.android.ugc.aweme", "label": None,
                                   "start_time": "2026-11-17 21:00:00", "seconds": 150, "apps": 1, "decrypt": True})
        self.assertEqual(runs[3]["seconds"], 60)

    def test_older_runs_get_an_overview_when_opened(self):
        old = self.runs_dir("com.xingin.xhs-20261117-210000")
        (old / "meta.json").write_text(json.dumps({
            "format": 1, "package": "com.xingin.xhs", "uid": 10378, "app_id": "u0a378",
            "start_time": "2026-11-17 21:00:00", "end_time": "2026-11-17 21:02:30"}))
        status, ov = self.get("/api/runs/com.xingin.xhs-20261117-210000/overview")
        self.assertEqual(status, 200)
        self.assertEqual(ov["run"]["scope"], "app")
        self.assertEqual([c[0] for c in self.world.calls], ["analyze", "write_app_run", "labels"])
        self.assertEqual(ov["apps"][0]["label"], "小红书")
        self.assertTrue((old / "overview.json").is_file() and (old / "report.html").is_file())
        self.get("/api/runs/com.xingin.xhs-20261117-210000/overview")
        self.assertEqual(len(self.world.calls), 3)       # made once

        phone = self.runs_dir("phone-20261117-200000")
        (phone / "meta.json").write_text(json.dumps({
            "format": 1, "scope": "phone", "package": None, "uid": None,
            "start_time": "2026-11-17 20:00:00", "end_time": "2026-11-17 20:05:00"}))
        status, ov = self.get("/api/runs/phone-20261117-200000/overview")
        self.assertEqual((status, len(ov["apps"])), (200, 2))
        self.assertEqual(self.world.calls[-2:], [("labels", False, sorted(p["package"] for p in PACKAGES)),
                                                 ("analyze_phone", {p["package"]: LABELS.get(p["package"])
                                                                    for p in PACKAGES})])

        copy = self.runs_dir("fixture-copy")
        (copy / "result.json").write_text(json.dumps({"meta": {"package": "com.xingin.xhs"}}))
        status, ov = self.get("/api/runs/fixture-copy/overview")
        self.assertEqual(status, 200)
        self.assertEqual(self.world.calls[-2], ("write_app_run", "fixture-copy"))

    def test_unknown_runs(self):
        self.runs_dir("empty")
        for run_id in ("nope", "empty", "..", "%2E%2E", ".hidden"):
            status, body = self.get(f"/api/runs/{run_id}/overview")
            self.assertEqual(status, 404, run_id)
            self.assertTrue(body["message"])

    def test_delete(self):
        kept = self.runs_dir("phone-20261119-100000")
        write_overview(kept, overview_of("phone-20261119-100000", "phone"))
        gone = self.runs_dir("com.xingin.xhs-20261118-090000")
        write_overview(gone, overview_of("com.xingin.xhs-20261118-090000", "app", "com.xingin.xhs", LABELS))
        (gone / "net.pcap").write_bytes(b"captured")
        outside = self.tmp / "other"
        outside.mkdir()

        self.assertEqual(self.request("POST", "/api/runs/com.xingin.xhs-20261118-090000/delete", {}, token=None)[0], 403)
        self.assertTrue(gone.is_dir())
        status, body = self.post("/api/runs/com.xingin.xhs-20261118-090000/delete", {})
        self.assertEqual((status, body), (200, {"deleted": "com.xingin.xhs-20261118-090000"}))
        self.assertFalse(gone.exists())
        self.assertEqual([r["id"] for r in self.get("/api/runs")[1]], ["phone-20261119-100000"])
        self.assertEqual(self.get("/api/runs/com.xingin.xhs-20261118-090000/overview")[0], 404)

        for run_id in ("com.xingin.xhs-20261118-090000", "nope", "..", "%2E%2E", "..%2Fother", ".hidden"):
            status, body = self.post(f"/api/runs/{run_id}/delete", {})
            self.assertEqual(status, 404, run_id)
        self.assertEqual(self.request("GET", "/api/runs/phone-20261119-100000/delete")[0], 404)   # POST only
        self.assertTrue(kept.is_dir() and outside.is_dir() and (self.tmp / "runs").is_dir())

    def test_analysis_failure_is_a_message(self):
        old = self.runs_dir("com.xingin.xhs-20261117-210000")
        (old / "meta.json").write_text(json.dumps({"package": "com.xingin.xhs", "start_time": "x", "end_time": "y"}))
        sys.modules["aw.analyze"].analyze = mock.Mock(side_effect=ValueError("bad data"))
        with mock.patch("traceback.print_exc"):
            status, body = self.get("/api/runs/com.xingin.xhs-20261117-210000/overview")
        self.assertEqual(status, 500)
        self.assertIn("bad data", body["message"])


if __name__ == "__main__":
    unittest.main()
