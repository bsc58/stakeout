"""aw/overview.py (docs/CONTRACT_PHONE.md: "The overview", "Categories", "Ranking", "aw/overview.py") and
aw.exchange.sensitive_kind. Synthetic facts for the texts, levels and score; fixtures/live_xhs_keylog_1119
for the one-app overview, its downloads and the rule that the overview holds no captured value. Values from
the fixture are read at run time and never written here."""

import json
import re
import shutil
import tempfile
import unittest
from collections import Counter
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qsl

from aw import analyze, device, overview, parse_har, report
from aw.exchange import is_sensitive, sensitive_kind
from aw.parse_appops import OP_INFO

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "live_xhs_keylog_1119"
TSHARK = device.find_tshark()


def ev(category, time, what, code, front, denied=False, count=1, at_least=False):
    return {"category": category, "time": time, "what": what, "code": code, "front": front, "denied": denied,
            "count": count, "at_least": at_least}


def facts(events=(), endpoints=(), requests=(), not_decrypted=0):
    return {"package": "com.example.app", "uid": 10123, "label": "示例", "third_party": True,
            "events": list(events),
            "network": {"endpoints": list(endpoints), "connections": sum(e["connections"] for e in endpoints),
                        "bytes": sum(e["bytes"] for e in endpoints), "not_decrypted": not_decrypted},
            "requests": list(requests)}


def request(host="api.example.com", headers=(), query=(), body=None, front=True, time="2026-11-19 10:00:01.000"):
    return {"source": "keylog", "time": time, "protocol": "h2", "method": "POST", "scheme": "https", "host": host,
            "path": "/v1/x", "query": [list(q) for q in query],
            "request": {"headers": [list(h) for h in headers], "body": body, "complete": True},
            "response": {"status": 200, "headers": [["content-type", "application/json"]],
                         "body": {"size": 2, "sha256": "0" * 64, "encoding": None, "encoding_detected": False,
                                  "decoded": True, "kind": "json", "text": "{}", "truncated": False,
                                  "preview_hex": None},
                         "complete": True},
            "pid": None, "thread": None, "partial": [], "connection_host_tail": None, "connection": 3,
            "server": "192.0.2.10:443", "front": front}


def text_body(text, kind="json"):
    return {"size": len(text.encode()), "sha256": "1" * 64, "encoding": None, "encoding_detected": False,
            "decoded": True, "kind": kind, "text": text, "truncated": False, "preview_hex": None}


def bar(app, key):
    return next(b for b in app["bars"] if b["key"] == key)


def section(app, key):
    return next(s for s in app["sections"] if s["key"] == key)


class SensitiveKind(unittest.TestCase):
    NAMES = ["Cookie", "set-cookie", "Authorization", "Proxy-Authorization", "x-auth-token", "sessionid", "sid",
             "id_token", "api_key", "password", "sign", "x-sign", "signature", "deviceId", "device_id", "did", "gid",
             "uid", "user_id", "userId", "openid", "imei", "oaid", "android_id", "mac", "serial", "x-forwarded-for",
             "xhs-real-ip", "ip", "ipv6", "content-type", "user-agent", "accept", "path", "lat", "idea", "valid",
             "sidebar", "tokenizer", "x-b3-traceid", "geo", ""]

    def test_agrees_with_is_sensitive(self):
        for name in self.NAMES:
            with self.subTest(name):
                self.assertEqual(sensitive_kind(name) is not None, is_sensitive(name))

    def test_groups(self):
        self.assertEqual(sensitive_kind("Cookie"), "credential")
        self.assertEqual(sensitive_kind("x-auth-token"), "credential")
        self.assertEqual(sensitive_kind("x-sign"), "signature")
        self.assertEqual(sensitive_kind("deviceId"), "identity")
        self.assertEqual(sensitive_kind("user_id"), "identity")
        self.assertEqual(sensitive_kind("x-forwarded-for"), "address")
        self.assertIsNone(sensitive_kind("content-type"))


class FieldKinds(unittest.TestCase):
    def test_last_words_decide(self):
        cases = {"deviceId": "device", "x-legacy-did": "device", "user_id": "account", "context_userId": "account",
                 "uid": "account", "Cookie": "credential", "id_token": "credential", "x_page_session_id": "credential",
                 "context_ip": "address", "lat": "location", "user_geo": "location",
                 "context_ip_type": None, "enable_location_permission": None, "x-sign": None,
                 "content-type": None, "access_token_expire": None}
        for name, kind in cases.items():
            with self.subTest(name):
                self.assertEqual(overview._kind_of(name), kind)


class Categories(unittest.TestCase):
    def test_table(self):
        weights = {k: w for k, _, w in overview.CATEGORIES}
        self.assertEqual([k for k, _, _ in overview.CATEGORIES],
                         ["location", "camera", "microphone", "contacts", "sms", "call_log", "calendar", "phone_state",
                          "photos", "clipboard", "installed_apps", "other_app_data", "sensors", "background_start",
                          "network", "sent_data", "other"])
        self.assertEqual({k for k, w in weights.items() if w == 3},
                         {"location", "camera", "microphone", "contacts", "sms", "call_log", "clipboard",
                          "installed_apps", "other_app_data", "photos"})
        self.assertEqual({k for k, w in weights.items() if w == 1}, {"background_start", "network", "other"})

    def test_every_known_operation(self):
        keys = {k for k, _, _ in overview.CATEGORIES}
        for op in OP_INFO:
            self.assertIn(overview.category_of(op), keys)
        expected = {"FINE_LOCATION": "location", "GPS": "location", "WIFI_SCAN": "location", "CAMERA": "camera",
                    "RECORD_AUDIO": "microphone", "READ_CONTACTS": "contacts", "READ_SMS": "sms",
                    "READ_CALL_LOG": "call_log", "READ_CALENDAR": "calendar", "READ_PHONE_STATE": "phone_state",
                    "READ_DEVICE_IDENTIFIERS": "phone_state", "READ_MEDIA_IMAGES": "photos",
                    "READ_CLIPBOARD": "clipboard", "GET_INSTALLED_APPS": "installed_apps",
                    "ACTIVITY_RECOGNITION": "sensors", "DIRECTION_SENSORS": "sensors", "WAKE_LOCK": "other",
                    "FINE_LOCATION_SOURCE": "location", "NOT_AN_OPERATION": "other"}
        for op, key in expected.items():
            self.assertEqual(overview.category_of(op), key, op)


class BuildApp(unittest.TestCase):
    def test_counts_background_and_at_least(self):
        app = overview.build_app(facts([
            ev("location", "2026-11-19 10:00:01", "精确位置", "FINE_LOCATION", True, at_least=True),
            ev("location", "2026-11-19 10:00:02", "GPS 定位", "GPS", True, at_least=True),
            ev("location", "2026-11-19 10:05:00", "精确位置", "FINE_LOCATION", False, at_least=True)]))
        b = bar(app, "location")
        self.assertEqual((b["text"], b["count"], b["background"], b["denied"], b["level"]),
                         ("定位 至少 3 次", 3, 1, 0, "high"))
        s = section(app, "location")
        self.assertEqual(s["summary"], "至少用了 3 次定位（精确位置 2 次、GPS 定位 1 次），其中至少 1 次是在你没打开它的时候。"
                                       "系统每次定位往往会同时记下好几项（例如精确位置和 GPS 定位），这里每一项分开计数。")
        self.assertEqual(s["title"], "定位")
        self.assertEqual(s["columns"], ["时间", "做了什么", "当时"])
        self.assertEqual(s["rows"][2], ["10:05:00", "精确位置", "你没打开它"])
        self.assertEqual(app["score"], 3 + 9)

    def test_in_front_and_refused(self):
        app = overview.build_app(facts([
            ev("camera", "2026-11-19 10:00:01", "相机", "CAMERA", True),
            ev("camera", "2026-11-19 10:00:09", "相机", "CAMERA", True),
            ev("sensors", "2026-11-19 10:00:03", "方向传感器", "DIRECTION_SENSORS", True, denied=True),
            ev("clipboard", "2026-11-19 10:00:04", "读取剪贴板", "READ_CLIPBOARD", False, denied=True),
            ev("clipboard", "2026-11-19 10:00:05", "读取剪贴板", "READ_CLIPBOARD", True)]))
        self.assertEqual(section(app, "camera")["summary"], "用了 2 次相机，都是在你正在用它的时候。")
        self.assertEqual(bar(app, "camera")["level"], "medium")
        self.assertEqual(section(app, "sensors")["summary"], "想用 1 次传感器（方向传感器），被系统拒绝了，是在你正在用它的时候。")
        self.assertEqual((bar(app, "sensors")["denied"], bar(app, "sensors")["level"]), (1, "low"))
        clip = section(app, "clipboard")
        self.assertEqual(clip["summary"], "用了 2 次剪贴板（读取剪贴板），其中 1 次被系统拒绝，1 次是在你没打开它的时候。"
                                          "被系统拒绝的那几次，它没有拿到剪贴板里的内容。")
        self.assertEqual(clip["columns"], ["时间", "做了什么", "当时", "结果"])
        self.assertEqual([r[3] for r in clip["rows"]], ["被系统拒绝", "允许"])
        # a refused attempt counts as seen: clipboard 3 + 9, camera 3, sensors 2
        self.assertEqual(app["score"], 12 + 3 + 2)
        self.assertEqual([b["key"] for b in app["bars"]], ["clipboard", "camera", "sensors"])
        self.assertEqual([s["key"] for s in app["sections"]], ["clipboard", "camera", "sensors"])

    def test_unknown_front_and_weight_two(self):
        app = overview.build_app(facts([
            ev("phone_state", "2026-11-19 10:00:01", "读取电话状态和身份信息", "READ_PHONE_STATE", False),
            ev("other_app_data", None, "读写 com.other.app 的数据（读 4 次、写 0 次）", "/data/data/com.other.app/x",
               None, count=4, at_least=True)]))
        self.assertEqual(bar(app, "phone_state")["level"], "medium")
        data = bar(app, "other_app_data")
        self.assertEqual((data["text"], data["count"], data["level"]), ("访问其他应用的数据 至少 1 次", 1, "medium"))
        self.assertIn("无法判断当时你是不是正在用它。", section(app, "other_app_data")["summary"])
        mixed = overview.build_app(facts([ev("camera", "2026-11-19 10:00:01", "相机", "CAMERA", True),
                                          ev("camera", None, "相机", "CAMERA", None)]))
        self.assertEqual(section(mixed, "camera")["summary"],
                         "用了 2 次相机，其中 1 次是在你正在用它的时候。有 1 次无法判断当时你是不是正在用它。")
        self.assertEqual(app["score"], (2 + 6) * 0 + 2 * 3 + 3)   # phone_state only while not in front; data: unknown = seen

    def test_things_and_operations_in_one_category(self):
        evs = [ev("installed_apps", f"2026-11-19 10:00:0{i}", f"读取 com.app{i} 的安装包", f"com.app{i} base.apk",
                  i != 2, count=5, at_least=True) for i in range(3)]
        evs.append(ev("installed_apps", "2026-11-19 10:00:08", "读取应用使用情况", "GET_USAGE_STATS", True, denied=True,
                      count=2, at_least=True))
        app = overview.build_app(facts(evs))
        b = bar(app, "installed_apps")
        self.assertEqual((b["text"], b["count"], b["background"], b["denied"]), ("查看你装了哪些应用 至少 5 次", 5, 1, 2))
        s = section(app, "installed_apps")["summary"]
        self.assertTrue(s.startswith("至少读取了 3 个其他应用的安装包"), s)
        self.assertIn("其中 1 个是在你没打开它的时候第一次读取的。", s)
        self.assertIn("至少想查询 2 次已安装或常用的应用（读取应用使用情况），都被系统拒绝了", s)

    def test_rows_are_cut_at_fifty_and_detail_has_all(self):
        evs = [ev("other", f"2026-11-19 10:{i // 60:02d}:{i % 60:02d}", "修改系统设置", "WRITE_SETTINGS", True)
               for i in range(60)]
        f = facts(evs)
        s = section(overview.build_app(f), "other")
        self.assertEqual((len(s["rows"]), s["more"]), (50, 10))
        d = next(s for s in overview.detail(f)["sections"] if s["key"] == "other")
        self.assertEqual(len(d["rows"]), 60)
        self.assertEqual(d["columns"][-1], "技术名称")
        self.assertEqual(d["rows"][0][-1], "WRITE_SETTINGS")
        self.assertNotIn("WRITE_SETTINGS", json.dumps(overview.build_app(f), ensure_ascii=False))

    def test_routine_operations_are_left_out(self):
        evs = [ev("other", "2026-11-19 10:00:01", "阻止手机休眠", "WAKE_LOCK", False),
               ev("other", "2026-11-19 10:00:02", "振动", "VIBRATE", False),
               ev("other", "2026-11-19 10:00:03", "调节媒体音量", "AUDIO_MEDIA_VOLUME", False)]
        self.assertEqual(overview.build_app(facts(evs))["bars"], [])
        d = next(s for s in overview.detail(facts(evs))["sections"] if s["key"] == "other")
        self.assertEqual(len(d["rows"]), 3)

    def test_network(self):
        eps = [{"host": "a.example.com", "address": "192.0.2.1:443", "connections": 2, "bytes": 3 * 1024 * 1024,
                "front": True, "background": False},
               {"host": "a.example.com", "address": "192.0.2.2:443", "connections": 1, "bytes": 1024,
                "front": True, "background": True},
               {"host": None, "address": "198.51.100.7:443", "connections": 1, "bytes": 10,
                "front": False, "background": True}]
        app = overview.build_app(facts(endpoints=eps, not_decrypted=2))
        b = bar(app, "network")
        self.assertEqual((b["text"], b["count"], b["background"], b["level"]), ("联网 2 个服务器", 2, 2, "low"))
        s = section(app, "network")
        # both servers were connected while it was not in front, one of them also while it was
        self.assertEqual(s["summary"], "连了 2 个服务器（其中 1 个只知道地址，不知道域名），收发约 3.0 MB，"
                                       "在你没打开它的时候也都连着。它有 2 个加密连接的内容没能解开。")
        self.assertEqual(s["rows"], [["a.example.com", "约 3.0 MB", "两种时候都有"],
                                     ["不知道域名的服务器（1 个）", "10 字节", "你没打开它"]])
        self.assertNotIn("198.51.100.7", json.dumps(app))
        self.assertEqual(app["score"], 1 + 3)

    def test_sent_data(self):
        reqs = [request(headers=[[":authority", "api.example.com"], ["x-device-id", "d3v1c3-0000-secret"],
                                 ["cookie", "a=b"]],
                        query=[["lat", "45.5017"]], body=text_body('{"user_id": "u-998877", "n": 1}'), front=False),
                request(host="cdn.example.com", headers=[["accept", "*/*"]])]
        app = overview.build_app(facts(requests=reqs))
        b = bar(app, "sent_data")
        self.assertEqual((b["text"], b["count"], b["background"], b["level"]),
                         ("发出去的信息 2 次，含设备标识、账号标识等字段", 2, 1, "medium"))
        s = section(app, "sent_data")
        self.assertEqual(s["summary"], "解密后看到它发出了 2 个请求，发往 2 个服务器，其中 1 个是在你没打开它的时候发的。"
                                       "按字段名来看，1 个请求里有设备标识类的字段，1 个请求里有账号标识类的字段，"
                                       "1 个请求里有位置类的字段，1 个请求里有登录凭据类的字段。"
                                       "每个请求的完整内容可以在下面下载。")
        self.assertEqual(s["rows"][0], ["api.example.com", 1, 1, "设备标识、账号标识、位置、登录凭据"])
        page = json.dumps(app, ensure_ascii=False)
        for value in ("d3v1c3-0000-secret", "45.5017", "u-998877", "/v1/x", "192.0.2.10"):
            self.assertNotIn(value, page)
        self.assertEqual(app["score"], 2 + 6)

    def test_sent_data_without_kinds_weighs_one(self):
        app = overview.build_app(facts(requests=[request(headers=[["accept", "*/*"]], front=False)]))
        self.assertEqual((bar(app, "sent_data")["level"], app["score"]), ("low", 3))
        self.assertIn("没有设备标识、账号标识、位置、手机的网络地址或登录凭据类的字段", section(app, "sent_data")["summary"])

    def test_background_start(self):
        app = overview.build_app(facts([
            ev("background_start", "2026-11-19 10:00:01", "系统启动了它的进程 com.example.app:push，起因：广播",
               "pid 1; com.example.app:push", False),
            ev("background_start", "2026-11-19 10:00:09", "它运行了程序 ping", "pid 2; ping -c 1 x", False,
               at_least=True)]))
        self.assertEqual(section(app, "background_start")["summary"], "它的进程至少启动了 2 次，都是在你没打开它的时候。")
        self.assertEqual((bar(app, "background_start")["level"], app["score"]), ("low", 3))

    def test_empty_and_shape(self):
        app = overview.build_app(facts())
        self.assertEqual(app, {"package": "com.example.app", "uid": 10123, "label": "示例", "third_party": True,
                               "score": 0, "bars": [], "sections": [], "downloads": []})


class Rank(unittest.TestCase):
    def test_order(self):
        def app(package, score, counts):
            return {"package": package, "score": score, "bars": [{"count": c} for c in counts]}
        apps = [app("c", 5, [1]), app("b", 9, [1]), app("a", 5, [1]), app("d", 5, [2])]
        self.assertEqual([a["package"] for a in overview.rank(apps)], ["b", "d", "a", "c"])


class Har(unittest.TestCase):
    def test_entries(self):
        x = request(headers=[[":method", "POST"], ["content-type", "application/json"]],
                    query=[["q", "a b"], ["k", "中+"]], body=text_body('{"a": 1}'))
        y = dict(request(host="b.example.com"), response=None, partial=["response_not_matched"],
                 time="2026-11-19 10:00:00.500")
        doc = overview.har([x, y], utc_offset="-0500")
        self.assertEqual(doc["log"]["version"], "1.2")
        self.assertEqual(doc["log"]["creator"]["name"], "Stakeout")
        first, second = doc["log"]["entries"]
        self.assertEqual(first["startedDateTime"], "2026-11-19T10:00:00.500-05:00")
        self.assertEqual(first["response"]["status"], 0)
        self.assertEqual(first["_stakeout"]["partial"], ["response_not_matched"])
        self.assertEqual(second["request"]["url"], "https://api.example.com/v1/x?q=a%20b&k=%E4%B8%AD%2B")
        self.assertEqual(second["request"]["httpVersion"], "HTTP/2")
        self.assertEqual(second["request"]["postData"], {"mimeType": "application/json", "text": '{"a": 1}'})
        self.assertEqual(second["request"]["queryString"], [{"name": "q", "value": "a b"}, {"name": "k", "value": "中+"}])
        self.assertEqual(second["response"]["content"], {"size": 2, "mimeType": "application/json", "text": "{}"})

    def test_parse_har_reads_it_back(self):
        x = request(query=[["q", "a b"]], body=text_body("a=1&b=2", "form"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.har"
            path.write_text(json.dumps(overview.har([x], "-0500")), encoding="utf-8")
            back = parse_har.parse_har(path, utc_offset="-0500")["exchanges"]
        self.assertEqual(len(back), 1)
        self.assertEqual((back[0]["time"], back[0]["host"], back[0]["path"], back[0]["query"], back[0]["method"]),
                         (x["time"], x["host"], x["path"], x["query"], x["method"]))
        self.assertEqual(back[0]["response"]["status"], 200)


class WriteDownloads(unittest.TestCase):
    def test_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "meta.json").write_text(json.dumps({"utc_offset": "+0800"}), encoding="utf-8")
            downloads = overview.write_downloads(run, "com.example.app", {"a": 1}, [request()])
            self.assertEqual([d["kind"] for d in downloads], ["requests.har", "detail.json"])
            for d in downloads:
                path = run / "apps" / "com.example.app" / d["kind"]
                self.assertEqual(path.stat().st_size, d["bytes"])
                self.assertTrue(d["private"])
                self.assertTrue(d["title"])
            doc = json.loads((run / "apps" / "com.example.app" / "requests.har").read_text(encoding="utf-8"))
            self.assertTrue(doc["log"]["entries"][0]["startedDateTime"].endswith("+08:00"))
            self.assertEqual([d["kind"] for d in overview.write_downloads(run, "com.other", {}, [])], ["detail.json"])


def _strings(obj):
    """The string values in obj (its keys are not shown on the page)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _captured_values(exchanges):
    """Header, query and body values, JSON string values and form values, and paths, of 6 or more characters."""
    out = set()

    def add(v):
        if isinstance(v, str) and len(v.strip()) >= 6:
            out.add(v.strip())

    for x in exchanges:
        add(x.get("path"))
        for _, v in x.get("query") or []:
            add(v)
        for side in (x.get("request"), x.get("response")):
            for _, v in (side or {}).get("headers") or []:
                add(v)
            body = (side or {}).get("body") or {}
            text = body.get("text")
            if text:
                add(text)
                for m in re.finditer(r':\s*"((?:[^"\\]|\\.)*)"', text):
                    add(m.group(1))
                if body.get("kind") == "form":
                    for _, v in parse_qsl(text, keep_blank_values=True):
                        add(v)
    return out


@unittest.skipUnless(FIXTURE.is_dir() and TSHARK, "fixture or tshark not present")
class OneAppRun(unittest.TestCase):
    """write_app_run on the result of `analyze fixtures/live_xhs_keylog_1119`."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = Path(cls.tmp.name) / "live-run"
        cls.result = analyze.analyze(FIXTURE, out_dir=cls.run_dir)
        (cls.run_dir / "report.html").write_text(report.render(cls.result), encoding="utf-8")
        shutil.copyfile(FIXTURE / "package_dump.txt", cls.run_dir / "package_dump.txt")
        cls.ov = overview.write_app_run(cls.result, cls.run_dir)
        cls.app = cls.ov["apps"][0]
        cls.page = "\n".join(_strings(cls.ov))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_run(self):
        meta = self.result["meta"]
        self.assertEqual(self.ov["format"], 1)
        self.assertEqual(self.ov["run"], {"id": "live-run", "scope": "app", "package": "com.xingin.xhs",
                                          "device": "OnePlus PKX110 · Android 15", "start_time": meta["start_time"],
                                          "end_time": meta["end_time"], "seconds": meta["duration_s"], "net": True,
                                          "decrypt": True})
        self.assertEqual(len(self.ov["apps"]), 1)
        self.assertEqual((self.app["package"], self.app["uid"], self.app["third_party"]), ("com.xingin.xhs", 10378, True))
        self.assertTrue(self.ov["limits"])

    def test_written_files(self):
        on_disk = json.loads((self.run_dir / "overview.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk, self.ov)
        self.assertEqual([d["kind"] for d in self.app["downloads"]], ["requests.har", "detail.json", "report.html"])
        for d in self.app["downloads"]:
            self.assertEqual((self.run_dir / "apps" / "com.xingin.xhs" / d["kind"]).stat().st_size, d["bytes"])
        self.assertEqual(overview.from_app_result(self.result, self.run_dir), self.ov)

    def test_counts_follow_the_result(self):
        files, clip = self.result["files"], self.result["clipboard"]
        apks = files["other_app_apks"]
        b = bar(self.app, "installed_apps")
        self.assertEqual((b["count"], b["background"]), (len(apks), sum(1 for a in apks if a["background"])))
        self.assertEqual(section(self.app, "installed_apps")["more"], len(apks) - 50)
        b = bar(self.app, "clipboard")
        self.assertEqual((b["count"], b["denied"], b["background"]),
                         (len(clip["events"]), clip["blocked"], sum(1 for e in clip["events"] if e["background"])))
        exchanges = [x for x in self.result["decrypted"]["exchanges"] if x["source"] != "har"]
        self.assertEqual(bar(self.app, "sent_data")["count"], len(exchanges))
        eps = self.result["network"]["endpoints"]
        self.assertEqual(bar(self.app, "network")["count"], len({e["host"] or (e["ip"], e["port"]) for e in eps}))
        self.assertEqual(bar(self.app, "other_app_data")["count"], len(files["other_app_data"]))

    def test_permission_occurrences_match_the_result(self):
        f = overview._facts_of_result(self.result, self.run_dir)
        per_op = Counter((e["code"], e["denied"]) for e in f["events"] if overview._is_op(e["code"])
                         and e["category"] != "clipboard")
        for u in self.result["permissions"]["used"]:
            if u["op"] in analyze.CLIP_OPS or u["count"] is None:
                continue
            self.assertEqual(per_op[(u["op"], u["kind"] == "reject")], u["count"], u["op"])
        location_ops = sum(u["count"] for u in self.result["permissions"]["used"]
                           if overview.category_of(u["op"]) == "location")
        self.assertEqual(bar(self.app, "location")["count"], location_ops)

    def test_front_time_matches_analyze(self):
        front = overview._Front(self.result["timeline"])
        end = overview._dt(self.result["meta"]["end_time"])
        times = front.times + [min(front.times[-1] + timedelta(seconds=1), end)]   # the last block lasts 1 s
        top = sum((times[i + 1] - t).total_seconds() for i, t in enumerate(front.times) if front.top[i])
        self.assertLessEqual(abs(top - self.result["background"]["seconds_top"]), 1)

    def test_score(self):
        score = 0
        for b in self.app["bars"]:
            weight = overview.WEIGHT[b["key"]]
            if b["key"] == "sent_data" and "含" not in b["text"]:
                weight = 1
            score += weight * ((1 if b["count"] > b["background"] else 0) + 3 * (1 if b["background"] else 0))
        self.assertEqual(self.app["score"], score)
        self.assertEqual([b["key"] for b in self.app["bars"]], [s["key"] for s in self.app["sections"]])
        levels = [b["level"] for b in self.app["bars"]]
        self.assertEqual(levels, sorted(levels, key=["high", "medium", "low"].index))

    def test_no_captured_value(self):
        exchanges = self.result["decrypted"]["exchanges"]
        # Names the page may show (host names, package names, the phone's model) can also be sent as values;
        # a value found inside one of them is not counted.
        allowed = [h for h in [x.get("host") for x in exchanges] + [e.get("host") for e in
                   self.result["network"]["endpoints"]] if h] + [self.ov["run"]["device"], self.app["package"]]
        allowed += [a["package"] for a in self.result["files"]["other_app_apks"] + self.result["files"]["other_app_data"]]
        allowed = [a.lower() for a in allowed]
        values = {v for v in _captured_values(exchanges) if not any(v.lower() in a for a in allowed)}
        self.assertGreater(len(values), 1000)
        found = sorted(v for v in values if v in self.page)
        self.assertEqual(len(found), 0, f"{len(found)} captured values on the page")
        addresses = {c[k].rsplit(":", 1)[0].strip("[]") for c in self.result["decrypted"]["keylog"]["connections"]
                     for k in ("client", "server")}
        addresses |= {e["ip"] for e in self.result["network"]["endpoints"]}
        self.assertGreater(len(addresses), 10)
        self.assertEqual(sum(1 for a in addresses if a in self.page), 0)

    def test_plain_words(self):
        for word in ("uid", "pid", "HTTP/2", "TLS", "ClientHello", "app_process", "topResumedActivity"):
            self.assertFalse(re.search(rf"(?<![A-Za-z]){re.escape(word)}(?![A-Za-z])", self.page), word)
        self.assertFalse(re.search(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b", self.page), "an operation code is on the page")

    def test_har_download(self):
        path = self.run_dir / "apps" / "com.xingin.xhs" / "requests.har"
        back = parse_har.parse_har(path, utc_offset=self.result["meta"]["utc_offset"])
        exchanges = [x for x in self.result["decrypted"]["exchanges"] if x["source"] != "har"]
        self.assertEqual(back["entries"], len(exchanges))
        self.assertEqual(back["skipped"], 0)

        def key(x):
            return (x["time"], x["method"], x["host"], x["path"], tuple(map(tuple, x["query"])),
                    (x["response"] or {}).get("status"))
        self.assertEqual(Counter(key(x) for x in back["exchanges"]), Counter(key(x) for x in exchanges))

    def test_detail_download(self):
        doc = json.loads((self.run_dir / "apps" / "com.xingin.xhs" / "detail.json").read_text(encoding="utf-8"))
        rows = {s["key"]: len(s["rows"]) for s in doc["sections"]}
        self.assertEqual(rows["installed_apps"], len(self.result["files"]["other_app_apks"]))
        self.assertEqual(rows["sent_data"], bar(self.app, "sent_data")["count"])
        self.assertEqual(len(doc["network"]["endpoints"]), len(self.result["network"]["endpoints"]))


if __name__ == "__main__":
    unittest.main()
