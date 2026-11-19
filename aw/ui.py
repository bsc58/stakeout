"""The local web page: an HTTP server on 127.0.0.1 that starts captures on the phone, runs them in a
thread, and serves the overviews and downloads of this and earlier runs (docs/CONTRACT_PHONE.md,
"aw/ui.py, aw/ui_static/").

Two checks guard every request, because the server can start captures and serves private files, and
any web page the user has open can make the browser send requests to localhost: the Host header must
name this server (against DNS rebinding), and every /api/ request must carry the token made at start
(header X-Stakeout-Token; download links carry it as the query parameter `token`).

The other modules (aw.collect, aw.labels, aw.phonewide, aw.overview, aw.analyze, aw.report) are
imported where they are used, through _aw().
"""
import importlib
import json
import secrets
import shutil
import sys
import threading
import time
import traceback
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import device

STATIC_DIR = Path(__file__).resolve().parent / "ui_static"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8")}
DOWNLOAD_TYPES = {"requests.har": "application/json", "detail.json": "application/json",
                  "report.html": "text/html; charset=utf-8"}
TOKEN_HEADER = "X-Stakeout-Token"
BUSY = ("starting", "running", "stopping", "analyzing")
MAX_BODY = 10_000
# The page loads its own three files and nothing else; it may not be framed by another page.
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

# aw_ctl.sh `WARN unavailable <code>` in the page's plain words (collect.UNAVAILABLE_ZH is the CLI's).
UNAVAILABLE_PAGE = {
    "tcpdump": "手机上没有抓包程序，这次只能看到应用连了哪些服务器的一部分，看不到流量大小。",
    "f2fs_events": "手机系统不支持跟踪文件读写，这次看不到应用读了哪些文件。",
    "trace_filter": "手机系统不支持跟踪文件读写，这次看不到应用读了哪些文件。",
    "ecapture": "解密没能在手机上启动，这次不解密网络内容，其他照常观察。",
}
RUNNING_NOTE = ("这个应用在开始前已经打开着，它之前建立的连接解不开。想看完整：在手机上把它彻底关掉，"
                "再重新打开。")
NO_TSHARK = "解密需要电脑上装有 Wireshark：请从 wireshark.org 下载安装，或者关掉解密再开始。"
NO_ECAPTURE = ("解密用的手机端程序（eCapture）不在电脑上：请把它放在 {path}，或者关掉解密再开始。")


def _aw(name):
    return importlib.import_module(f"aw.{name}")


class Refused(Exception):
    """A request that cannot be done now: HTTP status and one plain sentence."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _safe_name(name) -> bool:
    """A single path component (run id, package name): nothing that leaves its directory."""
    return bool(name) and name not in (".", "..") and "/" not in name and "\\" not in name \
        and not name.startswith(".")


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _seconds_between(start, end):
    try:
        return round((datetime.strptime(end[:19], "%Y-%m-%d %H:%M:%S")
                      - datetime.strptime(start[:19], "%Y-%m-%d %H:%M:%S")).total_seconds())
    except (TypeError, ValueError):
        return None


def _meta_entry(name, meta):
    scope = meta.get("scope") or "app"
    if not (meta.get("start_time") and meta.get("end_time") and (scope == "phone" or meta.get("package"))):
        return None
    if isinstance(meta.get("start_epoch"), int) and isinstance(meta.get("end_epoch"), int):
        seconds = meta["end_epoch"] - meta["start_epoch"]
    else:
        seconds = meta.get("duration_s") or _seconds_between(meta["start_time"], meta["end_time"])
    return {"id": name, "scope": scope, "package": meta.get("package") if scope == "app" else None,
            "label": None, "start_time": meta["start_time"], "seconds": seconds,
            # an app run's overview has its one app; a phone run's count is known once it is analysed
            "apps": 1 if scope == "app" else None,
            "decrypt": meta.get("decrypt") not in (None, "none")}


def run_entry(run_dir):
    """The /api/runs entry of a run directory; None when it has no overview and cannot get one."""
    run_dir = Path(run_dir)
    if (run_dir / "overview.json").is_file():
        ov = _read_json(run_dir / "overview.json")
        run, apps = ov["run"], ov["apps"]
        return {"id": run_dir.name, "scope": run["scope"], "package": run.get("package"),
                "label": apps[0].get("label") if run["scope"] == "app" and apps else None,
                "start_time": run.get("start_time"), "seconds": run.get("seconds"),
                "apps": len(apps), "decrypt": bool(run.get("decrypt"))}
    if (run_dir / "meta.json").is_file():
        return _meta_entry(run_dir.name, _read_json(run_dir / "meta.json"))
    if (run_dir / "result.json").is_file():           # analysed without its raw files (fixture copies)
        return _meta_entry(run_dir.name, _read_json(run_dir / "result.json")["meta"])
    return None


class Stakeout:
    """The server's state: the project's directories, the token, and the one capture at a time."""

    def __init__(self, project_dir=None):
        self.project_dir = Path(project_dir) if project_dir else device.PROJECT_DIR
        self.runs_dir = self.project_dir / "runs"
        self.labels_cache = self.project_dir / "cache" / "labels.json"
        self.token = secrets.token_urlsafe(24)
        self.lock = threading.Lock()
        self.overview_lock = threading.Lock()   # one on-demand analysis at a time
        self.stop_event = threading.Event()
        self.thread = None
        self.status = {"state": "idle", "run": None, "scope": None, "package": None,
                       "started": None, "seconds": None, "message": ""}

    # -- phone -----------------------------------------------------------------------------

    def device_state(self) -> dict:
        tshark = device.find_tshark() is not None
        ecapture = device.find_ecapture() is not None
        state = {"connected": False, "serial": None, "model": None, "android": None, "root": False,
                 "tshark": tshark, "ecapture": ecapture}
        try:
            info = device.Device().check()
        except device.DeviceError as e:
            state["connected"] = str(e) == device.NO_ROOT
            state["message"] = str(e)
            return state
        state.update(connected=True, serial=info["serial"], model=info["model"],
                     android=info["android"], root=True)
        missing = [name for name, ok in (("Wireshark", tshark), ("eCapture", ecapture)) if not ok]
        state["message"] = (f"手机已连接，可以开始观察。电脑上缺少解密要用的 {'、'.join(missing)}，这次只能不解密。"
                            if missing else "手机已连接，可以开始观察。")
        return state

    def _device(self):
        try:
            dev = device.Device()
            dev.check()
        except device.DeviceError as e:
            raise Refused(409, str(e)) from e
        return dev

    def apps(self) -> list:
        """The phone's apps for the one-app choice: user-installed first, by label. Labels of the
        user-installed ones are read from the phone when the cache does not have them yet."""
        collect, labels = _aw("collect"), _aw("labels")
        dev = self._device()
        try:
            packages = collect.list_packages(dev)
            third = [p for p in packages if p["third_party"]]
            other = [p for p in packages if not p["third_party"]]
            names = dict(labels.labels(dev, third, self.labels_cache))
            names.update(labels.labels(None, other, self.labels_cache))
        except device.DeviceError as e:
            raise Refused(409, str(e)) from e
        apps = [{"package": p["package"], "label": names.get(p["package"]), "third_party": p["third_party"]}
                for p in packages]
        apps.sort(key=lambda a: (not a["third_party"], a["label"] is None, a["label"] or "", a["package"]))
        return apps

    # -- capture ---------------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.status)

    def _set(self, **changes):
        with self.lock:
            self.status.update(changes)

    def start(self, body) -> dict:
        if not isinstance(body, dict):
            raise Refused(400, "请求的内容不对。")
        scope, package = body.get("scope"), body.get("package")
        seconds, decrypt = body.get("seconds"), body.get("decrypt")
        collect = _aw("collect")
        if scope not in ("phone", "app"):
            raise Refused(400, "请选择观察整部手机，还是只看一个应用。")
        if scope == "app":
            try:
                collect.check_package_name(package)
            except device.DeviceError as e:
                raise Refused(400, "请先选一个应用。" if not package else str(e)) from e
        else:
            package = None
        if seconds is not None and (not isinstance(seconds, int) or isinstance(seconds, bool)
                                    or not 0 < seconds <= collect.MAX_CAPTURE_S):
            raise Refused(400, f"观察时长要在 1 到 {collect.MAX_CAPTURE_S} 秒之间。")
        if not isinstance(decrypt, bool):
            raise Refused(400, "请选择解密开还是关。")
        with self.lock:      # the slot is taken before the phone is checked: one capture at a time
            if self.status["state"] in BUSY:
                raise Refused(409, "已经有一次观察在进行，请等它结束。")
            previous = dict(self.status)
            self.stop_event.clear()
            self.status.update(state="starting", run=None, scope=scope, package=package, started=None,
                               seconds=seconds, message="")
        try:
            if decrypt and device.find_tshark() is None:
                raise Refused(409, NO_TSHARK)
            if decrypt and device.find_ecapture() is None:
                raise Refused(409, NO_ECAPTURE.format(path=device.BUNDLED_ECAPTURE))
            dev = self._device()
        except Refused:
            with self.lock:
                self.status = previous
            raise
        run_id = f"{'phone' if scope == 'phone' else package}-{datetime.now():%Y%m%d-%H%M%S}"
        self._set(run=run_id)
        self.thread = threading.Thread(target=self._capture, name="capture", daemon=True,
                                       args=(dev, self.runs_dir / run_id, scope, package, seconds, decrypt))
        self.thread.start()
        return {"run": run_id}

    def stop(self) -> dict:
        with self.lock:
            if self.status["state"] not in ("starting", "running"):
                raise Refused(409, "现在没有在进行的观察。")
        self.stop_event.set()
        return self.snapshot()

    def _capture(self, dev, run_dir, scope, package, seconds, decrypt):
        try:
            self._capture_steps(dev, run_dir, scope, package, seconds, decrypt)
        except Exception as e:       # the thread must not end with the page still waiting
            traceback.print_exc()
            saved = (f"取回的数据保存在 {run_dir}，之后在“以前的观察”里打开它会再试一次。"
                     if (run_dir / "meta.json").is_file() else "")
            self._set(state="error", message=f"出错了：{e}。{saved}")

    def _capture_steps(self, dev, run_dir, scope, package, seconds, decrypt):
        collect = _aw("collect")
        phone = scope == "phone"
        max_seconds = seconds + collect.STOP_MARGIN_S if seconds else collect.MAX_CAPTURE_S
        try:
            info = collect.start(dev, package, net=True, filetrace=True, max_seconds=max_seconds,
                                 decrypt=decrypt)
        except collect.CaptureLeft as e:      # an earlier capture is on the phone: leave it alone
            self._set(state="error", message=str(e))
            return
        except device.DeviceError as e:
            try:
                collect.stop(dev, run_dir)    # clears what the start may have left on the phone
            except device.DeviceError:
                pass                          # usually "nothing to stop": says nothing about the start
            if run_dir.is_dir() and not any(run_dir.iterdir()):
                run_dir.rmdir()
            self._set(state="error", message=f"没能开始观察：{e}")
            return
        unavailable = info.get("unavailable") or []
        notes = [UNAVAILABLE_PAGE.get(code, "手机上有一项观察没能开始，这部分这次看不到。")
                 for code in dict.fromkeys(unavailable)]
        if decrypt and not info.get("decrypt") and "ecapture" not in unavailable:
            notes.append(UNAVAILABLE_PAGE["ecapture"])
        if not phone and info.get("decrypt") and info.get("running"):
            notes.append(RUNNING_NOTE)
        self._set(state="running", started=time.time(), message="".join(notes))

        self.stop_event.wait(seconds or collect.MAX_CAPTURE_S)

        self._set(state="stopping", message="")
        notes = []
        try:
            meta = collect.stop(dev, run_dir)
        except device.DeviceError as e:
            if not (run_dir / "meta.json").is_file():
                self._set(state="error", message=f"停止观察时出错：{e}")
                return
            meta = _read_json(run_dir / "meta.json")      # saved; only cleaning the phone failed
            notes.append(f"停止时出了问题：{e}")
        if meta.get("autostop"):
            why = collect.AUTOSTOP_ZH.get(meta["autostop"], meta["autostop"])
            notes.append(f"手机在 {str(meta.get('end_time'))[11:16]} 自己停止了观察：{why}。")

        self._set(state="analyzing", message="")
        overview = self.make_overview(run_dir)
        self._read_names(dev, run_dir, overview)
        notes.insert(0, f"观察完成，列出了 {len(overview['apps'])} 个应用。" if phone else "观察完成。")
        self._set(state="done", message="".join(notes))

    def _read_names(self, dev, run_dir, overview):
        """The names of the listed apps that the names cache does not have: read from the phone after the
        capture (only the listed apps, so no APK is read while the capture watches file access) and put
        into overview.json."""
        apps = [a for a in overview.get("apps") or [] if a.get("label") is None]
        if not apps:
            return
        self._set(message="正在读取应用的名称。")
        wanted = {a["package"] for a in apps}
        try:
            collect = _aw("collect")
            packages = (collect.read_packages(run_dir) if (Path(run_dir) / "packages.txt").is_file()
                        else collect.list_packages(dev))
            names = _aw("labels").labels(dev, [p for p in packages if p["package"] in wanted], self.labels_cache)
        except Exception:     # without names the page shows package names
            traceback.print_exc()
            return
        for a in apps:
            a["label"] = names.get(a["package"])
        if any(a["label"] for a in apps):
            (Path(run_dir) / "overview.json").write_text(json.dumps(overview, ensure_ascii=False, indent=1),
                                                         encoding="utf-8")

    def wait_capture(self):
        """Ctrl+C in the terminal: end a capture in progress normally before the server exits."""
        if self.snapshot()["state"] in BUSY and self.thread is not None:
            print("正在结束观察并整理结果，请稍候（再按一次 Ctrl+C 直接退出；手机上的观察会在设定时间后"
                  "自己停止，之后可以用 fetch 命令取回）……", file=sys.stderr)
            self.stop_event.set()
            self.thread.join()

    # -- runs ------------------------------------------------------------------------------

    def runs(self) -> list:
        entries = []
        if self.runs_dir.is_dir():
            for d in self.runs_dir.iterdir():
                if not d.is_dir() or not _safe_name(d.name):
                    continue
                try:
                    entry = run_entry(d)
                except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
                    continue          # a directory that is not a readable run
                if entry is not None:
                    entries.append(entry)
        unnamed = [e for e in entries if e["scope"] == "app" and e["package"] and e["label"] is None]
        if unnamed:
            names = _aw("labels").labels(None, [{"package": e["package"]} for e in unnamed], self.labels_cache)
            for e in unnamed:
                e["label"] = names.get(e["package"])
        entries.sort(key=lambda e: (e["start_time"] or "", e["id"]), reverse=True)
        return entries

    def run_dir(self, run_id) -> Path:
        d = self.runs_dir / run_id
        if not _safe_name(run_id) or not d.is_dir():
            raise Refused(404, "没有这次观察的记录。")
        return d

    def overview(self, run_id) -> dict:
        d = self.run_dir(run_id)
        with self.overview_lock:
            if (d / "overview.json").is_file():
                return self._fill_names(_read_json(d / "overview.json"))
            if self.snapshot()["state"] in BUSY and self.snapshot()["run"] == run_id:
                raise Refused(409, "这次观察还没有结束。")
            if not ((d / "meta.json").is_file() or (d / "result.json").is_file()):
                raise Refused(404, "这个目录里没有观察的数据。")
            return self.make_overview(d)

    def make_overview(self, run_dir) -> dict:
        """overview.json for a run directory, made from its raw files (or, without them, from result.json)."""
        run_dir = Path(run_dir)
        if not (run_dir / "meta.json").is_file():
            return self._named(_aw("overview").write_app_run(_read_json(run_dir / "result.json"), run_dir), run_dir)
        meta = _read_json(run_dir / "meta.json")
        if meta.get("scope") == "phone":
            return _aw("phonewide").analyze_phone(run_dir, labels=self._cached_labels(run_dir))
        result = _aw("analyze").analyze(run_dir)
        (run_dir / "report.html").write_text(_aw("report").render(result), encoding="utf-8")
        return self._named(_aw("overview").write_app_run(result, run_dir), run_dir)

    def _named(self, overview, run_dir):
        """A one-app run's overview does not know the app's name: it comes from the names cache."""
        app = overview["apps"][0] if overview.get("apps") else None
        if app is not None and app.get("label") is None:
            app["label"] = _aw("labels").labels(None, [{"package": app["package"]}], self.labels_cache) \
                .get(app["package"])
            if app["label"] is not None:
                (Path(run_dir) / "overview.json").write_text(json.dumps(overview, ensure_ascii=False, indent=1),
                                                             encoding="utf-8")
        return overview

    def _fill_names(self, overview):
        """Names an overview.json lacks (a run analysed on the command line, or before the names were
        read) from the names cache; the file is left as it is."""
        missing = [a for a in overview.get("apps") or [] if a.get("label") is None]
        if missing:
            names = _aw("labels").labels(None, [{"package": a["package"]} for a in missing], self.labels_cache)
            for a in missing:
                a["label"] = names.get(a["package"])
        return overview

    def _cached_labels(self, run_dir):
        try:
            return _aw("labels").labels(None, _aw("collect").read_packages(run_dir), self.labels_cache)
        except Exception:     # without names the overview shows package names
            traceback.print_exc()
            return None

    def delete_run(self, run_id) -> dict:
        """Delete a run for good: what was captured, its overview and its downloads."""
        d = self.run_dir(run_id)
        with self.lock:
            if self.status["run"] == run_id:
                if self.status["state"] in BUSY:
                    raise Refused(409, "这次观察还在进行，结束以后才能删除。")
                self.status.update(state="idle", run=None, scope=None, package=None, started=None,
                                   seconds=None, message="")
        with self.overview_lock:          # not while it is being analysed for the page
            if d.is_symlink():
                d.unlink()
            else:
                shutil.rmtree(d)
        return {"deleted": run_id}

    def download(self, run_id, package, kind) -> Path:
        d = self.run_dir(run_id)
        path = d / "apps" / package / kind
        if kind not in DOWNLOAD_TYPES or not _safe_name(package) or not path.is_file():
            raise Refused(404, "没有这个文件。")
        return path


class Handler(BaseHTTPRequestHandler):
    server_version = "Stakeout"
    app: Stakeout = None      # set by make_server

    def log_message(self, format, *args):     # quiet: the terminal is for the user's messages
        pass

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def _handle(self, method):
        port = self.server.server_address[1]
        if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return self._json(403, {"message": "这个地址不能访问 Stakeout。"})
        url = urlsplit(self.path)
        if not url.path.startswith("/api/"):
            if method == "GET" and url.path in STATIC:
                return self._static(*STATIC[url.path])
            return self._json(404, {"message": "没有这个页面。"})
        parts = [unquote(p) for p in url.path[len("/api/"):].split("/")]
        download = method == "GET" and len(parts) == 5 and parts[0] == "runs" and parts[2] == "apps"
        token = self.headers.get(TOKEN_HEADER) or ""
        if download and not token:
            token = (parse_qs(url.query).get("token") or [""])[0]
        if not secrets.compare_digest(token.encode(), self.app.token.encode()):
            return self._json(403, {"message": "页面已经过期，请打开终端里 Stakeout 给出的网址。"})
        try:
            if download:
                return self._file(self.app.download(parts[1], parts[3], parts[4]), parts)
            return self._json(200, self._route(method, parts))
        except Refused as e:
            return self._json(e.status, {"message": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"message": f"出错了：{e}"})

    def _route(self, method, parts):
        app = self.app
        if method == "GET":
            if parts == ["device"]:
                return app.device_state()
            if parts == ["apps"]:
                return app.apps()
            if parts == ["status"]:
                return app.snapshot()
            if parts == ["runs"]:
                return app.runs()
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "overview":
                return app.overview(parts[1])
        elif method == "POST":
            if parts == ["start"]:
                return app.start(self._body())
            if parts == ["stop"]:
                return app.stop()
            if len(parts) == 3 and parts[0] == "runs" and parts[2] == "delete":
                return app.delete_run(parts[1])
        raise Refused(404, "没有这个接口。")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            raise Refused(400, "请求的内容不对。")
        try:
            return json.loads(self.rfile.read(n) or b"null")
        except ValueError as e:
            raise Refused(400, "请求的内容不对。") from e

    def _json(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _static(self, name, ctype):
        data = (STATIC_DIR / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def _file(self, path, parts):
        run_id, package, kind = parts[1], parts[3], parts[4]
        self.send_response(200)
        self.send_header("Content-Type", DOWNLOAD_TYPES[kind])
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Content-Disposition", f'attachment; filename="{package}-{run_id}.{kind}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with path.open("rb") as f:
            shutil.copyfileobj(f, self.wfile)


def make_server(port=8765, project_dir=None) -> ThreadingHTTPServer:
    """The server, bound to 127.0.0.1:port (0: a free port), not yet serving. Its Stakeout is
    server.app, the page's address server.url."""
    app = Stakeout(project_dir)
    handler = type("StakeoutHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    server.app = app
    server.url = f"http://127.0.0.1:{server.server_address[1]}/?token={app.token}"
    return server


def serve(port=8765, open_browser=True, project_dir=None) -> int:
    try:
        server = make_server(port, project_dir)
    except OSError as e:
        print(f"无法在端口 {port} 上打开 Stakeout 页面（{e.strerror or e}）：可能已经有一个 Stakeout 在运行，"
              f"或者用 --port 换一个端口。", file=sys.stderr)
        return 1
    print(f"Stakeout 页面：{server.url}\n只有这台电脑能打开它。关掉浏览器不会停止；在这里按 Ctrl+C 退出。")
    if open_browser:
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        try:
            server.app.wait_capture()
        except KeyboardInterrupt:
            pass
    finally:
        server.server_close()
    return 0
