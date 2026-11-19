"""Live capture: look up the package, start the phone-side monitors, stop them and
bring the raw files home into a run directory (see docs/CONTRACT.md, "Run directory").
A phone run (package None) watches every app at once (docs/CONTRACT_PHONE.md)."""
import json
import re
from pathlib import Path

from . import device
from .device import DeviceError, DeviceLost

REMOTE_DIR = "/data/local/tmp/appwatch"
REMOTE_OUT = REMOTE_DIR + "/out"
CTL = REMOTE_DIR + "/aw_ctl.sh"
RUNNING = REMOTE_DIR + "/running"
REMOTE_ECAPTURE = REMOTE_DIR + "/ecapture"
PHONE_DIR = Path(__file__).resolve().parent / "phone"

# Run with root; plain words only (anything that needs quoting is in aw/phone/). `ls -d` prints
# those of the three that exist and exits 1 when one does not.
LIST_CMD = f"ls -d {CTL} {REMOTE_OUT} {RUNNING}"
PACKAGE_CMD = f"cat {REMOTE_OUT}/package"
STOP_CMD = f"sh {CTL} stop"
CLEAN_CMD = f"sh {CTL} clean"
CHMOD_ECAPTURE_CMD = f"chmod 755 {REMOTE_ECAPTURE}"
PROCS_CMD = "ps -A -o NAME"     # every process name, one per line, under a NAME heading
PACKAGES_CMD = "pm list packages -f -U"     # `package:<apk path>=<package> uid:<n>`, every package
THIRD_PARTY_CMD = "pm list packages -3"     # `package:<package>`, the ones the user installed

START_TIMEOUT = 120
# eCapture is a 23 MB file: 300 s allows for a slow USB link (about 80 KB/s).
ECAPTURE_PUSH_TIMEOUT = 300
STOP_TIMEOUT = 120
CLEAN_TIMEOUT = 60
# The phone stops a capture by itself (aw_watchdog.sh) after this long, so that it does not run
# on when the computer goes away: --seconds N plus a margin for stopping, or the cap without it.
MAX_CAPTURE_S = 3600
STOP_MARGIN_S = 300
FETCH_CMD = "python3 stakeout.py fetch"
# aw_ctl.sh `WARN unavailable <code>`: what the phone lacks, said when the capture starts.
UNAVAILABLE_ZH = {
    "tcpdump": "手机上没有 tcpdump 程序，本次不抓包。",
    "f2fs_events": "手机内核没有 f2fs 文件读写的跟踪事件，本次不跟踪文件访问。",
    "trace_filter": "手机内核没有接受文件跟踪的过滤条件，为了不让跟踪记录不断增长，本次不跟踪文件访问。",
    "ecapture": "eCapture 没能在手机上运行（手机上缺少它或系统的 TLS 库，或者它没有在 10 秒内正常启动，原因记在 "
                "ecapture_keylog_stdout.log），本次不解密 HTTPS 内容，其他采集照常进行。",
}
AUTOSTOP_ZH = {"deadline": "达到最长采集时间", "disk": "手机存储空间不足 1 GB"}
# aw_ctl.sh's own ERR lines in Chinese
_ERR_ZH = (("already running", "手机上已经有一次采集在进行"),
           ("missing", "手机上缺少采集脚本（推送没有完成）"),
           ("usage:", "采集脚本收到的参数不对"))

# Android's rule: at least two segments, each a letter followed by letters, digits or _.
_PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
# A PACKAGES_CMD line; the APK path itself can contain "=": the package is after the last one.
_PACKAGE_LINE_RE = re.compile(r"package:(.+)=([^=\s]+) uid:(\d+)")

# Small state files aw_ctl.sh writes into out/, and the data files a full run has.
STATE_FILES = ("package", "uid", "start_time", "start_epoch", "end_time", "end_epoch",
               "utc_offset", "filetrace_backend", "device_props.txt", "kernel.txt")
DATA_FILES = ("package_dump.txt", "appops_before.txt", "appops_after.txt",
              "ps_before.txt", "ps_after.txt", "logcat.txt", "poll.txt")
# A phone run has these instead of package_dump.txt.
PHONE_FILES = ("packages.txt", "packages_third.txt", "appops_all.txt.gz")
PHONE_DATA_FILES = tuple(n for n in DATA_FILES if n != "package_dump.txt") + PHONE_FILES
# Everything aw_ctl.sh can put into out/, and mitm.har (put into a run directory by analyze --har):
# stop() removes these from a reused run directory. `scope` is in every run made since v0.4.
RAW_FILES = STATE_FILES + DATA_FILES + PHONE_FILES + (
    "scope", "filetrace_f2fs.txt", "net.pcap", "errors.log", "tcpdump.log", "unavailable", "autostop",
    "decrypt", "tls_events.log", "ecapture.log", "ecapture_stdout.log", "tls_keys.log", "ecapture_keylog.log",
    "ecapture_keylog_stdout.log", "mitm.har")
# analyze cannot work without these (a phone run has no package and uid).
REQUIRED_META = ("package", "uid", "start_time", "end_time")
PHONE_REQUIRED_META = ("start_time", "end_time")


class CaptureLeft(DeviceError):
    """A capture an earlier run did not bring home is on the phone; `fetch` brings it home."""


def app_id(uid: int) -> str:
    """10378 -> "u0a378" (the form logcat uses)."""
    return f"u{uid // 100000}a{uid % 100000 - 10000}"


def check_package_name(package: str) -> None:
    if not isinstance(package, str) or not _PACKAGE_RE.fullmatch(package):
        raise DeviceError(f"包名格式不对：{package}。包名的样子是 com.example.app，可以用 list 命令查看。")


def parse_package_dump(text: str, package: str) -> dict | None:
    """uid and versionName from `dumpsys package <pkg>`; None when the package is not in it."""
    head = f"Package [{package}]"
    inside = False
    uid = version = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Package ["):
            if inside:
                break
            inside = s.startswith(head)
            continue
        if not inside:
            continue
        if s and not line.startswith("    "):
            break
        m = re.match(r"(?:appId|userId)=(\d+)", s)
        if m and uid is None:
            uid = int(m.group(1))
        elif s.startswith("versionName=") and version is None:
            version = s[len("versionName="):].strip() or None
    if uid is None:
        return None
    return {"uid": uid, "version_name": version}


def resolve_package(dev, package) -> dict:
    """{"package","uid","app_id","version_name"}; DeviceError if not installed."""
    check_package_name(package)
    info = parse_package_dump(dev.sh(f"dumpsys package {package}"), package)
    if info is None:
        raise DeviceError(f"手机上没有安装 {package}。可以用 list 命令查看手机上安装的应用。")
    return {"package": package, "uid": info["uid"], "app_id": app_id(info["uid"]),
            "version_name": info["version_name"]}


def parse_packages(packages_text: str, third_text: str) -> list[dict]:
    """[{"package","uid","apk","third_party"}] from the output of PACKAGES_CMD and THIRD_PARTY_CMD,
    in the order of the first; lines of another shape are skipped."""
    third = set()
    for line in third_text.splitlines():
        line = line.strip()
        if line.startswith("package:"):
            third.add(line[len("package:"):])
    result = []
    for line in packages_text.splitlines():
        m = _PACKAGE_LINE_RE.fullmatch(line.strip())
        if m:
            result.append({"package": m.group(2), "uid": int(m.group(3)), "apk": m.group(1),
                           "third_party": m.group(2) in third})
    return result


def list_packages(dev) -> list[dict]:
    """Every package installed on the phone (see parse_packages)."""
    return parse_packages(dev.sh(PACKAGES_CMD), dev.sh(THIRD_PARTY_CMD))


def read_packages(run_dir) -> list[dict]:
    """The same list from a phone run's packages.txt and packages_third.txt."""
    run_dir = Path(run_dir)
    return parse_packages((run_dir / "packages.txt").read_text(encoding="utf-8", errors="replace"),
                          (run_dir / "packages_third.txt").read_text(encoding="utf-8", errors="replace"))


def _ctl(dev, cmd, timeout):
    """Run an aw_ctl.sh command as root; return stdout, also when the script exits
    non-zero with its own `ERR …` line."""
    try:
        return dev.sh(cmd, root=True, timeout=timeout)
    except DeviceError as e:
        if "ERR " in (e.output or ""):
            return e.output
        raise


def _err_line(out):
    for line in out.splitlines():
        if line.startswith("ERR "):
            text = line[4:]
            return next((zh for key, zh in _ERR_ZH if key in text), text)
    return out.strip() or "没有输出"


def _why(e):
    return str(e).strip().rstrip("。")


def _on_phone(dev) -> dict:
    """Which of aw_ctl.sh, out/ and the `running` flag are on the phone."""
    try:
        out = dev.sh(LIST_CMD, root=True, timeout=30)
    except DeviceLost:
        raise
    except DeviceError as e:
        out = e.output or ""
    found = {line.strip() for line in out.splitlines()}
    return {"ctl": CTL in found, "out": REMOTE_OUT in found, "running": RUNNING in found}


def pending(dev) -> dict | None:
    """A capture an earlier run left on the phone (stopped or still running, not brought home):
    {"running": bool, "package": str | None, "scope": "phone" | "app"}; None when there is none."""
    on = _on_phone(dev)
    if not (on["out"] or on["running"]):
        return None
    try:
        package = dev.sh(PACKAGE_CMD, root=True, timeout=30).strip()
    except DeviceLost:
        raise
    except DeviceError:
        package = ""
    # aw_ctl.sh writes "-" as the package of a phone run
    return {"running": on["running"], "package": package if _PACKAGE_RE.fullmatch(package) else None,
            "scope": "phone" if package == "-" else "app"}


def app_running(dev, package) -> bool:
    """Whether the app has a process (named <package> or <package>:<anything>); False also when
    the phone's process list could not be read."""
    try:
        out = dev.sh(PROCS_CMD, root=True, timeout=30)
    except DeviceError:
        return False
    return any(n == package or n.startswith(package + ":") for n in (line.strip() for line in out.splitlines()))


def start(dev, package, net=True, filetrace=True, max_seconds=MAX_CAPTURE_S, decrypt=False) -> dict:
    """Push aw/phone/*.sh to the phone and run `aw_ctl.sh start`. The phone stops the capture
    by itself after max_seconds. A capture an earlier run left on the phone is not touched:
    CaptureLeft says to fetch it first. decrypt also pushes eCapture and has the phone run it in
    keylog mode (the computer decrypts net.pcap with tshark afterwards, so it needs net and tshark);
    when it does not start there, `unavailable` has "ecapture", the returned "decrypt" is False and
    the capture runs without it. "running": the app had a process just before the capture began.
    package None starts a phone run (`aw_ctl.sh start all -`): every app, no package lookups;
    "package", "uid", "app_id", "version_name" and "running" are then None."""
    phone = package is None
    if not phone:
        check_package_name(package)
    ecapture = None
    if decrypt:
        if not net:
            raise DeviceError("解密要用抓到的数据包，不能同时关掉抓包：请去掉 --no-net 再运行。")
        if device.find_tshark() is None:
            raise DeviceError("找不到 tshark（Wireshark 带的命令行程序），无法解密：请安装 Wireshark"
                              "（放进“应用程序”文件夹），或用环境变量 AW_TSHARK 指定 tshark 的路径。")
        ecapture = device.find_ecapture()
        if ecapture is None:
            raise DeviceError(f"找不到 eCapture 程序，无法解密：请用环境变量 AW_ECAPTURE 指定它的路径，"
                              f"或把它放在 {device.BUNDLED_ECAPTURE}。")
    left = pending(dev)
    if left:
        state = "仍在进行" if left["running"] else "已经停止，数据还没有取回"
        what = "整部手机" if left["scope"] == "phone" else left["package"] or "应用未知"
        raise CaptureLeft(f"手机上还有一次以前的采集（{what}，{state}）。"
                          f"请先运行 {FETCH_CMD} 停止它并取回数据，再开始新的采集。")
    if phone:
        info = {"package": None, "uid": None, "app_id": None, "version_name": None}
    else:
        info = resolve_package(dev, package)
    for script in sorted(PHONE_DIR.glob("*.sh")):
        dev.push(script, f"{REMOTE_DIR}/{script.name}")
    if ecapture:
        dev.push(ecapture, REMOTE_ECAPTURE, timeout=ECAPTURE_PUSH_TIMEOUT)
        dev.sh(CHMOD_ECAPTURE_CMD, root=True, timeout=30)
    running = None if phone else app_running(dev, package)
    target = "all -" if phone else f"{info['uid']} {package}"
    out = _ctl(dev, f"sh {CTL} start {target} {int(bool(net))} {int(bool(filetrace))} "
                    f"{int(max_seconds)}" + (" 1" if ecapture else ""), START_TIMEOUT)
    m = re.search(r"^OK started (.+)$", out, re.M)
    if not m:
        dev.sh(CLEAN_CMD, root=True, timeout=CLEAN_TIMEOUT)
        raise DeviceError(f"无法在手机上开始采集：{_err_line(out)}")
    unavailable = re.findall(r"^WARN unavailable (\S+)", out, re.M)
    # decrypt: eCapture is running on the phone (stakeout.py says so), not merely asked for.
    return {**info, "start_time": m.group(1).strip(), "net": bool(net), "filetrace": bool(filetrace),
            "max_seconds": int(max_seconds), "decrypt": bool(ecapture) and "ecapture" not in unavailable,
            "unavailable": unavailable, "running": running}


def fetch(dev, run_dir) -> dict:
    """Stop and bring home a capture an earlier run left on the phone (see pending), then clean
    the phone, as stop() does. The current aw_ctl.sh is pushed first: an older copy is not run."""
    dev.push(PHONE_DIR / "aw_ctl.sh", CTL)
    return stop(dev, run_dir)


def stop(dev, run_dir) -> dict:
    """`aw_ctl.sh stop`, pull out/ into run_dir, write meta.json, then `aw_ctl.sh clean`.
    Also works after an interrupted start(): whatever was captured is kept. Each failure says
    what is left on the phone and what to do."""
    run_dir = Path(run_dir)
    try:
        has_ctl = _on_phone(dev)["ctl"]
        out = _ctl(dev, STOP_CMD, STOP_TIMEOUT) if has_ctl else "ERR nothing to stop\n"
    except DeviceError as e:
        raise DeviceError(f"没能让手机停止采集：{_why(e)}。手机上的采集可能还在进行，到设定的最长时间或存储空间"
                          f"不足时会自行停止；重新连接手机后运行 {FETCH_CMD}，会停止采集并取回数据。") from e
    if "OK stopped" not in out:
        if "nothing to stop" in out:
            if has_ctl:
                dev.sh(CLEAN_CMD, root=True, timeout=CLEAN_TIMEOUT)
            raise DeviceError("手机上没有这次采集的数据：采集在手机上还没有开始。")
        raise DeviceError(f"停止采集失败：{_err_line(out)}。可以运行 {FETCH_CMD} 再试一次。")
    run_dir.mkdir(parents=True, exist_ok=True)
    # A reused run directory (--out): a file this run did not produce must not be
    # taken for part of it.
    for name in RAW_FILES + ("meta.json",):
        (run_dir / name).unlink(missing_ok=True)
    try:
        dev.pull_tar(REMOTE_OUT, run_dir, root=True)
    except DeviceError as e:
        for name in RAW_FILES:          # a part of a capture is not a run directory
            (run_dir / name).unlink(missing_ok=True)
        raise DeviceError(f"采集已在手机上停止，但取回数据失败：{_why(e)}。数据还在手机上；重新连接手机后运行 "
                          f"{FETCH_CMD} 取回。") from e
    meta = build_meta(run_dir)
    required = PHONE_REQUIRED_META if meta["scope"] == "phone" else REQUIRED_META
    unknown = [k for k in required if meta.get(k) is None]
    if not unknown:
        (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n",
                                           encoding="utf-8")
    try:
        out = dev.sh(CLEAN_CMD, root=True, timeout=CLEAN_TIMEOUT)
    except DeviceError as e:
        saved = f"数据已保存到 {run_dir}，但" if not unknown else ""
        raise DeviceError(f"{saved}没能清理手机上的临时文件（{_why(e)}）。手机上的采集已经停止；重新连接手机后运行 "
                          f"{FETCH_CMD} 可以清理（会再取回一份同样的数据）。") from e
    if unknown:
        raise DeviceError(f"手机上的采集没有完整开始（没有记录 {'、'.join(unknown)}），无法生成报告。请重新运行。")
    if "OK cleaned" not in out:
        if "trace instance" in out:
            raise DeviceError(f"数据已保存到 {run_dir}。手机上留下了一个内核跟踪实例"
                              "（/sys/kernel/tracing/instances/appwatch，占用一些内存），重启手机后就没有了。")
        raise DeviceError(f"数据已保存到 {run_dir}，但没能清理手机上的临时文件：{_err_line(out)}")
    return meta


def _read_small(run_dir, name):
    try:
        return (run_dir / name).read_text(encoding="utf-8", errors="replace").strip() or None
    except FileNotFoundError:
        return None


def _int(text):
    return int(text) if text and text.isdigit() else None


def build_meta(run_dir) -> dict:
    """meta.json from the small files aw_ctl.sh writes into out/ (already pulled into run_dir).
    "scope": "phone" or "app" (runs made before v0.4 have no `scope` file: one app); a phone
    run has no package, uid, app_id or version_name (None)."""
    run_dir = Path(run_dir)
    scope = _read_small(run_dir, "scope") or "app"
    phone = scope == "phone"
    package = None if phone else _read_small(run_dir, "package")
    uid = None if phone else _int(_read_small(run_dir, "uid"))
    props = {}
    for line in (_read_small(run_dir, "device_props.txt") or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and v.strip():
            props[k.strip()] = v.strip()
    version = None
    if package:
        try:
            dump = (run_dir / "package_dump.txt").read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            dump = ""
        info = parse_package_dump(dump, package)
        version = info["version_name"] if info else None
    backend = _read_small(run_dir, "filetrace_backend")
    if backend is None:   # start interrupted between starting the trace and writing this file
        backend = "f2fs" if (run_dir / "filetrace_f2fs.txt").is_file() else "none"

    meta = {
        "format": 1,
        "scope": scope,
        "package": package,
        "uid": uid,
        "app_id": app_id(uid) if uid is not None else None,
        "version_name": version,
        "device": {
            "brand": props.get("ro.product.brand"),
            "model": props.get("ro.product.model"),
            "android": props.get("ro.build.version.release"),
            "sdk": _int(props.get("ro.build.version.sdk")),
            "kernel": _read_small(run_dir, "kernel.txt"),
        },
    }
    # Left out, not null, when the phone did not record them: analyze tests these keys for presence.
    for key, value in (("start_time", _read_small(run_dir, "start_time")),
                       ("end_time", _read_small(run_dir, "end_time")),
                       ("start_epoch", _int(_read_small(run_dir, "start_epoch"))),
                       ("end_epoch", _int(_read_small(run_dir, "end_epoch"))),
                       ("utc_offset", _read_small(run_dir, "utc_offset"))):
        if value is not None:
            meta[key] = value
    meta["filetrace_backend"] = backend
    meta["net"] = (run_dir / "net.pcap").is_file()
    decrypt = _read_small(run_dir, "decrypt")
    if decrypt is None:   # older runs; live_xhs_tls_0120 (eCapture run by hand) has tls_events.log only
        decrypt = "ecapture" if (run_dir / "tls_events.log").is_file() else "none"
    meta["decrypt"] = decrypt
    # Left out when absent: what the phone lacked (aw_ctl.sh), and why the phone stopped by itself.
    unavailable = (_read_small(run_dir, "unavailable") or "").split()
    if unavailable:
        meta["unavailable"] = list(dict.fromkeys(unavailable))
    autostop = _read_small(run_dir, "autostop")
    if autostop:
        meta["autostop"] = autostop
    missing = [n for n in STATE_FILES if _read_small(run_dir, n) is None]
    expected = (PHONE_DATA_FILES if phone else DATA_FILES) + (("filetrace_f2fs.txt",) if backend == "f2fs" else ())
    missing += [n for n in expected
                if not (run_dir / n).is_file() or (run_dir / n).stat().st_size == 0]
    if missing:
        meta["missing"] = missing
    return meta
