"""Phone access over adb. Everything Stakeout does on the phone goes through Device.

Root is KernelSU, reached as `adb shell su -c '<command>'`. Commands passed to
sh() are plain words (paths, package names, numbers); anything that would need
quoting belongs in a pushed script (aw/phone/).
"""
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
BUNDLED_ADB = PROJECT_DIR.parent / "adb-tools" / "platform-tools" / "adb"
BUNDLED_ECAPTURE = PROJECT_DIR.parent / "ecapture-tools" / "ecapture"
BUNDLED_TSHARK = PROJECT_DIR.parent / "wireshark-tools" / "Wireshark.app" / "Contents" / "MacOS" / "tshark"
SYSTEM_TSHARK = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")

_SAFE_REMOTE_PATH = re.compile(r"/[A-Za-z0-9_./-]+")

NO_DEVICE = "没有检测到手机。请用数据线连接手机，并在开发者选项中打开 USB 调试。"
UNAUTHORIZED = "手机还没有允许这台电脑调试。请解锁手机，在“允许 USB 调试吗？”对话框中点允许，然后重试。"
NO_ROOT = "无法获得 root 权限。请在 KernelSU 管理器中允许 Shell（com.android.shell）使用超级用户，然后重试。"
# What the adb client prints when it cannot reach the phone (cable pulled, phone rebooting).
_LOST = re.compile(r"^(?:adb: )?(?:error: )?(?:no devices/emulators found|device offline|device unauthorized"
                   r"|device '[^']*' not found|device not found|closed|protocol fault|connect failed)", re.M)
PULL_IDLE_S = 60      # pull_tar gives up when the stream brings no data for this long


class DeviceError(Exception):
    """adb or the phone failed. str(e) is a message for the user.

    `output` is the command's stdout (aw_ctl.sh reports its own errors there),
    `returncode` the exit status when there was one.
    """

    def __init__(self, message, output="", returncode=None):
        super().__init__(message)
        self.output = output
        self.returncode = returncode


class DeviceLost(DeviceError):
    """adb could not reach the phone: the command may not have run, or not to the end."""


def _check_lost(err):
    m = _LOST.search(err or "")
    if m:
        line = err[m.start():].splitlines()[0].strip()
        raise DeviceLost(f"与手机的连接断开了（adb：{re.sub(r'^(?:adb: )?(?:error: )?', '', line)}）")


def find_adb(adb=None):
    """adb lookup order: argument, $AW_ADB, <project>/../adb-tools/platform-tools/adb, PATH."""
    if adb:
        found = shutil.which(adb)
        if not found:
            raise DeviceError(f"找不到指定的 adb：{adb}。请检查这个路径。")
        return found
    env = os.environ.get("AW_ADB")
    if env:
        found = shutil.which(env)
        if not found:
            raise DeviceError(f"环境变量 AW_ADB 指向的 adb 不存在：{env}。请改正或删除这个变量。")
        return found
    if BUNDLED_ADB.is_file() and os.access(BUNDLED_ADB, os.X_OK):
        return str(BUNDLED_ADB)
    found = shutil.which("adb")
    if found:
        return found
    raise DeviceError("找不到 adb。请安装 Android platform-tools，或用环境变量 AW_ADB 指定 adb 的路径。")


def find_ecapture(path=None) -> str | None:
    """The eCapture binary for the phone, on this computer. Lookup order: argument, $AW_ECAPTURE,
    <project>/../ecapture-tools/ecapture. None when the first of these that is set is not a file
    (a wrong explicit setting does not fall through, as with adb)."""
    found = path or os.environ.get("AW_ECAPTURE") or BUNDLED_ECAPTURE
    return str(found) if Path(found).is_file() else None


def find_tshark(path=None) -> str | None:
    """Wireshark's tshark on this computer. Lookup order: argument, $AW_TSHARK,
    <project>/../wireshark-tools/Wireshark.app/Contents/MacOS/tshark,
    /Applications/Wireshark.app/Contents/MacOS/tshark, PATH. None when the first of these that is
    set is not an executable (a wrong explicit setting does not fall through, as with adb)."""
    explicit = path or os.environ.get("AW_TSHARK")
    if explicit:
        return shutil.which(explicit)
    for candidate in (BUNDLED_TSHARK, SYSTEM_TSHARK):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which("tshark")


def _text(data):
    return data.decode("utf-8", errors="replace").replace("\r\n", "\n")


def _as_root(cmd):
    return f"su -c {shlex.quote(cmd)}"


def _strip_top(top):
    """tar filter: extract `<top>/x` as `x`, skip everything else, then apply the 'data' filter."""
    prefix = top + "/"

    def filt(member, dest):
        name = member.name[2:] if member.name.startswith("./") else member.name
        if not name.startswith(prefix):
            return None
        rest = name[len(prefix):].strip("/")
        if not rest:
            return None
        return tarfile.data_filter(member.replace(name=rest, deep=False), dest)

    return filt


class _Watched:
    """A read-only stream that records when data last arrived."""

    def __init__(self, f):
        self.f = f
        self.last = time.monotonic()

    def read(self, n=-1):
        data = self.f.read(n)
        self.last = time.monotonic()
        return data


class Device:
    def __init__(self, adb: str | None = None, serial: str | None = None):
        self.adb = find_adb(adb)
        self.serial = serial

    def _base(self):
        return [self.adb] + (["-s", self.serial] if self.serial else [])

    def _adb(self, args, timeout):
        """Run adb; return (stdout, stderr, returncode)."""
        try:
            # Own session: Ctrl+C in the terminal does not kill adb mid-command.
            proc = subprocess.Popen(self._base() + args, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except OSError as e:
            raise DeviceError(f"无法运行 adb（{self.adb}）：{e}") from e
        deadline = time.monotonic() + timeout
        interrupted = False
        while True:
            try:
                out, err = proc.communicate(timeout=max(0.0, deadline - time.monotonic()))
                break
            except KeyboardInterrupt:
                # Let the phone-side command finish before passing Ctrl+C on, however often
                # it is pressed. Killing adb would not stop it: a root command on the phone
                # keeps running after the client goes away, and a half-run `aw_ctl.sh start`
                # would then race the stop() that follows.
                if not interrupted:
                    interrupted = True
                    print("正在等待手机完成当前操作，请稍候……", file=sys.stderr, flush=True)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise DeviceLost(f"手机在 {timeout:g} 秒内没有响应（adb {args[0]}）。请检查数据线连接后重试。")
        if interrupted:
            raise KeyboardInterrupt
        return _text(out), _text(err), proc.returncode

    def sh(self, cmd: str, root: bool = False, timeout: float = 60) -> str:
        """Run `cmd` in the phone's shell (as root with root=True); return stdout."""
        out, err, rc = self._adb(["shell", _as_root(cmd) if root else cmd], timeout)
        if rc != 0:
            _check_lost(err)
            detail = (err.strip() or out.strip())
            raise DeviceError(f"手机上的命令失败（退出码 {rc}）：{cmd}" + (f"\n{detail}" if detail else ""),
                              output=out, returncode=rc)
        return out

    def push(self, local, remote, timeout: float = 60) -> None:
        out, err, rc = self._adb(["push", str(local), remote], timeout)
        if rc != 0:
            _check_lost(err)
            raise DeviceError(f"无法把 {local} 传到手机的 {remote}：{(err.strip() or out.strip())}",
                              output=out, returncode=rc)

    def pull_tar(self, remote_dir: str, local_dir, root: bool = True) -> None:
        """Copy the contents of remote_dir into local_dir as a tar stream (adb exec-out, binary-safe)."""
        remote_dir = remote_dir.rstrip("/")
        if not _SAFE_REMOTE_PATH.fullmatch(remote_dir):
            raise DeviceError(f"不支持的手机目录：{remote_dir}")
        parent, name = posixpath.split(remote_dir)
        cmd = f"tar -C {parent or '/'} -cf - {name}"
        local_dir = Path(local_dir)
        local_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile() as errf:
            try:
                # Own session, as in _adb: Ctrl+C in the terminal must not cut the pull short.
                proc = subprocess.Popen(self._base() + ["exec-out", _as_root(cmd) if root else cmd],
                                        stdout=subprocess.PIPE, stderr=errf, start_new_session=True)
            except OSError as e:
                raise DeviceError(f"无法运行 adb（{self.adb}）：{e}") from e
            stream = _Watched(proc.stdout)
            done = threading.Event()
            stalled = []

            def watch():
                # A stalled stream (phone gone without adb noticing) would block the read for ever.
                while not done.wait(1):
                    if time.monotonic() - stream.last > PULL_IDLE_S:
                        stalled.append(True)
                        proc.kill()
                        return

            threading.Thread(target=watch, daemon=True).start()
            try:
                with tarfile.open(fileobj=stream, mode="r|") as tf:
                    tf.extractall(local_dir, filter=_strip_top(name))
            except BaseException as e:
                proc.kill()
                proc.communicate()
                if stalled:
                    raise DeviceLost(f"从手机取回数据时，{PULL_IDLE_S} 秒没有收到任何数据，已放弃") from e
                if isinstance(e, tarfile.TarError):
                    errf.seek(0)
                    _check_lost(_text(errf.read()))
                    raise DeviceError(f"从手机取回 {remote_dir} 失败：数据不完整（{e}）") from e
                raise
            finally:
                done.set()
            proc.communicate()      # rest of the stream (tar padding)
            if proc.returncode != 0:
                errf.seek(0)
                detail = _text(errf.read()).strip()
                _check_lost(detail)
                raise DeviceError(f"从手机取回 {remote_dir} 失败（adb 退出码 {proc.returncode}）：{detail}",
                                  returncode=proc.returncode)

    def check(self) -> dict:
        """Pick the phone and make sure root works.

        Returns {"serial","model","android","sdk","root": True}; DeviceError otherwise.
        """
        out, err, rc = self._adb(["devices"], 30)
        if rc != 0:
            raise DeviceError(f"adb 无法列出已连接的手机：{(err.strip() or out.strip())}")
        entries = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("*") or line.startswith("List of devices"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                entries.append((parts[0], parts[1].strip()))
        if self.serial:
            match = [e for e in entries if e[0] == self.serial]
            if not match:
                raise DeviceError(f"没有找到序列号为 {self.serial} 的手机。请检查连接，或去掉 --serial 后重试。")
            serial, state = match[0]
        else:
            if not entries:
                raise DeviceError(NO_DEVICE)
            if len(entries) > 1:
                names = "、".join(s for s, _ in entries)
                raise DeviceError(f"连接了 {len(entries)} 台设备（{names}），请用 --serial 指定其中一台。")
            serial, state = entries[0]
        if state == "unauthorized":
            raise DeviceError(UNAUTHORIZED)
        if state != "device":
            raise DeviceError(f"手机 {serial} 现在的状态是 {state}，无法使用。请解锁手机并重新插拔数据线后重试。")
        self.serial = serial

        props = self.sh("getprop ro.product.model; getprop ro.build.version.release; "
                        "getprop ro.build.version.sdk").splitlines()
        model, android, sdk = [(props[i].strip() if i < len(props) else "") for i in range(3)]
        try:
            ident = self.sh("id", root=True, timeout=30)
        except DeviceError:
            ident = ""
        if "uid=0" not in ident:
            raise DeviceError(NO_ROOT)
        return {"serial": serial, "model": model, "android": android,
                "sdk": int(sdk) if sdk.isdigit() else None, "root": True}
