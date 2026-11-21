"""Tests for the adb lookup in aw/device.py (find_adb, common_adbs). No phone, and none of this computer's own
adb: the home folder, the project's folder and the environment are stood in for by a temporary folder."""
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aw import device
from aw.device import DeviceError

REAL = "windows" if os.name == "nt" else "linux"


class FindAdb(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.projects = self.root / "projects"
        # nothing on PATH, no AW_ADB, no SDK variables
        for p in (mock.patch.dict(os.environ, {"PATH": str(self.root / "empty")}, clear=True),
                  mock.patch.object(Path, "home", return_value=self.home),
                  mock.patch.object(device, "PROJECT_DIR", self.projects / "stakeout"),
                  mock.patch.object(device, "BUNDLED_ADB", self.projects / "adb-tools" / "platform-tools" / "adb")):
            p.start()
            self.addCleanup(p.stop)

    def system(self, name):
        """Look up as on this system: "windows", "darwin" or "linux"."""
        for p in (mock.patch.object(device, "WINDOWS", name == "windows"),
                  mock.patch.object(device, "sys", SimpleNamespace(platform="win32" if name == "windows" else name))):
            p.start()
            self.addCleanup(p.stop)

    def adb(self, folder):
        exe = Path(folder) / ("adb.exe" if device.WINDOWS else "adb")
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"")
        exe.chmod(0o755)
        return str(exe)

    def test_order_linux(self):
        self.system("linux")
        os.environ.update(ANDROID_HOME=str(self.root / "a"), ANDROID_SDK_ROOT=str(self.root / "b"))
        tools = [self.root / "a", self.root / "b", self.home / "Android" / "Sdk"]
        self.assertEqual(device.common_adbs(),
                         [t / "platform-tools" / "adb" for t in tools]
                         + [d / "platform-tools" / "adb" for d in (self.projects, self.home, self.home / "Downloads",
                                                                   self.home / "Desktop")])

    def test_order_macos(self):
        self.system("darwin")
        self.assertEqual(device.common_adbs(),
                         [d / "platform-tools" / "adb" for d in (self.home / "Library" / "Android" / "sdk", self.projects,
                                                                 self.home, self.home / "Downloads", self.home / "Desktop")]
                         + [Path("/opt/homebrew/bin/adb"), Path("/usr/local/bin/adb")])

    def test_order_windows(self):
        self.system("windows")
        os.environ.update(LOCALAPPDATA=str(self.root / "local"), SystemDrive="C:")
        self.assertEqual(device.common_adbs(),
                         [d / "platform-tools" / "adb.exe" for d in (self.root / "local" / "Android" / "Sdk",
                                                                     self.projects, self.home, self.home / "Downloads",
                                                                     self.home / "Desktop", Path("C:\\"))])

    def test_windows_without_localappdata_has_no_sdk_folder(self):
        self.system("windows")
        self.assertNotIn(self.home / "Android" / "Sdk" / "platform-tools" / "adb.exe", device.common_adbs())

    def test_found_in_the_home_folder(self):
        # platform-tools unpacked into the home folder, not on PATH: the case on the Windows machine that asked for this
        self.system(REAL)
        self.adb(self.home / "Downloads" / "platform-tools")
        want = self.adb(self.home / "platform-tools")
        self.assertEqual(device.find_adb(), want)

    def test_android_studio_on_windows(self):
        self.system("windows")
        os.environ["LOCALAPPDATA"] = str(self.root / "local")
        want = self.adb(self.root / "local" / "Android" / "Sdk" / "platform-tools")
        self.assertEqual(device.find_adb(), want)

    def test_path_comes_before_the_common_places(self):
        self.system(REAL)
        self.adb(self.home / "platform-tools")
        on_path = self.adb(self.root / "bin")
        os.environ["PATH"] = str(self.root / "bin")
        self.assertEqual(os.path.normcase(device.find_adb()), os.path.normcase(on_path))

    def test_wrong_aw_adb_does_not_fall_through(self):
        self.system(REAL)
        self.adb(self.home / "platform-tools")
        os.environ["AW_ADB"] = str(self.root / "nowhere" / "adb")
        with self.assertRaises(DeviceError) as cm:
            device.find_adb()
        self.assertIn("AW_ADB", str(cm.exception))

    def test_nowhere_says_what_to_do(self):
        self.system("linux")        # not macOS: Homebrew's folders are real ones
        with self.assertRaises(DeviceError) as cm:
            device.find_adb()
        for text in ("platform-tools", "AW_ADB", "https://developer.android.com/tools/releases/platform-tools"):
            self.assertIn(text, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
