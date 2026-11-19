"""Parse `dumpsys appops --package <pkg>` and compare two dumps.

The dump keeps only the *last* access / reject per (uid state, flags), so a
diff can only say "it happened at least once in this state, last at T".
"""
import re
from datetime import datetime

# Simplified Chinese names for app ops. "sensitive" marks ops that read or
# change personal data, reveal location / surroundings, or expose the screen.
_OPS = [
    # (op, zh, category, sensitive)
    ("COARSE_LOCATION", "大致位置", "位置", True),
    ("FINE_LOCATION", "精确位置", "位置", True),
    ("GPS", "GPS 定位", "位置", True),
    ("MONITOR_LOCATION", "持续获取位置", "位置", True),
    ("MONITOR_HIGH_POWER_LOCATION", "持续获取位置（高耗电）", "位置", True),
    ("WIFI_SCAN", "扫描 WLAN 网络", "位置", True),
    ("NEIGHBORING_CELLS", "读取附近基站信息", "位置", True),
    ("ACCESS_MEDIA_LOCATION", "读取照片和视频中的位置信息", "位置", True),
    ("MOCK_LOCATION", "模拟位置", "位置", False),

    ("CAMERA", "相机", "相机", True),
    ("PHONE_CALL_CAMERA", "通话中使用相机", "相机", True),

    ("RECORD_AUDIO", "麦克风（录音）", "麦克风", True),
    ("PHONE_CALL_MICROPHONE", "通话中使用麦克风", "麦克风", True),
    ("RECORD_AUDIO_HOTWORD", "语音唤醒词录音", "麦克风", True),
    ("RECORD_AUDIO_OUTPUT", "录制设备播放的声音", "麦克风", True),

    ("READ_CLIPBOARD", "读取剪贴板", "剪贴板", True),
    ("WRITE_CLIPBOARD", "写入剪贴板", "剪贴板", False),

    ("READ_EXTERNAL_STORAGE", "读取共享存储空间", "存储与媒体", True),
    ("WRITE_EXTERNAL_STORAGE", "写入共享存储空间", "存储与媒体", True),
    ("MANAGE_EXTERNAL_STORAGE", "所有文件访问权限", "存储与媒体", True),
    ("LEGACY_STORAGE", "旧版存储访问模式", "存储与媒体", False),
    ("NO_ISOLATED_STORAGE", "不使用分区存储", "存储与媒体", False),
    ("READ_MEDIA_AUDIO", "读取音乐和音频", "存储与媒体", True),
    ("WRITE_MEDIA_AUDIO", "修改音乐和音频", "存储与媒体", True),
    ("READ_MEDIA_VIDEO", "读取视频", "存储与媒体", True),
    ("WRITE_MEDIA_VIDEO", "修改视频", "存储与媒体", True),
    ("READ_MEDIA_IMAGES", "读取照片", "存储与媒体", True),
    ("WRITE_MEDIA_IMAGES", "修改照片", "存储与媒体", True),
    ("READ_MEDIA_VISUAL_USER_SELECTED", "读取用户选定的照片和视频", "存储与媒体", True),
    ("MANAGE_MEDIA", "管理媒体文件", "存储与媒体", True),

    ("READ_CONTACTS", "读取通讯录", "通讯录", True),
    ("WRITE_CONTACTS", "修改通讯录", "通讯录", True),
    ("GET_ACCOUNTS", "读取设备上的账号", "通讯录", True),

    ("READ_CALENDAR", "读取日历", "日历", True),
    ("WRITE_CALENDAR", "修改日历", "日历", True),

    ("READ_PHONE_STATE", "读取电话状态和身份信息", "电话", True),
    ("READ_PHONE_NUMBERS", "读取本机号码", "电话", True),
    ("CALL_PHONE", "拨打电话", "电话", True),
    ("ANSWER_PHONE_CALLS", "接听电话", "电话", True),
    ("PROCESS_OUTGOING_CALLS", "处理拨出的电话", "电话", True),
    ("ACCEPT_HANDOVER", "接续其他应用中的通话", "电话", True),
    ("MANAGE_ONGOING_CALLS", "管理进行中的通话", "电话", True),
    ("ADD_VOICEMAIL", "添加语音邮件", "电话", True),
    ("USE_SIP", "使用 SIP 网络电话", "电话", True),
    ("READ_CALL_LOG", "读取通话记录", "电话", True),
    ("WRITE_CALL_LOG", "修改通话记录", "电话", True),

    ("READ_SMS", "读取短信", "短信", True),
    ("RECEIVE_SMS", "接收短信", "短信", True),
    ("RECEIVE_MMS", "接收彩信", "短信", True),
    ("RECEIVE_WAP_PUSH", "接收 WAP 推送", "短信", True),
    ("SEND_SMS", "发送短信", "短信", True),
    ("WRITE_SMS", "修改短信", "短信", True),
    ("READ_ICC_SMS", "读取 SIM 卡中的短信", "短信", True),
    ("WRITE_ICC_SMS", "修改 SIM 卡中的短信", "短信", True),
    ("READ_CELL_BROADCASTS", "读取小区广播消息", "短信", True),
    ("RECEIVE_EMERGECY_SMS", "接收紧急广播", "短信", True),  # AOSP spells it this way

    ("READ_DEVICE_IDENTIFIERS", "读取设备标识符", "设备标识", True),
    ("USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER", "用设备标识符进行 SIM 卡认证", "设备标识", True),

    ("GET_USAGE_STATS", "读取应用使用情况", "使用情况", True),
    ("GET_INSTALLED_APPS", "读取已安装应用列表", "应用列表", True),

    ("BODY_SENSORS", "身体传感器", "传感器", True),
    ("DIRECTION_SENSORS", "方向传感器", "传感器", True),
    ("ACTIVITY_RECOGNITION", "识别身体活动", "传感器", True),

    ("SYSTEM_ALERT_WINDOW", "显示在其他应用上层（悬浮窗）", "悬浮窗", True),
    ("TOAST_WINDOW", "显示提示框（Toast）", "悬浮窗", False),

    ("POST_NOTIFICATION", "发送通知", "通知", False),
    ("ACCESS_NOTIFICATIONS", "读取通知", "通知", True),

    ("BLUETOOTH_SCAN", "扫描附近的蓝牙设备", "附近设备", True),
    ("BLUETOOTH_CONNECT", "连接蓝牙设备", "附近设备", True),
    ("BLUETOOTH_ADVERTISE", "向附近设备发送蓝牙广播", "附近设备", True),
    ("NEARBY_WIFI_DEVICES", "查找附近的 WLAN 设备", "附近设备", True),
    ("UWB_RANGING", "超宽带（UWB）测距", "附近设备", True),

    ("BIND_ACCESSIBILITY_SERVICE", "绑定无障碍服务", "无障碍", True),
    ("ACCESS_ACCESSIBILITY", "使用无障碍功能", "无障碍", True),

    ("PROJECT_MEDIA", "录制或投放屏幕", "屏幕内容", True),
    ("ASSIST_STRUCTURE", "读取屏幕内容（助理）", "屏幕内容", True),
    ("ASSIST_SCREENSHOT", "截取屏幕（助理）", "屏幕内容", True),

    ("CHANGE_WIFI_STATE", "更改 WLAN 连接状态", "网络", False),

    ("RUN_IN_BACKGROUND", "在后台运行", "后台运行", False),
    ("RUN_ANY_IN_BACKGROUND", "在后台运行（不受限制）", "后台运行", False),
    ("START_FOREGROUND", "启动前台服务", "后台运行", False),
    ("BACKGROUND_START_ACTIVITY", "从后台打开界面", "后台运行", False),
    ("WAKE_LOCK", "阻止手机休眠", "后台运行", False),

    ("VIBRATE", "振动", "系统", False),
    ("TAKE_AUDIO_FOCUS", "占用音频焦点", "系统", False),
    ("PLAY_AUDIO", "播放音频", "系统", False),
    ("AUDIO_MASTER_VOLUME", "调节总音量", "系统", False),
    ("AUDIO_VOICE_VOLUME", "调节通话音量", "系统", False),
    ("AUDIO_RING_VOLUME", "调节铃声音量", "系统", False),
    ("AUDIO_MEDIA_VOLUME", "调节媒体音量", "系统", False),
    ("AUDIO_ALARM_VOLUME", "调节闹钟音量", "系统", False),
    ("AUDIO_NOTIFICATION_VOLUME", "调节通知音量", "系统", False),
    ("AUDIO_BLUETOOTH_VOLUME", "调节蓝牙音量", "系统", False),
    ("AUDIO_ACCESSIBILITY_VOLUME", "调节无障碍音量", "系统", False),
    ("WRITE_SETTINGS", "修改系统设置", "系统", False),
    ("ACCESS_RESTRICTED_SETTINGS", "受限设置", "系统", False),
    ("REQUEST_INSTALL_PACKAGES", "安装未知应用", "系统", False),
    ("SCHEDULE_EXACT_ALARM", "设置精确闹钟", "系统", False),
    ("PICTURE_IN_PICTURE", "画中画", "系统", False),
    ("TURN_SCREEN_ON", "点亮屏幕", "系统", False),
    ("USE_BIOMETRIC", "使用生物识别", "系统", False),
    ("USE_FINGERPRINT", "使用指纹", "系统", False),
]

OP_INFO = {op: {"zh": zh, "category": cat, "sensitive": sens} for op, zh, cat, sens in _OPS}

STATE_ZH = {
    "top": "前台",
    "fgsvc": "前台服务",
    "fgsvcl": "前台服务（位置）",
    "fg": "前台（非顶层）",
    "bg": "后台",
    "cch": "后台（缓存）",
    "pers": "常驻",
}


def op_info(op: str) -> dict:
    """Chinese name, category and sensitivity of an op; unknown ops keep the raw name."""
    info = OP_INFO.get(op)
    if info is None:
        return {"zh": op, "category": "其他", "sensitive": False}
    return dict(info)


_DUR_RE = re.compile(r"([+-])?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?")


def parse_duration_ms(text: str) -> int | None:
    """Android TimeUtils.formatDuration text ("+1d2h3m4s5ms", "+50ms", "0") -> ms.

    Returns None for text that is not a complete duration (e.g. cut off).
    """
    text = text.strip()
    if text in ("0", "+0", "-0"):
        return 0
    m = _DUR_RE.fullmatch(text)
    if not m or all(g is None for g in m.groups()[1:]):
        return None
    sign, d, h, mi, s, ms = m.groups()
    total = ((int(d or 0) * 24 + int(h or 0)) * 60 + int(mi or 0)) * 60 * 1000
    total += int(s or 0) * 1000 + int(ms or 0)
    return -total if sign == "-" else total


_UID_RE = re.compile(r"^\s*Uid (\S+):\s*$")
_UID_STATE_RE = re.compile(r"^\s*state=(\S+)\s*$")
_UID_MODE_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]*): mode=(\S+)\s*$")
_PKG_RE = re.compile(r"^\s*Package (\S+):\s*$")
_OP_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]*) \((.*)\):\s*$")
_ENTRY_RE = re.compile(
    r"^\s*(Access|Reject):\s*\[(\w+)-(\w+)\]\s*"
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)(.*)$")
_ENTRY_DUR_RE = re.compile(r"duration=(\S+)")
_ENTRY_PROXY_RE = re.compile(r"proxy\[(.*)\]")


def _read_lines(path) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    lines = text.split("\n")
    if not text.endswith("\n"):
        lines.pop()  # incomplete last line (or the empty tail of an empty file)
    return lines


def parse_appops_dump(path) -> dict:
    """Parse `dumpsys appops --package <pkg>` output.

    {"uid_state": "cch", "uid_modes": {op: mode},
     "ops": {op: {"mode": "allow", "entries": [{"kind","state","flags","time",
                                                 "duration_ms","proxy"}]}}}
    """
    uid_state = None
    uid_modes: dict[str, str] = {}
    ops: dict[str, dict] = {}
    section = None  # "uid" | "package"
    cur_op = None
    for line in _read_lines(path):
        if _UID_RE.match(line):
            section, cur_op = "uid", None
            continue
        if _PKG_RE.match(line):
            section, cur_op = "package", None
            continue
        if section == "uid":
            m = _UID_STATE_RE.match(line)
            if m:
                uid_state = uid_state or m.group(1)
                continue
            m = _UID_MODE_RE.match(line)
            if m:
                uid_modes[m.group(1)] = m.group(2)
            continue
        if section != "package":
            continue
        m = _OP_RE.match(line)
        if m:
            cur_op = m.group(1)
            mode = m.group(2).split(" / ")[0].strip()
            ops.setdefault(cur_op, {"mode": mode, "entries": []})["mode"] = mode
            continue
        m = _ENTRY_RE.match(line)
        if m and cur_op:
            kind, state, flags, time, rest = m.groups()
            dm = _ENTRY_DUR_RE.search(rest)
            pm = _ENTRY_PROXY_RE.search(rest)
            ops[cur_op]["entries"].append({
                "kind": "access" if kind == "Access" else "reject",
                "state": state,
                "flags": flags,
                "time": time,
                "duration_ms": parse_duration_ms(dm.group(1)) if dm else None,
                "proxy": pm.group(1) if pm else None,
            })
    return {"uid_state": uid_state, "uid_modes": uid_modes, "ops": ops}


def _to_second(text: str) -> datetime:
    return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")


def diff_appops(before: dict | None, after: dict, start: str, end: str) -> list[dict]:
    """Entries of `after` whose time lies in [start, end] (whole seconds, inclusive).

    Entries identical to one in `before` are left out. Entries that differ only
    in flags (self / proxy) are reported once. Sorted by time.
    -> [{"op","kind","state","time","duration_ms"}]
    """
    lo, hi = _to_second(start), _to_second(end)
    old = set()
    for op, data in ((before or {}).get("ops") or {}).items():
        for e in data["entries"]:
            old.add((op, e["kind"], e["state"], e["flags"], e["time"]))
    out: dict[tuple, dict] = {}
    for op, data in after.get("ops", {}).items():
        for e in data["entries"]:
            if (op, e["kind"], e["state"], e["flags"], e["time"]) in old:
                continue
            if not lo <= _to_second(e["time"]) <= hi:
                continue
            key = (op, e["kind"], e["state"], e["time"])
            rec = out.get(key)
            if rec is None:
                out[key] = {"op": op, "kind": e["kind"], "state": e["state"],
                            "time": e["time"], "duration_ms": e["duration_ms"]}
            elif rec["duration_ms"] is None:
                rec["duration_ms"] = e["duration_ms"]
    return sorted(out.values(), key=lambda r: (r["time"], r["op"], r["kind"], r["state"]))
