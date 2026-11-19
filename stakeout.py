#!/usr/bin/env python3
"""Stakeout command line: run / fetch / analyze / list / ui (docs/CONTRACT.md, "appwatch.py", now stakeout.py;
docs/CONTRACT_PHONE.md for phone runs and ui)."""

import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # `import aw` also when started from another directory


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, f"参数有误（{message}），用 -h 查看用法。\n")


# argparse builds its own texts (usage, help, errors) through its module-level gettext function `_`;
# main() puts these Chinese versions of its Python 3.12 message ids in for the duration of parsing.
_ARGPARSE_ZH = {
    "usage: ": "用法：",
    "positional arguments": "参数",
    "options": "选项",
    "show this help message and exit": "显示这段说明并退出",
    "argument %(argument_name)s: %(message)s": "%(argument_name)s：%(message)s",
    "invalid choice: %(value)r (choose from %(choices)s)": "没有 %(value)r 这一项，可以用的是 %(choices)s",
    "the following arguments are required: %s": "缺少必填的参数：%s",
    "unrecognized arguments: %s": "不认识的参数：%s",
    "expected one argument": "后面要跟一个值",
    "ambiguous option: %(option)s could match %(matches)s": "%(option)s 有歧义，可能是 %(matches)s",
    "one of the arguments %s is required": "缺少必填的参数：%s 中的一个",
    "not allowed with argument %s": "不能和 %s 一起用",
}


SHOW_SECRETS_HELP = "报告里显示 Cookie、令牌、设备标识等被隐藏的值的原值（默认只显示长度）"
# run --decrypt (the key route, docs/CONTRACT_KEYLOG.md) while the app already had a process: what that
# costs and what to do. Stakeout never stops or starts the app itself.
RUNNING_ZH = ("注意：开始采集时这个应用已经在运行。它在采集开始前建立的加密连接没有记录到密钥，解不开。"
              "要避免这种情况：结束这次采集，在手机上彻底停止这个应用（系统设置的应用信息里点“强行停止”），"
              "再重新开始采集，看到“已开始采集”后再打开应用。")
DECRYPTING_ZH = ("正在记录密钥：eCapture 在应用建立加密连接时记下密钥，采集结束后用 tshark 解开抓到的数据包。"
                 "采集开始前已建立的连接、应用用自带的加密库（例如 Cronet）建立的连接解不开。")
TSHARK_MISSING_ZH = ("找不到 tshark：--decrypt 要在电脑上用 Wireshark 自带的 tshark 解开抓包。"
                     "请从 https://www.wireshark.org 下载安装 Wireshark，或用环境变量 AW_TSHARK 指定 tshark 的路径。")
# run --all --decrypt: the whole-phone counterpart of RUNNING_ZH, said every time (no app is looked up).
PHONE_DECRYPT_ZH = ("要尽量多地解开：采集开始后，把你关心的应用彻底停止（系统设置的应用信息里点“强行停止”）"
                    "再重新打开。它们在采集开始前建立的加密连接解不开。")
HAR_PHONE_ZH = "--har 只能用于只看一个应用的采集：整部手机的采集分不清 HAR 文件里的请求是哪个应用发的。"


def _positive(text):
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n <= 0:
        raise argparse.ArgumentTypeError(f"需要一个正整数，收到的是 {text}")
    return n


def _fail(message):
    print(message, file=sys.stderr)
    return 1


def _report(run_dir, out_dir, show_secrets=False, har=None, phone=False):
    """A phone run: overview.json and the apps' downloads (aw.phonewide). A one-app run: result.json
    and report.html as before, then overview.json and the app's downloads (aw.overview)."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        writable = os.access(out_dir, os.W_OK)
    except OSError:
        writable = False
    if not writable:
        return _fail(f"无法写入 {out_dir}：请用 --out 指定一个可写的目录。")
    if phone:
        from aw import phonewide
        phonewide.analyze_phone(run_dir, out_dir)
        print(f"概览已生成：{out_dir / 'overview.json'}")
        return 0
    from aw import analyze, report

    try:
        result = analyze.analyze(run_dir, out_dir, har=har)
    except ValueError as e:     # parse_har: the given file is not a HAR file (one Chinese sentence)
        if har is None:
            raise
        return _fail(str(e))
    path = out_dir / "report.html"
    path.write_text(report.render(result, show_secrets=show_secrets), encoding="utf-8")
    print(f"报告已生成：{path}")
    from aw import overview
    overview.write_app_run(result, out_dir)
    return 0


def _wait(seconds, max_seconds, phone=False):
    try:
        if seconds:
            print(f"正在采集，{seconds} 秒后自动结束（按 Ctrl+C 可提前结束）。")
            time.sleep(seconds)
        else:
            use = "照常使用手机" if phone else "在手机上正常使用这个应用"
            input(f"正在采集。请{use}，结束时按回车（Ctrl+C 也可以）。"
                  f"最长 {max_seconds // 60} 分钟，到时手机会自行停止采集。")
    except (KeyboardInterrupt, EOFError):
        print()


def _still_stopping(signum, frame):
    print("\n正在停止采集，请稍候……", file=sys.stderr)


def _not_a_run_dir(run_dir):
    """--out names an existing file, or a directory with other files and no meta.json: stop()
    would delete and overwrite files there that have the names of raw files."""
    if not run_dir.exists():
        return False
    if not run_dir.is_dir():
        return True
    return any(run_dir.iterdir()) and not (run_dir / "meta.json").is_file()


def _remove_if_empty(run_dir, created):
    if created:
        try:
            run_dir.rmdir()      # only when nothing was saved into it
        except OSError:
            pass


def _stop(stop, dev, run_dir):
    """collect.stop / collect.fetch with Ctrl+C held off: (meta, error)."""
    from aw.device import DeviceError

    previous = signal.signal(signal.SIGINT, _still_stopping)   # a second Ctrl+C must not cut the stop short
    try:
        return stop(dev, run_dir), None
    except DeviceError as e:
        return None, e
    finally:
        signal.signal(signal.SIGINT, previous)


def _finish(run_dir, created, meta, stop_error, show_secrets, phone=False):
    from aw import collect

    if stop_error is not None:
        _fail(f"停止采集时出错：{stop_error}")
        if (run_dir / "meta.json").is_file():   # the data was saved; only cleaning the phone failed
            _report(run_dir, run_dir, show_secrets, phone=phone)
        else:
            _remove_if_empty(run_dir, created)
        return 1
    if (meta or {}).get("autostop"):
        why = collect.AUTOSTOP_ZH.get(meta["autostop"], meta["autostop"])
        print(f"手机已在 {str(meta.get('end_time'))[11:]} 自行停止采集：{why}。")
    print(f"原始数据已保存到：{run_dir}")
    return _report(run_dir, run_dir, show_secrets, phone=phone)


def _default_run_dir(name):
    return Path("runs") / f"{name}-{datetime.now():%Y%m%d-%H%M%S}"


def cmd_run(args):
    from aw import collect
    from aw.device import Device, DeviceError

    if args.seconds is None and not sys.stdin.isatty():
        return _fail("当前没有可以按回车的终端：请用 --seconds 指定采集秒数。")
    pkg = None if args.all else args.package     # None: the whole phone
    run_dir = Path(args.out) if args.out else _default_run_dir(pkg or "phone")
    if _not_a_run_dir(run_dir):
        return _fail(f"{run_dir} 不是空目录，也不是 Stakeout 的运行目录：请用 --out 指定一个新目录或空目录。")
    if args.decrypt:        # said before the phone is contacted (after a failed start, stop() runs on the phone)
        from aw.device import BUNDLED_ECAPTURE, find_ecapture, find_tshark
        if args.no_net:
            return _fail("--decrypt 要用抓到的数据包来解密，不能和 --no-net 一起用。")
        if find_tshark() is None:
            return _fail(TSHARK_MISSING_ZH)
        if find_ecapture() is None:
            return _fail(f"找不到 eCapture 程序，无法解密：请用环境变量 AW_ECAPTURE 指定它的路径，或把它放在 {BUNDLED_ECAPTURE}。")
    try:
        if pkg is not None:
            collect.check_package_name(pkg)
        dev = Device(serial=args.serial)
        dev.check()
    except DeviceError as e:
        return _fail(str(e))
    created = not run_dir.exists()
    run_dir.mkdir(parents=True, exist_ok=True)

    max_seconds = args.seconds + collect.STOP_MARGIN_S if args.seconds else collect.MAX_CAPTURE_S
    start_error = None
    try:
        info = collect.start(dev, pkg, net=not args.no_net, filetrace=not args.no_filetrace,
                             max_seconds=max_seconds, decrypt=args.decrypt)
        if pkg is None:
            print("已开始观察整部手机（所有应用）。")
        else:
            print(f"已开始采集 {pkg}（版本 {info.get('version_name')}，uid {info.get('uid')}）。")
        unavailable = info.get("unavailable") or []
        for code in unavailable:
            print(collect.UNAVAILABLE_ZH.get(code, code))
        if args.decrypt:
            if info.get("decrypt"):
                print(DECRYPTING_ZH)
                if pkg is None:
                    print(PHONE_DECRYPT_ZH)
                elif info.get("running"):
                    print(RUNNING_ZH)
            elif "ecapture" not in unavailable:     # otherwise the line above already said why
                print("eCapture 没有启动，本次不解密 HTTPS 内容。")
        _wait(args.seconds, max_seconds, phone=pkg is None)
    except KeyboardInterrupt:
        print()
    except collect.CaptureLeft as e:     # an earlier capture is on the phone: leave it alone
        _remove_if_empty(run_dir, created)
        return _fail(str(e))
    except DeviceError as e:
        start_error = e

    if start_error is None:
        print("正在停止采集并取回数据……")
    # After a failed start this only clears what the start may have left on the phone; it then
    # usually reports "nothing to stop", which says nothing about why the start failed.
    meta, stop_error = _stop(collect.stop, dev, run_dir)
    if start_error is not None:
        _remove_if_empty(run_dir, created)
        return _fail(str(start_error))
    return _finish(run_dir, created, meta, stop_error, args.show_secrets, phone=pkg is None)


def cmd_fetch(args):
    from aw import collect
    from aw.device import Device, DeviceError

    try:
        dev = Device(serial=args.serial)
        dev.check()
        left = collect.pending(dev)
    except DeviceError as e:
        return _fail(str(e))
    if left is None:
        print("手机上没有以前留下的采集。")
        return 0
    phone = left.get("scope") == "phone"
    name = "phone" if phone else left.get("package") or "unknown"
    run_dir = Path(args.out) if args.out else _default_run_dir(name)
    if _not_a_run_dir(run_dir):
        return _fail(f"{run_dir} 不是空目录，也不是 Stakeout 的运行目录：请用 --out 指定一个新目录或空目录。")
    created = not run_dir.exists()
    print("正在停止手机上的采集并取回数据……" if left["running"] else "正在取回手机上的数据……")
    meta, stop_error = _stop(collect.fetch, dev, run_dir)
    return _finish(run_dir, created, meta, stop_error, args.show_secrets, phone=phone)


def cmd_analyze(args):
    run_dir = Path(args.run_dir)
    if not (run_dir / "meta.json").is_file():
        return _fail(f"{run_dir} 里没有 meta.json：请指定 Stakeout 采集生成的运行目录。")
    try:
        meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
        complete = isinstance(meta, dict) and all(k in meta for k in ("package", "uid", "app_id",
                                                                       "start_time", "end_time"))
    except (OSError, ValueError):
        complete = False
    if not complete:
        return _fail(f"{run_dir / 'meta.json'} 已损坏或不完整：请指定 Stakeout 采集生成的运行目录。")
    phone = meta.get("scope") == "phone"      # runs made before v0.4 have no scope: one app
    har = Path(args.har) if args.har else None
    if har is not None:
        if phone:
            return _fail(HAR_PHONE_ZH)
        if not har.is_file():
            return _fail(f"找不到 HAR 文件 {har}：请检查 --har 后面的路径。")
        if not os.access(run_dir, os.W_OK):      # the HAR file is kept in the run directory as mitm.har
            return _fail(f"无法把 HAR 文件保存到 {run_dir}：运行目录不可写，请先把运行目录复制到可写的位置。")
    return _report(run_dir, Path(args.out) if args.out else run_dir, args.show_secrets, har, phone=phone)


def cmd_list(args):
    from aw import collect
    from aw.device import Device, DeviceError

    try:
        dev = Device(serial=args.serial)
        dev.check()
        listed = collect.list_packages(dev)
    except DeviceError as e:
        return _fail(str(e))
    keyword = (args.keyword or "").lower()
    packages = sorted(p["package"] for p in listed if p["third_party"] and keyword in p["package"].lower())
    if not packages:
        print(f"没有找到包名包含“{args.keyword}”的第三方应用。" if args.keyword else "手机上没有第三方应用。")
    for p in packages:
        print(p)
    return 0


def cmd_ui(args):
    from aw import ui

    return ui.serve(port=args.port, open_browser=not args.no_open)    # 1: the port could not be opened


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    translate = argparse._
    argparse._ = lambda text: _ARGPARSE_ZH.get(text) or translate(text)
    try:
        parser = _parser()
        if not argv:               # no command: show how to use it
            parser.print_help()
            return 2
        args = parser.parse_args(argv)
    finally:
        argparse._ = translate
    return {"run": cmd_run, "fetch": cmd_fetch, "analyze": cmd_analyze, "list": cmd_list,
            "ui": cmd_ui}[args.command](args)


def _parser():
    parser = _Parser(prog="stakeout.py", description="Stakeout：从手机外部观察应用做了什么（一个应用，或整部手机上的所有应用），"
                                                     "生成中文报告和概览（需要已 root 的安卓手机）。")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{run,fetch,analyze,list,ui}")

    run = sub.add_parser("run", help="采集一段时间，然后生成报告和概览")
    target = run.add_mutually_exclusive_group(required=True)
    target.add_argument("package", nargs="?", help="应用包名，例如 com.xingin.xhs")
    target.add_argument("--all", action="store_true", help="观察整部手机上的所有应用（这时不填包名）")
    run.add_argument("--seconds", type=_positive, help="采集多少秒；不填则按回车结束")
    run.add_argument("--out", help="运行目录，默认 ./runs/<包名>-<时间>/，--all 时是 ./runs/phone-<时间>/")
    run.add_argument("--no-net", action="store_true", help="不抓包")
    run.add_argument("--no-filetrace", action="store_true", help="不跟踪文件访问")
    run.add_argument("--decrypt", action="store_true",
                     help="解密 HTTPS 内容：手机上用 eCapture 记下应用加密连接的密钥，结束后在电脑上用 tshark 解开抓包"
                          "（需要 Wireshark，不需要安装证书，不能和 --no-net 一起用）")
    run.add_argument("--show-secrets", action="store_true", help=SHOW_SECRETS_HELP)
    run.add_argument("--serial", help="连接了多台设备时，指定设备序列号")

    fet = sub.add_parser("fetch", help="停止并取回手机上以前留下的采集（例如采集时连接断开了），然后生成报告和概览")
    fet.add_argument("--out", help="运行目录，默认 ./runs/<包名>-<时间>/")
    fet.add_argument("--show-secrets", action="store_true", help=SHOW_SECRETS_HELP)
    fet.add_argument("--serial", help="连接了多台设备时，指定设备序列号")

    ana = sub.add_parser("analyze", help="用保存的原始数据重新生成报告和概览，不需要手机")
    ana.add_argument("run_dir", help="运行目录")
    ana.add_argument("--out", help="结果和报告写到哪个目录，默认写回运行目录")
    ana.add_argument("--har", metavar="FILE",
                     help="导入你自己用代理录制的 HAR 文件（复制到运行目录的 mitm.har），见 docs/MITM.md")
    ana.add_argument("--show-secrets", action="store_true", help=SHOW_SECRETS_HELP)

    lst = sub.add_parser("list", help="列出手机上的第三方应用")
    lst.add_argument("keyword", nargs="?", help="只列出包名包含这个词的应用")
    lst.add_argument("--serial", help="连接了多台设备时，指定设备序列号")

    web = sub.add_parser("ui", help="打开本机网页：在网页上开始采集、查看这次和以前的结果")
    web.add_argument("--port", type=_positive, default=8765, help="网页用的端口，默认 8765")
    web.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    return parser


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
        sys.exit(130)
