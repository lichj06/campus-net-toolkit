"""共用：终端输出、计时、平台判定、本机地址。"""

import platform
import shutil
import socket
import sys
import time

# ---------- 终端输出 ----------

_COLOR = sys.stdout.isatty() and platform.system() != "Windows"


def _c(code, text):
    return "\033[%sm%s\033[0m" % (code, text) if _COLOR else text


def head(title):
    """章节标题。"""
    print()
    print("=" * 64)
    print(title)
    print("=" * 64)


def ok(msg):
    print("  [OK]   " + str(msg))


def fail(msg):
    print("  [FAIL] " + _c("31", str(msg)))


def warn(msg):
    print("  [WARN] " + _c("33", str(msg)))


def note(msg):
    print("         " + str(msg))


def item(name, value, width=32):
    """一行「名称 …… 值」。"""
    print("  %-*s %s" % (width, name, value))


def stage(name, fn):
    """跑一个测试，自动计时并打印结果。

    fn 正常返回则打 [OK]，抛异常则打 [FAIL]。返回值原样传出（失败为 None）。
    """
    t0 = time.time()
    try:
        r = fn()
        ms = (time.time() - t0) * 1000
        print("  [OK]   %-*s %6.0f ms  %s" % (30, name, ms, r))
        return r
    except Exception as e:  # noqa: BLE001 —— 诊断工具要吃掉一切异常
        ms = (time.time() - t0) * 1000
        fail("%-*s %6.0f ms  %s: %s" % (30, name, ms, type(e).__name__, e))
        return None


# ---------- 平台 ----------

def system():
    """返回 'windows' / 'darwin' / 'linux' / 其他。"""
    s = platform.system().lower()
    if s.startswith("win"):
        return "windows"
    if s == "darwin":
        return "darwin"
    return "linux"


def is_android():
    """在 Android 的 proot/Termux 里跑时返回 True。"""
    return "android" in platform.platform().lower() or shutil.which("getprop") is not None


def have(cmd):
    return shutil.which(cmd)


# ---------- 网络 ----------

_PROBE_TARGET = ("192.0.2.1", 9)   # RFC 5737 TEST-NET-1，仅用于选路，不会真的发包


def local_ip():
    """本机在默认路由上的地址。

    对 UDP 套接字调用 connect() 只查路由表、不发包，所以目标地址不需要可达，
    只要「能匹配上一条默认路由」即可。这里用 192.0.2.1:9（RFC 5737 文档保留段）
    而不是某个具体网络的解析器地址 —— 后者换到别的网络可能匹配到别的网卡，
    甚至直接失败，导致上层（lanfind/diagnose）误判成「读不到本机地址」。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(3)
        s.connect(_PROBE_TARGET)
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def local_subnet(prefix_len=24):
    """本机所在的 /24 前缀，如 '192.0.2.'。"""
    ip = local_ip()
    if not ip:
        return None
    parts = ip.split(".")
    keep = prefix_len // 8
    return ".".join(parts[:keep]) + "."
