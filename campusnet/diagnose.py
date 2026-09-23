"""一次跑完的「网络体检」：这个网络到底限制了什么？

覆盖六类常见限制：
    1. 认证门户（Captive Portal）—— 连上了但没登录
    2. DNS                —— 解析不通，或只有特定服务器能用
    3. 客户端隔离          —— 同一网络里的设备互相看不见
    4. 端口封锁            —— 只放行 80/443，其他全拦
    5. 外网可达性          —— 到底是全断还是只有部分域名不行
    6. MTU                —— 小包能过、大包卡死

设计原则
--------
**不依赖 DNS 的测试优先。** 如果 DNS 本身是坏的，任何「先解析再连接」的
测试都会失败，但那是 DNS 的锅，不是目标服务的锅 —— 两者必须分开测，
否则你会得到一堆积压的假阴性。
"""

import concurrent.futures as cf
import errno
import socket
import struct
import time

from . import dnsproto, dnsfind, sysdns, util

# 全部用 IP，不依赖 DNS
TCP_TARGETS = [
    ("223.5.5.5", 53, "阿里 DNS (UDP/53 对照)"),
    ("223.5.5.5", 443, "阿里 DNS (443)"),
    ("119.29.29.29", 53, "腾讯 DNS"),
    ("114.114.114.114", 53, "114 DNS"),
    ("8.8.8.8", 53, "Google DNS"),
    ("1.1.1.1", 443, "Cloudflare"),
]

# 门户检测目标（明文 HTTP，不依赖 DNS）
PORTAL_TARGETS = [("223.5.5.5", "阿里 DNS"), ("114.114.114.114", "114 DNS")]


def _sock(host, port, timeout):
    s = socket.create_connection((host, port), timeout=timeout)
    s.close()
    return True


def tcp(host, port, timeout=3.0):
    t0 = time.time()
    _sock(host, port, timeout)
    return "连上了（%.0f ms）" % ((time.time() - t0) * 1000)


# ---------------- 1. 认证门户 ----------------

def _http_probe(host, path="/", port=80, timeout=4.0):
    """明文 HTTP 探测。被门户劫持时会返回 3xx + Location。"""
    import http.client
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        c.request("GET", path, headers={"User-Agent": "Mozilla/5.0"})
        r = c.getresponse()
        loc = r.getheader("Location") or ""
        body = r.read(200).decode("utf-8", "replace")
        return r.status, loc, body
    finally:
        c.close()


def _loc_host(loc):
    """从 Location 头里取出 主机[:端口]，用于判断「是不是都跳到同一个地址」。"""
    from urllib.parse import urlsplit
    try:
        sp = urlsplit(loc)
    except Exception:  # noqa: BLE001
        return loc
    return sp.netloc or sp.path.split("/")[0] or loc


def check_portal():
    """判断是不是「连上了但没认证」。

    判据只有两条，都必须能排除「服务器自己的正常跳转」：

        a) 明文 HTTP 拿到 200/204 —— 请求确实到达了目标服务器本身；
        b) 两个不同目标的 3xx Location 指向同一个地址 —— 只有中间设备
           统一劫持才会这样（不同服务器各自跳转的落点不会一致）。

    单独一个 3xx（比如 1.1.1.1 对 http:// 返回 301）**不能**当证据：
    那是它自己的策略，任何正常网络都会发生。之前的实现把这种也算成
    「认证门户劫持」，会给出假阳性的定性结论。
    """
    util.head("1. 认证门户（Captive Portal）")
    util.note("原理：没认证时，网关会把明文 HTTP 请求劫持到登录页。")
    util.note("判据：a) 拿到 200/204；b) 两个不同目标跳到同一个地址。")
    util.note("      单个 3xx 不算 —— 那是服务器自己的跳转。")
    print()

    obs = []
    for host, name in PORTAL_TARGETS:
        def go(h=host):
            st, loc, _b = _http_probe(h)
            obs.append((h, st, loc))
            return "HTTP %d%s" % (st, ("  -> %s" % loc) if loc else "")
        util.stage("明文 HTTP  %s (%s)" % (host, name), go)

    print()
    clean = [o for o in obs if o[1] in (200, 204)]
    if clean:
        util.ok("明文请求直达目标服务器（HTTP %d）—— 没有门户劫持" % clean[0][1])
        return "ok"

    redirects = [(o[0], o[2]) for o in obs if 300 <= o[1] < 400 and o[2]]
    if len(redirects) >= 2 and len({_loc_host(loc) for _h, loc in redirects}) == 1:
        util.warn("检测到认证门户劫持：%d 个不同目标被跳到同一个地址" % len(redirects))
        util.note("登录地址：%s" % redirects[0][1])
        util.note("→ 用浏览器打开任意 http:// 网站，登录后重试")
        return "portal"

    util.warn("本节未能定性（既不满足 a 也不满足 b）")
    util.note("HTTP 404/403、单个 3xx、连接被拒 —— 这些都不能证明有门户。")
    util.note("想确认的话：用浏览器打开任意 http:// 网站，看会不会跳到登录页。")
    return "unknown"


# ---------------- 2. DNS ----------------

def check_dns():
    util.head("2. DNS")
    sysd = sysdns.system_dns()
    util.item("系统配置的 DNS", ", ".join(sysd) or "（读不到）")
    util.note("提示：%s" % sysdns.resolver_hint())
    print()

    if sysd:
        for s in sysd[:3]:
            def go(srv=s):
                ips = dnsproto.resolve_a(srv, "www.baidu.com", timeout=3)
                return "可用 -> %s" % ",".join(ips[:2])
            util.stage("测试 %s" % s, go)

    print()
    util.note("对照：公共 DNS 在这个网络下能不能用")
    for s in ["223.5.5.5", "119.29.29.29", "8.8.8.8"]:
        def go2(srv=s):
            ips = dnsproto.resolve_a(srv, "www.baidu.com", timeout=2)
            return "可用 -> %s" % ips[0]
        util.stage("公共 %s" % s, go2)

    return sysd


# ---------------- 3. 客户端隔离 ----------------

def tcp_probe(host, port, timeout=1.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def check_isolation(prefix=None, ports=(80, 443, 22, 445, 3389, 8080)):
    """扫本机所在 /24，看能不能看到别的设备。"""
    util.head("3. 客户端隔离")
    util.note("原理：校园网常把每台设备关进「单间」，同网段互相看不见。")
    util.note("      扫一遍本网段，如果有别的设备在监听端口，说明没隔离。")
    print()

    pre = prefix or util.local_subnet(24)
    if not pre:
        util.warn("读不到本机地址，跳过")
        return None

    me = util.local_ip()
    util.item("本机", me)
    util.item("扫描范围", pre + "0/24")

    found = []
    hosts = [pre + str(i) for i in range(1, 255) if pre + str(i) != me]
    t0 = time.time()

    def probe(h):
        for p in ports:
            if tcp_probe(h, p):
                return (h, p)
        return None

    with cf.ThreadPoolExecutor(max_workers=128) as ex:
        for r in ex.map(probe, hosts):
            if r:
                found.append(r)

    print()
    util.item("耗时", "%.1f 秒" % (time.time() - t0))
    if found:
        util.ok("发现 %d 台设备 —— 没有客户端隔离" % len(found))
        for h, p in found[:8]:
            util.note("%s:%d" % (h, p))
        return "open"
    util.warn("整个 /24 一台都没发现 —— 大概率开了客户端隔离")
    util.note("（也可能这个网段本来就没别人。cross-check：能不能 ping 通网关？）")
    return "isolated"


# ---------------- 4. 端口封锁 ----------------

def check_ports():
    util.head("4. 端口与外网可达性（全部用 IP，不依赖 DNS）")
    util.note("这一节的意义：把「DNS 坏了」和「网络真的不通」分开。")
    print()

    results = {}
    for host, port, name in TCP_TARGETS:
        def go(h=host, p=port):
            return tcp(h, p)
        results["%s:%d" % (host, port)] = util.stage("%-22s %s:%d" % (name, host, port), go)

    print()
    ok_count = sum(1 for v in results.values() if v)
    util.item("可达", "%d / %d" % (ok_count, len(results)))
    if ok_count == 0:
        util.fail("对外一个端口都不通 —— 网络层就没出去")
    elif ok_count == len(results):
        util.ok("全部可达 —— 没有端口封锁")
    else:
        util.warn("部分可达 —— 存在端口封锁")
    return results


# ---------------- 5. MTU ----------------

MTU_HOST, MTU_PORT = "223.5.5.5", 53
MTU_DF_SIZES = (1200, 1400, 1472, 4000, 65000)
MTU_SEARCH_MAX = 9000      # 二分搜索的载荷上界

# Linux 的 IP_MTU_DISCOVER / IP_PMTUDISC_DO 在 Python 的 socket 模块里没有导出常量，
# 这里按 Linux 内核头文件里的值兜底（实测 Python 3.12 无此属性）。
_IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
_IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)


def _df_sendto(host, port, size):
    """带 DF 的 UDP 发送。返回 'ok' / 'emsgsize' / 'unsupported' / 'error: ...'。

    DF（IP_MTU_DISCOVER=IP_PMTUDISC_DO）是这一节的关键：
    不带 DF 的探测测不出任何 MTU 问题 —— 内核会把大包分片发出去，照样成功。
    """
    if util.system() != "linux":
        return "unsupported"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            s.setsockopt(socket.IPPROTO_IP, _IP_MTU_DISCOVER,
                         struct.pack("i", _IP_PMTUDISC_DO))
        except (AttributeError, OSError):
            return "unsupported"
        s.settimeout(1.0)
        try:
            s.connect((host, port))
            s.send(b"x" * size)
            return "ok"
        except OSError as e:
            if e.errno == errno.EMSGSIZE:
                return "emsgsize"
            return "error: %s" % e
    finally:
        s.close()


def check_mtu():
    """只报「内核允许带 DF 发出的最大载荷」，不冒充链路 MTU。

    为什么不用 HTTP POST 大小来测：TCP 会按 MSS 分段，多大的请求都能发出去，
    所以「POST 65000 字节返回 404」不能证明 MTU 正常。
    另外**这一节给不出确定的路径 MTU**：非 root 发不了 ICMP，
    链路中间若丢弃「需要分片」的 ICMP 且 ICMP 被墙，探测就看不见。
    """
    util.head("5. 大包 / MTU")
    util.note("原理：链路 MTU 太小时，带 DF（不分片）的大包会被静默丢弃。")
    util.note("做法：对 UDP 套接字设 IP_MTU_DISCOVER=IP_PMTUDISC_DO，")
    util.note("      看多大的载荷会被内核以 EMSGSIZE 拒绝。")
    print()

    unsupported = False
    for size in MTU_DF_SIZES:
        r = _df_sendto(MTU_HOST, MTU_PORT, size)
        if r == "unsupported":
            unsupported = True
            break
        if r == "ok":
            util.ok("发 %6d 字节（带 DF）—— 内核允许发送" % size)
        elif r == "emsgsize":
            util.fail("发 %6d 字节（带 DF）—— EMSGSIZE，超过 MTU" % size)
        else:
            util.warn("发 %6d 字节（带 DF）—— %s" % (size, r))

    print()
    if unsupported:
        util.warn("本节未能定性：本平台不支持 IP_MTU_DISCOVER，做不了带 DF 的探测。")
        util.note("（Windows 用的是另一套选项，本工具没实现。）")
        return None

    if _df_sendto(MTU_HOST, MTU_PORT, MTU_SEARCH_MAX) == "ok":
        util.ok("%d 字节带 DF 都能发出 —— 本机这一路径的 MTU 不是当前瓶颈" % MTU_SEARCH_MAX)
        util.note("注意：这只说明「本机到该目标」没问题，不代表所有目标都一样。")
        return MTU_SEARCH_MAX

    lo, hi = 576, MTU_SEARCH_MAX       # 不变式：lo 允许、hi 不允许
    if _df_sendto(MTU_HOST, MTU_PORT, lo) != "ok":
        util.warn("连 576 字节带 DF 都发不出去 —— 本节未能定性。")
        return None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _df_sendto(MTU_HOST, MTU_PORT, mid) == "ok":
            lo = mid
        else:
            hi = mid

    util.item("带 DF 可发送上限（估计）", "%d 字节 UDP 载荷" % lo, 28)
    util.item("对应 MTU（估计）", "≈ %d 字节（载荷 + 8 UDP + 20 IP）" % (lo + 28), 28)
    util.note("这是内核当前已知的路径 MTU 上限，不是端到端保证：")
    util.note("  链路中间若有更小的 MTU 且「需要分片」的 ICMP 被丢弃/墙掉，本探测看不到。")
    util.note("要精确确认，用 ping -M do -s <载荷> <目标> 逐点试（需管理员/root）。")
    util.note("旧版本用 HTTP POST 四个尺寸来测，TCP 会按 MSS 分段，四个尺寸必然全 OK ——")
    util.note("那种做法测不出 MTU 问题，本工具已不再据此建议改 MTU。")
    return lo


# ---------------- 汇总 ----------------

def run(prefix=None, skip_scan=False):
    util.head("网络体检")
    util.item("时间", time.strftime("%Y-%m-%d %H:%M:%S"))
    util.item("平台", "%s%s" % (util.system(), " (Android/proot)" if util.is_android() else ""))

    util.head("0. 网络身份")
    util.item("本机地址", util.local_ip() or "（读不到）")
    gw, gwsrc = dnsfind.default_gateway(with_source=True)
    util.item("默认网关", "%s%s" % (gw or "（读不到）",
                                "  ← 猜的，读不到路由表" if gwsrc == "guess" else ""))
    util.item("Docker/容器", "可能在 NAT 后面" if util.local_ip() and
              util.local_ip().startswith(("10.0.", "172.17.")) else "否")

    portal = check_portal()
    dns = check_dns()
    iso = None if skip_scan else check_isolation(prefix)
    ports = check_ports()
    check_mtu()

    # ---------- 结论 ----------
    util.head("结论")
    verdict = []
    if portal == "portal":
        verdict.append(("先登录认证门户", "照上面给出的地址去浏览器登录"))
    if dns:
        verdict.append(("用系统配置的 DNS", "本次测量里公共 DNS 不可用，别急着去改它"))
    else:
        verdict.append(("读不到系统 DNS", "先解决这个，否则后面全是假阴性"))
    if iso == "isolated":
        verdict.append(("设备间被隔离", "该限制存在；哪些用途被允许请向学校信息化中心确认"))
    okc = sum(1 for v in ports.values() if v) if ports else 0
    if ports and okc == 0:
        verdict.append(("网络层不通", "先解决认证/出口，再谈别的"))
    verdict.append(("系统 DNS 不可用时钉 hosts", "用 pinhosts 命令（每个 IP 过 TLS 校验证书）"))

    for i, (what, how) in enumerate(verdict, 1):
        print("  %d. %-18s %s" % (i, what, how))
    print()
    return verdict
