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
import socket
import ssl
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

PORT_PROBE = [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (8080, "HTTP-alt")]


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


def check_portal():
    """判断是不是「连上了但没认证」。"""
    util.head("1. 认证门户（Captive Portal）")
    util.note("原理：没认证时，网关会把明文 HTTP 请求劫持到登录页。")
    util.note("      所以看「有没有被重定向」即可判断。")
    print()

    hijacked = []
    for host, name in [("223.5.5.5", "阿里 DNS"), ("114.114.114.114", "114 DNS")]:
        def go(h=host):
            st, loc, _b = _http_probe(h)
            if 300 <= st < 400 and loc:
                hijacked.append((h, loc))
                return "被重定向 -> %s" % loc
            return "HTTP %d（正常，无劫持）" % st
        util.stage("明文 HTTP  %s (%s)" % (host, name), go)

    print()
    if hijacked:
        util.warn("检测到认证门户劫持！")
        util.note("登录地址：%s" % hijacked[0][1])
        util.note("→ 用浏览器打开任意 http:// 网站，登录后重试")
        return "portal"
    util.ok("没有门户劫持 —— 要么已认证，要么这个网络不需要认证")
    return "ok"


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

def check_mtu():
    util.head("5. 大包 / MTU")
    util.note("原理：有些链路小包能过、大包被静默丢弃。表现是「网页能开、传文件卡死」。")
    print()

    def send(size):
        import http.client
        body = b"x" * size
        c = http.client.HTTPConnection("223.5.5.5", 80, timeout=6)
        try:
            c.request("POST", "/", body=body, headers={"Content-Type": "text/plain"})
            r = c.getresponse()
            return "HTTP %d（发了 %d 字节）" % (r.status, size)
        finally:
            c.close()

    for size in (1200, 4000, 16000, 65000):
        try:
            util.stage("发 %6d 字节" % size, lambda s=size: send(s))
        except Exception:
            pass

    print()
    util.note("如果小包通、大包超时 → MTU 问题，把网卡 MTU 调到 1400 试试")


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
        verdict.append(("用系统配置的 DNS", "公共 DNS 在这个网络下不可用，别去改它"))
    else:
        verdict.append(("读不到系统 DNS", "先解决这个，否则后面全是假阴性"))
    if iso == "isolated":
        verdict.append(("设备间被隔离", "别指望靠局域网直连，走热点或中继"))
    okc = sum(1 for v in ports.values() if v) if ports else 0
    if ports and okc == 0:
        verdict.append(("网络层不通", "先解决认证/出口，再谈别的"))
    verdict.append(("想钉 hosts 绕过 DNS", "用 pinhosts 命令"))

    for i, (what, how) in enumerate(verdict, 1):
        print("  %d. %-18s %s" % (i, what, how))
    print()
    return verdict
