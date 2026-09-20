"""找出「这个网络下真正能用」的 DNS 服务器。

这是本工具最有用的命令。

思路
----
1. 先问系统：你现在配的是哪几台？（很多人跳过这一步，直接去测公共 DNS）
2. 再加上默认网关（很多网络把解析器放在网关上）
3. 再加上几台常见公共 DNS 做对照
4. 逐台实测 —— **UDP 和 TCP 分别测**，因为有些网络封 UDP/53 但放行 TCP/53
5. 给出结论和可落地的建议

为什么 UDP/TCP 要分开测
-----------------------
实测遇到过：同一台服务器 UDP 查询 3 秒超时，TCP 查询 3 毫秒返回。
只测 UDP 会得出「这台不能用」的错误结论。
"""

import concurrent.futures as cf
import time

from . import dnsproto, sysdns, util

# 常见公共 DNS（做对照，不是重点）
PUBLIC = [
    ("223.5.5.5", "阿里"),
    ("223.6.6.6", "阿里备用"),
    ("119.29.29.29", "腾讯"),
    ("114.114.114.114", "114"),
    ("180.76.76.76", "百度"),
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
]

PROBE_NAME = "www.baidu.com"      # 国内可达，解析快，适合做探针
PROBE_TIMEOUT = 2.5


def default_gateway(with_source=False):
    """取默认网关。返回 IP，或 (IP, 来源)。

    来源 'route' = 从路由表读到，'guess' = 按 X.Y.Z.1 猜的。

    为什么要区分：手机上常常读不到路由表（没有 ip 命令、/proc/net/route 也不可读），
    只能猜。**猜错的时候不能拿它当证据** —— 否则会得出「网络层不通」这种错误结论。
    """
    gw, src = _default_gateway_impl()
    return (gw, src) if with_source else gw


def _default_gateway_impl():
    sysname = util.system()

    if sysname == "windows":
        ps = ("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
              "-ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
              "Select-Object -First 1).NextHop")
        import subprocess
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                               capture_output=True, text=True, timeout=8)
            gw = (r.stdout or "").strip()
            if gw and gw[0].isdigit():
                return gw, "route"
        except Exception:
            pass
        return None, None

    if sysname == "darwin":
        import subprocess
        try:
            r = subprocess.run(["route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=5)
            for line in (r.stdout or "").splitlines():
                if "gateway:" in line:
                    return line.split(":", 1)[1].strip(), "route"
        except Exception:
            pass
        return None, None

    import subprocess
    try:
        r = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        for line in (r.stdout or "").splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1], "route"
    except Exception:
        pass
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000":
                    n = int(cols[2], 16)
                    return ("%d.%d.%d.%d" % (n & 0xFF, (n >> 8) & 0xFF,
                                             (n >> 16) & 0xFF, (n >> 24) & 0xFF), "route")
    except Exception:
        pass

    ip = util.local_ip()
    if ip:
        return ip.rsplit(".", 1)[0] + ".1", "guess"
    return None, None


def probe(server, name=PROBE_NAME, timeout=PROBE_TIMEOUT):
    """测一台服务器。返回 dict，含 udp/tcp 各自的结果。"""
    r = {"server": server, "udp": None, "tcp": None, "udp_ms": None, "tcp_ms": None,
         "ips": [], "error": None}

    t0 = time.time()
    try:
        rcode, recs = dnsproto.query_udp(server, name, timeout=timeout)
        r["udp"] = (rcode == 0)
        r["udp_ms"] = (time.time() - t0) * 1000
        if rcode == 0:
            r["ips"] = [v for (_n, t, v) in recs if t == dnsproto.TYPE_A and v]
        else:
            r["error"] = "rcode=%d" % rcode
    except Exception as e:  # noqa: BLE001
        r["udp_ms"] = (time.time() - t0) * 1000
        r["error"] = "%s: %s" % (type(e).__name__, e)

    t0 = time.time()
    try:
        rcode, recs = dnsproto.query_tcp(server, name, timeout=max(timeout, 4))
        r["tcp"] = (rcode == 0)
        r["tcp_ms"] = (time.time() - t0) * 1000
        if rcode == 0 and not r["ips"]:
            r["ips"] = [v for (_n, t, v) in recs if t == dnsproto.TYPE_A and v]
    except Exception:
        r["tcp_ms"] = (time.time() - t0) * 1000

    return r


def collect_candidates():
    """汇总所有候选：(server, 来源说明)。系统配置永远排最前。"""
    cands = []

    for s, src in sysdns.system_dns(with_source=True):
        cands.append((s, "系统配置"))

    gw = default_gateway()
    if gw:
        cands.append((gw, "默认网关"))

    for s, who in PUBLIC:
        cands.append((s, "公共/" + who))

    seen, out = set(), []
    for s, src in cands:
        if s and s not in seen:
            seen.add(s)
            out.append((s, src))
    return out


def run(name=PROBE_NAME, workers=12, quiet=False):
    """跑完整流程，返回 (可用列表, 全部结果)。"""
    cands = collect_candidates()

    if not quiet:
        util.head("DNS 服务器发现")
        util.note("探针域名：%s" % name)
        util.note("候选 %d 台，并发 %d，每台同时试 UDP 和 TCP" % (len(cands), workers))
        print()

    results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, s, name): (s, src) for s, src in cands}
        for fu in cf.as_completed(futs):
            s, src = futs[fu]
            r = fu.result()
            r["source"] = src
            results.append(r)

    # 排序：可用的排前面，UDP 优先
    def rank(r):
        usable = (r["udp"] or r["tcp"])
        return (0 if usable else 1,
                0 if r["udp"] else 1,
                r["udp_ms"] if r["udp"] else (r["tcp_ms"] or 9e9))

    results.sort(key=rank)
    usable = [r for r in results if r["udp"] or r["tcp"]]

    if not quiet:
        print("  %-16s %-12s %-14s %-14s %s" % ("服务器", "来源", "UDP", "TCP", "解析结果"))
        print("  " + "-" * 74)
        for r in results:
            udp = ("%.0fms" % r["udp_ms"]) if r["udp"] else "✗"
            tcp = ("%.0fms" % r["tcp_ms"]) if r["tcp"] else "✗"
            mark = "  " if (r["udp"] or r["tcp"]) else "  "
            ips = ",".join(r["ips"][:2]) if r["ips"] else "-"
            print("  %s%-14s %-12s %-14s %-14s %s"
                  % (mark, r["server"], r["source"], udp, tcp, ips))
        print()
        util.item("可用服务器", len(usable), 20)

        if usable:
            best = usable[0]
            util.ok("建议使用：%s（%s）" % (best["server"], best["source"]))
            tcp_only = [r for r in usable if not r["udp"] and r["tcp"]]
            if tcp_only:
                util.warn("其中 %d 台只通 TCP —— UDP/53 被这个网络拦了"
                          % len(tcp_only))
        else:
            util.fail("没有一台能用 —— 这个网络可能要求先认证，或者 DNS 被完全劫持")

    return usable, results


def cmd(args):
    """CLI 入口。"""
    name = args.name or PROBE_NAME
    usable, _ = run(name)

    if usable and getattr(args, "apply", False):
        _apply([r["server"] for r in usable])
    return 0 if usable else 1


def _apply(servers):
    """把可用的服务器写进系统 DNS 配置（尽力而为，失败不影响主流程）。"""
    util.head("尝试应用")
    sysname = util.system()
    if sysname == "windows":
        util.warn("Windows 下改 DNS 需要管理员权限，请手动执行：")
        util.note('Set-DnsClientServerAddress -InterfaceAlias "<网卡名>" '
                  '-ServerAddresses %s' % ",".join(servers[:2]))
        return
    if sysname == "darwin":
        util.warn("macOS 请手动到「系统设置 → 网络 → DNS」里填：")
        util.note("  " + ", ".join(servers[:2]))
        return
    # Linux：写 resolv.conf
    path = "/etc/resolv.conf"
    body = "".join("nameserver %s\n" % s for s in servers[:3])
    body += "options timeout:1 attempts:2\n"
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        util.ok("已写入 %s" % path)
        util.note(body.replace("\n", " | "))
    except Exception as e:  # noqa: BLE001
        util.fail("写入失败（%s）—— 可能需要 root" % e)
        util.note("手动内容：")
        util.note(body.replace("\n", " | "))
