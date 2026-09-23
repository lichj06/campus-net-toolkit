"""在同一个网络里找自己的其他设备。

用途：手机和电脑连同一个 Wi-Fi，但电脑只监听 127.0.0.1（很多桌面软件默认如此），
或者你忘了电脑的 IP。这个命令把同网段的设备扫出来。

先说清楚一件事
--------------
**扫不到 ≠ 不存在。**

校园网普遍开「客户端隔离」，同网段互相看不见。这时候扫出来是空的，
但设备其实好好的。所以本模块同时做一个对照测试：
**能不能连上默认网关？**

    网关通 + 邻居一个都没有   → 大概率是客户端隔离
    网关也不通               → 网络层就没出去，跟隔离无关
"""

import concurrent.futures as cf
import socket
import time

from . import dnsfind, util

# 默认只探「通用服务」端口。
#
# 为什么不带个人端口：这个仓库是公开的，默认值里塞进 8899/59931/11434 这类
# 远控或本地模型端口，等于教别人去扫宿舍网里的个人服务，也容易被安全设备
# 当成内网探测。要探自己的端口，显式传 --ports 8899,11434。
COMMON_PORTS = [80, 443, 22, 445, 3389, 8080, 8443]


def open_port(host, port, timeout=0.8):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def scan(prefix, ports, workers=192, timeout=0.8):
    """扫一个 /24，返回 [(ip, [开放端口...]), ...]。"""
    hosts = [prefix + str(i) for i in range(1, 255)]
    me = util.local_ip()
    if me:
        hosts = [h for h in hosts if h != me]

    def probe(h):
        hits = [p for p in ports if open_port(h, p, timeout)]
        return (h, hits) if hits else None

    found = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, hosts):
            if r:
                found.append(r)
    found.sort(key=lambda x: x[0])
    return found


def gateway_reachable(gw, timeout=1.5):
    """网关能不能连（用一个几乎一定会开的端口探测）。"""
    if not gw:
        return None
    for p in (80, 443, 53):
        if open_port(gw, p, timeout):
            return True
    return False


def run(prefix=None, ports=None, wide=False):
    util.head("局域网设备发现")

    pre = prefix or util.local_subnet(24)
    if not pre:
        util.fail("读不到本机地址")
        return []
    me = util.local_ip()
    util.item("本机", me)
    gw, gwsrc = dnsfind.default_gateway(with_source=True)
    util.item("默认网关", "%s%s" % (gw or "（读不到）",
                                "  ← 猜的" if gwsrc == "guess" else ""))

    port_list = ports or COMMON_PORTS
    util.item("探测端口", ", ".join(str(p) for p in port_list))
    util.note("每个 IP 会依次试这些端口，命中任一个就算「这台有服务」")
    if not ports:
        util.note("默认只探通用服务端口。要探自己的端口：--ports 8899,11434")
    print()

    ranges = [pre]
    if wide:
        base = ".".join(pre.rstrip(".").split(".")[:3])
        ranges = [base.rsplit(".", 1)[0] + "." + str(i) + "." for i in range(0, 6)]

    t0 = time.time()
    found = []
    for r in ranges:
        # 每个区间都跑完：早期版本一有命中就 break，导致 wide 实际只扫了第一个 /24，
        # 「0 号区间之外一台都没有」这个结论从来没被测过。
        util.note("扫描 %s0/24 ..." % r)
        hits = scan(r, port_list)
        util.note("  -> %d 台" % len(hits))
        found += hits

    print()
    util.item("耗时", "%.1f 秒" % (time.time() - t0))

    # 网关对照 —— 只有从路由表读到的网关才算证据
    gw_ok = gateway_reachable(gw) if gwsrc == "route" else None
    util.item("网关可达", {True: "是", False: "否",
                          None: "未知（网关是猜的，不作证据）"}[gw_ok])

    print()
    if found:
        util.ok("发现 %d 台有服务的设备：" % len(found))
        for ip, ps in found:
            util.note("%-16s 开放: %s" % (ip, ", ".join(str(p) for p in ps)))
        return found

    util.warn("没有扫到任何设备")
    if gw_ok is True:
        util.note("但网关是通的 → 这符合「客户端隔离」的特征")
        util.note("设备是好的，只是这个网络不让你看见邻居")
    elif gw_ok is False:
        util.note("网关也不通 → 问题在网络层（没认证 / 没出口），跟隔离无关")
    else:
        util.note("拿不到可信的网关地址 → 无法区分「真隔离」和「网络本身不通」")
        util.note("想确认的话，在一台能读路由表的机器上跑一次（如电脑）")
    return []


def cmd(args):
    ports = None
    if args.ports:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    found = run(prefix=args.prefix, ports=ports, wide=args.wide)
    return 0 if found else 1
