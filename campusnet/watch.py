"""网络看门狗：在网络变化的那一刻把现场抓下来。

为什么需要它
------------
网络出问题时，你**往往没法当场诊断** —— 因为诊断工具本身需要网络。
等你回到能上网的地方，现场已经没了。

这个守护进程解决的就是这个时序问题：它常驻，盯着几个信号，
一旦发现变化就**立刻**把当时的完整现场写进日志文件。等你恢复网络再看日志。

盯三个信号
----------
1. 本机 IP 变了          → 换了网络
2. 某个目标从「通」变「不通」→ 出问题了
3. 某个目标从「不通」变「通」→ 恢复了

前两个触发完整诊断（包含一次局域网扫描）。
"""

import datetime
import json
import os
import socket
import time

from . import diagnose, dnsfind, util

DEFAULT_LOG = "campusnet-watch.log"


def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Watcher:
    def __init__(self, targets=None, interval=10, log_path=DEFAULT_LOG,
                 full_diag=True, max_hours=24):
        self.targets = targets or [("223.5.5.5", 443), ("223.5.5.5", 53)]
        self.interval = interval
        self.log_path = log_path
        self.full_diag = full_diag
        self.max_hours = max_hours
        self.state = {}
        self.last_ip = None
        self.events = 0

    # -------- 日志 --------

    def log(self, msg=""):
        line = str(msg)
        print(line, flush=True)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def banner(self, title):
        self.log("")
        self.log("#" * 62)
        self.log("### " + title)
        self.log("#" * 62)

    # -------- 探测 --------

    def probe(self, host, port, timeout=4.0):
        t0 = time.time()
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True, (time.time() - t0) * 1000, ""
        except Exception as e:  # noqa: BLE001
            return False, (time.time() - t0) * 1000, type(e).__name__

    # -------- 现场 --------

    def snapshot(self, reason):
        self.banner("现场快照：%s" % reason)
        self.log("时间: %s" % _now())
        self.log("本机: %s" % (util.local_ip() or "?"))
        self.log("网关: %s" % (dnsfind.default_gateway() or "?"))

        self.log("")
        self.log("--- 系统配置的 DNS ---")
        from . import dnsproto, sysdns
        sysd = sysdns.system_dns()
        self.log("  " + (", ".join(sysd) if sysd else "（读不到）"))
        for s in sysd[:3]:
            try:
                ips = dnsproto.resolve_a(s, "www.baidu.com", timeout=3)
                self.log("  %-16s ✅ %s" % (s, ",".join(ips[:2])))
            except Exception as e:  # noqa: BLE001
                self.log("  %-16s ❌ %s" % (s, type(e).__name__))

        self.log("")
        self.log("--- 直连 IP 探测（不依赖 DNS）---")
        for host, port in [(t[0], t[1]) for t in self.targets] + \
                          [("223.5.5.5", 53), ("223.5.5.5", 443), ("1.1.1.1", 443)]:
            okc, ms, why = self.probe(host, port)
            self.log("  %-16s:%-5d %s %6.0f ms %s"
                     % (host, port, "✅" if okc else "❌", ms, why))

        if self.full_diag:
            self.log("")
            self.log("--- 局域网扫描 ---")
            try:
                from . import lanfind
                found = lanfind.scan(util.local_subnet(24) or "10.0.0.",
                                     [80, 443, 22, 445, 3389], workers=192, timeout=0.6)
                self.log("  发现 %d 台" % len(found))
                for ip, ps in found[:10]:
                    self.log("    %s  开放 %s" % (ip, ps))
                gw = dnsfind.default_gateway()
                self.log("  网关可达: %s" % (lanfind.gateway_reachable(gw),))
            except Exception as e:  # noqa: BLE001
                self.log("  扫描失败: %s" % e)

        self.events += 1

    # -------- 主循环 --------

    def run(self):
        self.log("=" * 62)
        self.log("campus-net-toolkit 看门狗  启动于 %s" % _now())
        self.log("目标: %s" % ", ".join("%s:%d" % t for t in self.targets))
        self.log("间隔: %ds   最长: %dh" % (self.interval, self.max_hours))
        self.log("日志: %s" % os.path.abspath(self.log_path))
        self.log("=" * 62)

        self.last_ip = util.local_ip()
        for t in self.targets:
            self.state[t] = self.probe(*t)[0]
        self.log("[基线] IP=%s  目标=%s" % (self.last_ip, self.state))

        end_at = time.time() + self.max_hours * 3600
        beats = 0

        while time.time() < end_at:
            time.sleep(self.interval)
            beats += 1

            # 1) IP 变了
            ip = util.local_ip()
            if ip != self.last_ip:
                self.log("")
                self.log("[%s] >>> 网络切换：%s -> %s" % (_now(), self.last_ip, ip))
                self.snapshot("网络切换 %s -> %s" % (self.last_ip, ip))
                self.last_ip = ip
                continue

            # 2) 目标状态翻转
            for t in self.targets:
                okc, ms, why = self.probe(*t)
                was = self.state.get(t)
                if was and not okc:
                    self.log("")
                    self.log("[%s] >>> %s:%d 从「通」变「不通」 (%.0fms %s)"
                             % (_now(), t[0], t[1], ms, why))
                    self.snapshot("%s:%d 失联" % t)
                    self.state[t] = False
                elif was is False and okc:
                    self.log("[%s] <<< %s:%d 恢复了 (%.0fms)" % (_now(), t[0], t[1], ms))
                    self.state[t] = True
                else:
                    self.state[t] = okc

            if beats % 30 == 0:
                self.log("[%s] 心跳  IP=%s  目标=%s  事件=%d"
                         % (_now(), self.last_ip, self.state, self.events))

        self.log("[%s] 到时退出" % _now())


def cmd(args):
    targets = []
    for spec in (args.target or []):
        if ":" in spec:
            h, p = spec.rsplit(":", 1)
            targets.append((h, int(p)))
    w = Watcher(targets=targets or None,
                interval=args.interval,
                log_path=args.log,
                full_diag=not args.no_scan,
                max_hours=args.hours)
    try:
        w.run()
    except KeyboardInterrupt:
        w.log("")
        w.log("收到中断，退出。共抓到 %d 次事件。" % w.events)
    return 0
