"""把关键域名钉进 /etc/hosts —— DNS 被拦时的绕过手段。

为什么要把 IP 钉死而不是改 DNS
------------------------------
有些网络（比如某个校园网）**所有外网 UDP/53 都封**，任何公共 DNS 都用不了。
但同一个网络里，学校自己的解析器是通的 —— 前提是你知道它的地址。

如果你连系统 DNS 都拿不到（或者它时好时坏），还有一招：
**把这个域名的 IP 直接写进 hosts，彻底不查 DNS。**

安全前提：每个 IP 都要过一遍 TLS 证书校验
----------------------------------------
不能随便从别处抄一个 IP 就信。必须确认：
    连到 这个IP:443，用 目标域名 做 SNI，证书链验得过

否则你等于把流量交给了一个陌生 IP。本模块里每个候选 IP 都会验一遍
（`cert_check`），验证不通过的直接丢弃。
"""

import socket
import ssl

from . import dnsproto, sysdns, util

HOSTS = "/etc/hosts"
MARK = "# pinned by campus-net-toolkit"


def cert_check(ip, hostname, port=443, timeout=6.0):
    """连到 ip:port，用 hostname 做 SNI，校验证书。返回 True/False。

    这是本项目里唯一「不可省略」的安全检查 ——
    它保证你钉进 hosts 的 IP 真的是那个域名的服务器。
    """
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        try:
            ss = ctx.wrap_socket(raw, server_hostname=hostname)
            ss.close()
            return True
        except Exception:
            raw.close()
            return False
    except Exception:
        return False


def read_hosts(path=HOSTS):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except Exception:
        return []


def pinned(path=HOSTS, hostname=None):
    """读出已被本工具钉住的条目。"""
    out = []
    for line in read_hosts(path):
        if MARK not in line:
            continue
        parts = line.split()
        if len(parts) >= 2 and (hostname is None or parts[1] == hostname):
            out.append(parts[0])
    return out


def resolve(hostname, extra_servers=()):
    """依次问「系统 DNS → 额外服务器」，返回能用的一批 IP。"""
    servers = list(sysdns.system_dns()) + list(extra_servers)
    for srv in servers:
        try:
            return srv, dnsproto.resolve_a(srv, hostname, timeout=3)
        except Exception:
            continue
    return None, []


def pin(hostname, servers=(), max_ips=6, dry_run=False):
    """把 hostname 的可用 IP 钉进 hosts。返回 (写入的 IP 列表, 说明)。"""
    util.head("钉 hosts：%s" % hostname)

    used, ips = resolve(hostname, servers)
    if not ips:
        util.fail("所有 DNS 都问不到 %s 的地址" % hostname)
        util.note("可以手动指定：--servers 192.0.2.53,192.0.2.54")
        return [], "no-dns"
    util.item("解析来源", used)
    util.item("候选 IP", ", ".join(ips))

    print()
    util.note("逐个做 TLS 证书校验（确认这些 IP 真的是 %s）" % hostname)
    good = []
    for ip in ips:
        if ip in good:
            continue
        okc = cert_check(ip, hostname)
        print("    %-18s %s" % (ip, "✅ 证书通过" if okc else "❌ 证书不匹配，丢弃"))
        if okc:
            good.append(ip)
        if len(good) >= max_ips:
            break

    if not good:
        util.fail("没有一个 IP 通过证书校验 —— 拒绝写入")
        return [], "no-valid-ip"

    print()
    if dry_run:
        util.warn("--dry-run：没有真的写入")
        for ip in good:
            util.note("%s\t%s" % (ip, hostname))
        return good, "dry-run"

    lines = [l for l in read_hosts() if MARK not in l]
    while lines and not lines[-1].strip():
        lines.pop()
    lines.append("")
    lines.append("# --- campus-net-toolkit: %s ---" % hostname)
    for ip in good:
        lines.append("%s\t%s\t%s" % (ip, hostname, MARK))

    try:
        with open(HOSTS, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:  # noqa: BLE001
        util.fail("写 %s 失败（%s）—— 通常需要 root" % (HOSTS, e))
        util.note("手动追加这些行：")
        for ip in good:
            util.note("%s\t%s" % (ip, hostname))
        return good, "permission-denied"

    util.ok("已写入 %s（%d 条）" % (HOSTS, len(good)))
    return good, "ok"


def unpin(hostname=None):
    """移除本工具钉过的条目（hostname 为 None 时全清）。"""
    lines = read_hosts()
    kept = []
    removed = 0
    for line in lines:
        if MARK in line and (hostname is None or
                             (len(line.split()) >= 2 and line.split()[1] == hostname)):
            removed += 1
            continue
        kept.append(line)
    if not removed:
        util.warn("没有找到对应的钉记录")
        return 0
    try:
        with open(HOSTS, "w", encoding="utf-8") as f:
            f.write("\n".join(kept) + "\n")
        util.ok("已移除 %d 条" % removed)
    except Exception as e:  # noqa: BLE001
        util.fail("写入失败：%s" % e)
        return 0
    return removed


def cmd(args):
    if args.unpin:
        return 0 if unpin(args.host) else 1
    servers = [s for s in (args.servers or "").split(",") if s.strip()]
    ips, status = pin(args.host, servers, dry_run=args.dry_run)
    return 0 if ips and status in ("ok", "dry-run") else 1
