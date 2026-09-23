"""读取「系统当前实际在用的 DNS 服务器」。

这个模块是本工具存在的理由。

一个很常见的错误
----------------
在校园网下，随手测几个公共 DNS（8.8.8.8 / 114.114.114.114 / 223.5.5.5），
全都超时，于是得出结论：**「学校把 DNS 封了」**。

错。学校通常有自己的解析器，只是地址不是那些公共地址。
真正的解法是**先问系统**：你现在用的是哪台？然后测那一台。

实测案例
--------
    测公共 DNS         -> 3 台全部超时        （得出错误结论）
    读系统配置         -> 192.0.2.53, 192.0.2.54
    测这两台           -> 17ms（UDP）正常返回  （真相）

（数字出处：docs/raw-run-2026-09-23.md 的 dnsfind 一节，那次运行的真实输出；
地址已打码为 RFC 5737 文档保留段。换网络不成立，只作量级参考。）

同一台机器、同一个网络，结论完全相反。区别只在于「问谁」。
"""

import re
import subprocess

from . import util

# 各平台读系统 DNS 的命令超时（秒）
_CMD_TIMEOUT = 8


def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=_CMD_TIMEOUT)
        return p.stdout or ""
    except Exception:
        return ""


def _unique(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def from_resolv_conf(path="/etc/resolv.conf"):
    """解析 /etc/resolv.conf（Linux / Android / 多数容器）。"""
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        out.append(parts[1])
    except Exception:
        pass
    return out


def from_resolvectl():
    """systemd-resolved：`resolvectl status` 里的 Current DNS Server。"""
    txt = _run(["resolvectl", "status"])
    if not txt:
        txt = _run(["systemd-resolve", "--status"])
    out = []
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("Current DNS Server:") or s.startswith("DNS Servers:"):
            out += _IPV4.findall(s)
    return out


def from_scutil():
    """macOS：`scutil --dns` 的 nameserver 行。"""
    txt = _run(["scutil", "--dns"])
    out = []
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith("nameserver["):
            out += _IPV4.findall(s)
    return out


def from_windows():
    """Windows：问 PowerShell 要每块网卡的 DNS。

    这是本项目里最有价值的一段 —— 就是靠它发现了校园网自己的解析器。
    """
    ps = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses } | "
        "ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }"
    )
    txt = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
    out = []
    if txt:
        for line in txt.splitlines():
            if "|" in line:
                out += _IPV4.findall(line.split("|", 1)[1])
    if not out:  # 退化方案：解析 ipconfig
        out = _IPV4.findall(_run(["ipconfig", "/all"]).split("DNS Servers")[-1][:200])
    return out


def system_dns(with_source=False):
    """返回系统当前在用的 DNS 服务器列表（去重、保序）。

    with_source=True 时返回 [(server, 来源说明), ...]，便于排障时展示。
    """
    sysname = util.system()
    found = []          # [(server, source)]

    def add(servers, source):
        for s in servers:
            found.append((s, source))

    if sysname == "windows":
        add(from_windows(), "Get-DnsClientServerAddress")
    elif sysname == "darwin":
        add(from_scutil(), "scutil --dns")
        add(from_resolv_conf(), "/etc/resolv.conf")
    else:
        add(from_resolv_conf(), "/etc/resolv.conf")
        add(from_resolvectl(), "resolvectl status")

    # 去重（保留第一次出现的来源）
    seen, out = set(), []
    for s, src in found:
        if s not in seen and s not in ("127.0.0.1", "::1"):
            seen.add(s)
            out.append((s, src))

    if with_source:
        return out
    return [s for s, _ in out]


def resolver_hint():
    """给用户的一句话建议（当前系统该去哪里看 DNS）。"""
    s = util.system()
    if s == "windows":
        return "PowerShell: Get-DnsClientServerAddress -AddressFamily IPv4"
    if s == "darwin":
        return "scutil --dns"
    return "cat /etc/resolv.conf   （或 resolvectl status）"
