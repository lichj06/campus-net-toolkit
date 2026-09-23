"""极简 DNS 报文构造与解析 —— 只用标准库。

为什么不用 `socket.getaddrinfo`？
    它走系统解析器，你无法控制「问哪台服务器」。而本工具的核心工作恰恰是
    **逐个测试某台服务器能不能用**，所以必须自己拼 DNS 报文。

为什么 UDP 和 TCP 都要有？
    有些网络封 UDP/53 但放行 TCP/53。只测 UDP 会得出「这台不能用」的错误结论。
    （两者耗时不同属正常：一次真实运行里同一台解析器 UDP 17ms、TCP 27ms，
    见 docs/raw-run-2026-09-23.md；具体数值随网络变化。）
"""

import random
import socket
import struct

TYPE_A = 1
TYPE_AAAA = 28
TYPE_CNAME = 5
TYPE_NS = 2
TYPE_MX = 15
TYPE_TXT = 16

_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}


def build_query(name, qtype=TYPE_A):
    """构造一个标准查询报文（RD=1，请求递归）。"""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    body = b""
    for part in name.rstrip(".").split("."):
        body += bytes([len(part)]) + part.encode("ascii")
    body += b"\x00" + struct.pack(">HH", qtype, 1)
    return tid, header + body


def _skip_name(data, i):
    """跳过（可能被压缩的）域名，返回新偏移。"""
    while i < len(data):
        ln = data[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0 == 0xC0:      # 压缩指针，两字节
            return i + 2
        i += ln + 1
    return i


def _read_name(data, i):
    """读取域名（跟随压缩指针）。"""
    parts = []
    seen = set()
    while i < len(data):
        if i in seen:              # 防御性：坏包导致的循环
            break
        seen.add(i)
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[i:i + 2])[0] & 0x3FFF
            sub, _ = _read_name(data, ptr)
            parts.append(sub)
            i += 2
            break
        i += 1
        parts.append(data[i:i + ln].decode("ascii", "replace"))
        i += ln
    return ".".join(p for p in parts if p), i


def parse_answers(data):
    """解析响应，返回 (rcode, [(name, type, value), ...])。

    rcode: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED
    A/AAAA 的 value 是 IP 字符串；CNAME/NS 是域名；其他为 None。
    """
    if len(data) < 12:
        raise ValueError("响应太短（%d 字节）" % len(data))
    _tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F

    i = 12
    for _ in range(qd):            # 跳过问题区
        i = _skip_name(data, i) + 4

    out = []
    for _ in range(an):
        name, i = _read_name(data, i)
        if i + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        value = None
        if rtype == TYPE_A and rdlen == 4:
            value = ".".join(str(b) for b in rd)
        elif rtype == TYPE_AAAA and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rd)
        elif rtype in (TYPE_CNAME, TYPE_NS):
            value, _ = _read_name(data, i)
        out.append((name, rtype, value))
        i += rdlen

    return rcode, out


def query_udp(server, name, qtype=TYPE_A, timeout=3.0):
    """UDP 查询。返回 (rcode, records)。"""
    _tid, pkt = build_query(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return parse_answers(data)


def query_tcp(server, name, qtype=TYPE_A, timeout=5.0):
    """TCP 查询（长度前缀 + 报文）。UDP 被封时的关键退路。"""
    _tid, pkt = build_query(name, qtype)
    s = socket.create_connection((server, 53), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(struct.pack(">H", len(pkt)) + pkt)
        hdr = s.recv(2)
        if len(hdr) < 2:
            raise IOError("响应头不完整")
        need = struct.unpack(">H", hdr)[0]
        buf = b""
        while len(buf) < need:
            chunk = s.recv(need - len(buf))
            if not chunk:
                break
            buf += chunk
    finally:
        s.close()
    return parse_answers(buf)


def query(server, name, qtype=TYPE_A, timeout=3.0, transport="auto"):
    """统一入口。transport 为 'udp' / 'tcp' / 'auto'。

    auto 会先试 UDP，失败再试 TCP —— 这样能同时覆盖两种封锁方式。
    """
    if transport in ("udp", "auto"):
        try:
            return "udp", query_udp(server, name, qtype, timeout)
        except Exception:
            if transport == "udp":
                raise
    return "tcp", query_tcp(server, name, qtype, max(timeout, 5.0))


def resolve_a(server, name, timeout=3.0, transport="auto"):
    """只要 A 记录，返回 IP 列表（失败抛异常）。"""
    _tr, (rcode, recs) = query(server, name, TYPE_A, timeout, transport)
    if rcode != 0:
        raise IOError("DNS rcode=%d (%s)" % (rcode, {
            1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(rcode, "?")))
    ips = [v for (_n, t, v) in recs if t == TYPE_A and v]
    if not ips:
        raise IOError("响应里没有 A 记录")
    return ips
