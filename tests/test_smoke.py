"""最小冒烟测试：只跑纯函数与 --help，不发真实网络请求、不写任何系统文件。

    python3 -m unittest discover -s tests -v

为什么要有这些用例：这个仓库会改系统文件（/etc/resolv.conf、/etc/hosts），
所以「哪些路径**拒绝**写入」必须被固定下来 —— 这是回归测试，不是覆盖率游戏。
"""

import argparse
import os
import pathlib
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from campusnet import __main__ as cli          # noqa: E402
from campusnet import diagnose, dnsfind, dnsproto, lanfind, pinhosts, sysdns, util  # noqa: E402


class TestCli(unittest.TestCase):
    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            cli.build_parser().parse_args(["--help"])
        self.assertEqual(cm.exception.code, 0)

    def test_all_subcommands_have_parser(self):
        for name in ("diagnose", "dnsfind", "pin", "unpin", "lanfind", "watch"):
            args = cli.build_parser().parse_args([name] + (["x.com"] if name == "pin" else []))
            self.assertEqual(args.cmd, name)


class TestDnsproto(unittest.TestCase):
    def test_build_query_shape(self):
        _tid, pkt = dnsproto.build_query("www.example.com", dnsproto.TYPE_A)
        self.assertEqual(pkt[4:6], b"\x00\x01")       # QDCOUNT=1
        self.assertIn(b"www", pkt)
        self.assertTrue(pkt.endswith(b"\x00\x00\x01\x00\x01"))

    def test_parse_answers_roundtrip(self):
        # 手工拼一个最小响应：1 个问题 + 1 条 A 记录
        import struct
        q = dnsproto.build_query("a.example.com")[1]
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 1])
        rcode, recs = dnsproto.parse_answers(header + q[12:] + answer)
        self.assertEqual(rcode, 0)
        self.assertEqual(recs, [("a.example.com", dnsproto.TYPE_A, "192.0.2.1")])

    def test_short_packet_raises(self):
        with self.assertRaises(ValueError):
            dnsproto.parse_answers(b"\x00\x01")


class TestSysdns(unittest.TestCase):
    def test_from_resolv_conf(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("# comment\nnameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch x\n")
            path = f.name
        try:
            self.assertEqual(sysdns.from_resolv_conf(path), ["192.0.2.53", "192.0.2.54"])
        finally:
            os.unlink(path)

    def test_missing_file_is_empty_not_crash(self):
        self.assertEqual(sysdns.from_resolv_conf("/nonexistent/resolv.conf"), [])


class TestUtil(unittest.TestCase):
    def test_local_ip_is_documentation_address_target(self):
        # 探测目标必须是文档保留地址，不能是某个具体校园网的解析器
        host, port = util._PROBE_TARGET
        self.assertTrue(host.startswith("192.0.2."), host)
        self.assertEqual(port, 9)

    def test_local_subnet_uses_first_three_octets(self):
        orig = util.local_ip
        util.local_ip = lambda: "192.0.2.167"
        try:
            self.assertEqual(util.local_subnet(24), "192.0.2.")
        finally:
            util.local_ip = orig


class TestDnsfind(unittest.TestCase):
    def test_dual_stack_filter(self):
        rows = [{"server": "a", "udp": True, "tcp": False},
                {"server": "b", "udp": False, "tcp": True},
                {"server": "c", "udp": True, "tcp": True}]
        self.assertEqual([r["server"] for r in dnsfind._dual_stack(rows)], ["c"])

    def test_apply_refuses_without_dual_stack(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "resolv.conf")
            original = "nameserver 192.0.2.99\n"
            pathlib.Path(path).write_text(original)
            ok = dnsfind._apply([{"server": "192.0.2.99", "udp": True, "tcp": False}], path=path)
            self.assertFalse(ok)
            self.assertEqual(pathlib.Path(path).read_text(), original)

    def test_apply_backs_up_before_writing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "resolv.conf")
            original = "nameserver 192.0.2.99\n"
            pathlib.Path(path).write_text(original)
            ok = dnsfind._apply([{"server": "192.0.2.53", "udp": True, "tcp": True}], path=path)
            self.assertTrue(ok)
            self.assertIn("nameserver 192.0.2.53", pathlib.Path(path).read_text())
            backups = list(pathlib.Path(d).glob("resolv.conf.bak-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)


class TestDiagnose(unittest.TestCase):
    def test_loc_host_normalises(self):
        self.assertEqual(diagnose._loc_host("http://portal.example.edu/login"), "portal.example.edu")
        self.assertEqual(diagnose._loc_host("http://portal.example.edu:8080/a"), "portal.example.edu:8080")

    def test_single_redirect_is_not_a_portal_verdict(self):
        # 单个 3xx 不算证据：必须是「多个目标跳到同一个地址」或 200/204
        seq = iter([(301, "http://only.example/", ""), (404, "", "")])
        orig = diagnose._http_probe
        diagnose._http_probe = lambda *a, **k: next(seq)
        try:
            self.assertEqual(diagnose.check_portal(), "unknown")
        finally:
            diagnose._http_probe = orig

    def test_same_location_redirect_is_portal(self):
        orig = diagnose._http_probe
        diagnose._http_probe = lambda *a, **k: (302, "http://portal.example.edu/login", "")
        try:
            self.assertEqual(diagnose.check_portal(), "portal")
        finally:
            diagnose._http_probe = orig

    def test_mtu_probe_returns_mostly_ok(self):
        # 只验函数能跑通、返回值合法；不假设具体 MTU
        r = diagnose._df_sendto("223.5.5.5", 53, 1200)
        self.assertIn(r.split(":")[0], ("ok", "emsgsize", "unsupported", "error"))


class TestLanfind(unittest.TestCase):
    def test_default_ports_are_common_only(self):
        self.assertEqual(lanfind.COMMON_PORTS, [80, 443, 22, 445, 3389, 8080, 8443])
        for personal in (8899, 59931, 11434, 7860):
            self.assertNotIn(personal, lanfind.COMMON_PORTS)


class TestPinhosts(unittest.TestCase):
    def test_pinned_parses_marked_lines_only(self):
        with tempfile.NamedTemporaryFile("w", suffix="hosts", delete=False) as f:
            f.write("127.0.0.1 localhost\n")
            f.write("192.0.2.1\texample.com\t%s\n" % pinhosts.MARK)
            path = f.name
        try:
            self.assertEqual(pinhosts.pinned(path, "example.com"), ["192.0.2.1"])
            self.assertEqual(pinhosts.pinned(path, "other.com"), [])
        finally:
            os.unlink(path)

    def test_no_marked_line_means_nothing_pinned(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("127.0.0.1 localhost\n")
            path = f.name
        try:
            self.assertEqual(pinhosts.pinned(path), [])
        finally:
            os.unlink(path)


class TestRepoPrivacy(unittest.TestCase):
    """防止真实内网地址再被写回仓库（本文件所在目录里不该出现这些前缀）。"""

    # 必须写出真实前缀才能当检测项，所以本文件被下面的循环跳过。
    # 注意：批量脱敏脚本很容易连这一行一起替换掉，那会让这个断言变成
    # 「禁止文档地址」的空转 —— 改这一行后一定要重跑本测试。
    FORBIDDEN = ("10.11.8.", "10.168.8.", "192.0.2.")

    def test_no_private_net_address_in_tracked_text(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        me = pathlib.Path(__file__).resolve()
        bad = []
        for p in list(root.rglob("*.py")) + list(root.rglob("*.md")) + [root / "pyproject.toml"]:
            if ".git" in p.parts or "__pycache__" in p.parts or p.resolve() == me:
                continue        # 本文件里必须写出这些前缀才能当检测项
            text = p.read_text(encoding="utf-8", errors="replace")
            for needle in self.FORBIDDEN:
                if needle in text:
                    bad.append("%s: %s" % (p.name, needle))
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
