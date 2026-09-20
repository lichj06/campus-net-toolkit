"""命令行入口。

    python3 -m campusnet diagnose          # 网络体检
    python3 -m campusnet dnsfind           # 找出能用的 DNS
    python3 -m campusnet pin api.deepseek.com
    python3 -m campusnet lanfind
    python3 -m campusnet watch
"""

import argparse
import sys

from . import __version__, diagnose, dnsfind, lanfind, pinhosts, watch


def build_parser():
    p = argparse.ArgumentParser(
        prog="campusnet",
        description="受限网络（校园网/酒店/公司）诊断与绕过工具箱 —— 零依赖",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""例子:
  campusnet diagnose                    网络体检，一次说清限制在哪
  campusnet dnsfind                     找出这个网络下真正能用的 DNS
  campusnet dnsfind --apply             顺便写进系统配置
  campusnet pin api.deepseek.com        把域名钉进 hosts（IP 会做 TLS 校验）
  campusnet pin github.com --dry-run    只看看，不真写
  campusnet unpin github.com            撤掉
  campusnet lanfind                     在局域网里找自己的其他设备
  campusnet watch                       常驻，网络一变就抓现场
""")
    p.add_argument("-V", "--version", action="version",
                   version="campus-net-toolkit %s" % __version__)
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("diagnose", help="一次跑完的网络体检")
    d.add_argument("--prefix", help="指定要扫的 /24 前缀，如 192.0.2.")
    d.add_argument("--skip-scan", action="store_true", help="跳过局域网扫描（快很多）")

    f = sub.add_parser("dnsfind", help="找出这个网络下能用的 DNS")
    f.add_argument("--name", default="www.baidu.com", help="探针域名")
    f.add_argument("--apply", action="store_true", help="把结果写进系统配置")

    pi = sub.add_parser("pin", help="把域名钉进 hosts")
    pi.add_argument("host", help="域名")
    pi.add_argument("--servers", help="先用这些 DNS 解析，逗号分隔")
    pi.add_argument("--dry-run", action="store_true", help="只展示，不写入")
    pi.add_argument("--unpin", action="store_true", help="反过来：移除该域名的钉")

    u = sub.add_parser("unpin", help="移除钉过的条目")
    u.add_argument("host", nargs="?", help="域名；省略则全部移除")
    u.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)

    l = sub.add_parser("lanfind", help="在局域网里找设备")
    l.add_argument("--prefix", help="要扫的 /24 前缀")
    l.add_argument("--ports", help="要探测的端口，逗号分隔")
    l.add_argument("--wide", action="store_true", help="扫更大范围")

    w = sub.add_parser("watch", help="网络看门狗")
    w.add_argument("--target", action="append", metavar="HOST:PORT",
                   help="盯的目标，可重复。默认 223.5.5.5:443 和 :53")
    w.add_argument("--interval", type=int, default=10, help="轮询间隔秒数（默认 10）")
    w.add_argument("--hours", type=int, default=24, help="最长运行小时数（默认 24）")
    w.add_argument("--log", default="campusnet-watch.log", help="日志文件")
    w.add_argument("--no-scan", action="store_true", help="抓现场时跳过局域网扫描")

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.cmd:
        build_parser().print_help()
        return 0

    if args.cmd == "diagnose":
        diagnose.run(prefix=args.prefix, skip_scan=args.skip_scan)
        return 0
    if args.cmd == "dnsfind":
        return dnsfind.cmd(args)
    if args.cmd == "pin":
        return pinhosts.cmd(args)
    if args.cmd == "unpin":
        return 0 if pinhosts.unpin(args.host) else 1
    if args.cmd == "lanfind":
        return lanfind.cmd(args)
    if args.cmd == "watch":
        return watch.cmd(args)

    build_parser().print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
