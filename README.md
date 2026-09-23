# campus-net-toolkit

> 校园网（以及酒店、公司、任何受限网络）下的**诊断与合规适配**工具箱。
> **零依赖** —— 只用 Python 标准库。
>
> 它只做两件事：**查清楚限制到底在哪一类**，以及**在规则允许的范围内把该用的事情用上**。
> 仓库里**没有**任何认证、计费、限速、设备数绕过手段。
> **使用须遵守学校/运营商的规定**；遇到限制先向学校信息化中心确认哪些用途被允许。

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)]()

---

## 先看这条：本文的数字从哪来

本文里每个毫秒级数字都来自**同一次真实运行**，原始输出（含 UTC 时间戳）逐字保存在
[`docs/raw-run-2026-09-23.md`](docs/raw-run-2026-09-23.md)。本文里的数字若在那里找不到，
就不写毫秒值，只给定性描述。

- **这些数据只来自一处校园网、单次运行。换网络、换时间都不成立**，不要当通则看。
- 采集环境：Android + proot 的 Linux 容器，Python 3.12.3，2026-09-23（UTC）。
- 为防止泄露作者所在网络，解析器/本机/网关地址已替换成 RFC 5737 文档保留段
  （`192.0.2.0/24`），延迟、rcode、端口、HTTP 状态码全部是真实测量值。

---

## 先说一个我犯过的错

我在校园网下连不上外网，随手测了几个公共 DNS：223.5.5.5、119.29.29.29、
114.114.114.114、8.8.8.8 —— 四个全挂，于是我得出了结论：**「学校把 DNS 封了」**。

然后我花了几小时去「对抗」它：把域名 IP 逐个做 TLS 校验后钉进 `hosts`、
写自愈脚本、做看门狗…… 直到我偶然读到系统自己配的 DNS。

下面是 [`docs/raw-run-2026-09-23.md`](docs/raw-run-2026-09-23.md) 里
`python3 -m campusnet dnsfind` 那一段的**逐字复制**：

```
  服务器              来源                 UDP          TCP          解析结果
  --------------------------------------------------------------------------
   192.0.2.54      /etc/resolv.conf   17ms         27ms         110.242.70.57,110.242.69.21
   192.0.2.53      /etc/resolv.conf   17ms         27ms         110.242.69.21,110.242.70.57
   192.0.2.1     默认网关               ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: OSError: [Errno 113] No route to host
   180.76.76.76   公共/百度              ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   1.1.1.1        公共/Cloudflare      ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   119.29.29.29   /etc/resolv.conf   ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   192.0.2.99   /etc/resolv.conf   ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   114.114.114.114 公共/114             ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   8.8.8.8        公共/Google          ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   223.5.5.5      /etc/resolv.conf   ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out
   223.6.6.6      公共/阿里备用            ✗            ✗            -
       └ UDP: TimeoutError: timed out
       └ TCP: TimeoutError: timed out

  可用服务器                2
  [OK]   建议使用：192.0.2.54（/etc/resolv.conf）
```

**学校没封 DNS。学校有自己的解析器，17 毫秒（UDP）就返回。**
**我只是从来没问过系统「你现在用的是哪台」。**

关于「来源」这一列，有个容易误读的地方：`223.5.5.5`、`119.29.29.29` 显示成
`/etc/resolv.conf`，不是因为工具有什么内部标签，而是这台机器的 `resolv.conf` 里
**确实列着**它们（看第 2 节「系统配置的 DNS」那行也能对上）。工具只是把「从哪读到」
照实打出来 —— 来源是数据，不是结论。

这个工具就是从那次的教训里长出来的 —— **它的第一条命令就是「先问系统」。**

---

## 它解决什么

校园网/受限网络的限制通常是这六类，**每类的合规做法完全不同**，
而症状看起来一模一样（"网断了"）：

| 限制 | 症状 | 怎么判断 | 合规做法 |
|---|---|---|---|
| **认证门户** | 连上了但什么都没网 | 明文 HTTP 被重定向（判据见下） | 按学校要求完成登录认证 |
| **DNS 被拦** | 能通 IP、打不开域名 | 公共 DNS 全挂但系统 DNS 通 | **优先用系统配置的 DNS**，别改它 |
| **UDP/53 封锁** | DNS 时好时坏 | 同一台服务器 UDP 超时、TCP 正常 | 该限制存在；用什么替代、哪些用途被允许，向信息化中心确认 |
| **客户端隔离** | 同网段设备互相看不见 | 扫本网段一台都没有，但网关通 | 该限制存在，通常有安全理由；哪些用途被允许，向信息化中心确认 |
| **端口封锁** | 只有 80/443 能用 | 直连 IP 逐个端口试 | 同上 —— 不要自行搭隧道规避 |
| **MTU 问题** | 网页能开、传文件卡死 | 大包被静默丢弃 | 先用第 5 节确认，本节只能给「内核已知上限」，不能定性 |

**这个工具的价值不在于"帮你连上网"，而在于告诉你**：

> **到底是哪一类限制，以及为什么学校要这么干。**

因为「网断了」这三个字，背后可能是六个完全不同的原因，用错方向只会浪费一晚上。
（也不会因为「绕过去」而消失 —— 规则问题不是技术问题。）

---

## 安装

**不需要安装。**

```bash
git clone https://github.com/lichj06/campus-net-toolkit
cd campus-net-toolkit
python3 -m campusnet diagnose --skip-scan
```

没有依赖，没有虚拟环境，没有 `pip install`。只要有 Python 3.8+。

（如果你想装成命令：`pip install -e .`，然后可以直接用 `campusnet`。）

---

## 用法

### `diagnose` —— 网络体检

一次跑完，给出结论。局域网扫描很慢，加 `--skip-scan` 跳过。

```bash
python3 -m campusnet diagnose --skip-scan
```

**第 1 节「认证门户」的判据被刻意收紧了。** 必须是下面两条之一才算证据：

1. 明文 HTTP 拿到 **200/204** —— 请求确实到达了目标服务器本身；
2. **两个不同目标的 3xx Location 指向同一个地址** —— 只有中间设备统一劫持才会这样。

单独一个 3xx（比如 `1.1.1.1` 对自己的 http 返回 301）**不算**：那是服务器自己的策略，
任何正常网络都会发生。旧版本把这种也报成「检测到认证门户劫持」，是假阳性的定性结论。
三条判据都测不出来时，本节会明确写「**未能定性**」，而不是硬给一个结论。

实测里这一节就是「未能定性」：

```
  [OK]   明文 HTTP  223.5.5.5 (阿里 DNS)        91 ms  HTTP 404
  [FAIL] 明文 HTTP  114.114.114.114 (114 DNS)     29 ms  ConnectionRefusedError: [Errno 111] Connection refused

  [WARN] 本节未能定性（既不满足 a 也不满足 b）
```

**第 2 节 DNS**：真正的结论在这一节 —— 公共 DNS 在那次运行里全部超时
（7007 / 7010 / 7008 ms，逐字见 `docs/`），而系统配置的解析器 11–13 ms 就返回。

补充一句**按代码推算**（不是日志）的说明：那三个 `70xx ms` 不是某个 7 秒常量，
而是 `dnsproto.query` 的 auto 策略先等 UDP 超时（2 s）再走 TCP（`max(timeout, 5.0)` = 5 s），
2 + 5 ≈ 7 s；上面的 `8009 ms` 同理，是 3 s + 5 s。

**第 4 节 端口与外网可达性**：全部用 IP、不依赖 DNS。
`TCP_TARGETS` 一共 **6** 条，那次运行的可达数是 1/6，6 条逐字如下：

```
  [FAIL] 阿里 DNS (UDP/53 对照)     223.5.5.5:53   3003 ms  TimeoutError: timed out
  [OK]   阿里 DNS (443)           223.5.5.5:443    105 ms  连上了（105 ms）
  [FAIL] 腾讯 DNS                 119.29.29.29:53   3016 ms  TimeoutError: timed out
  [FAIL] 114 DNS                114.114.114.114:53   3014 ms  TimeoutError: timed out
  [FAIL] Google DNS             8.8.8.8:53   3001 ms  TimeoutError: timed out
  [FAIL] Cloudflare             1.1.1.1:443   3003 ms  TimeoutError: timed out

  可达                               1 / 6
```

**第 5 节 MTU —— 现在会说人话，也不给不该给的建议了。**
旧版本用 4 个 HTTP POST（1200/4000/16000/65000 字节）来「测 MTU」，
但那台机器上四个尺寸全都返回 `HTTP 404`，看起来一切正常 —— 其实**什么都没测到**：
TCP 会按 MSS 分段，多大的请求都能发出去，根本碰不到 MTU 上限。

现在改用**带 DF（`IP_MTU_DISCOVER=IP_PMTUDISC_DO`，不分片）的 UDP 探测**，
二分找出内核允许的最大载荷。那次运行的结果：

```
  [OK]   发   1472 字节（带 DF）—— 内核允许发送
  [FAIL] 发   4000 字节（带 DF）—— EMSGSIZE，超过 MTU

  带 DF 可发送上限（估计）               1472 字节 UDP 载荷
  对应 MTU（估计）                   ≈ 1500 字节（载荷 + 8 UDP + 20 IP）
```

但这仍然是「**内核当前已知的上限**」，不是端到端保证：链路中间若有更小的 MTU、
而「需要分片」的 ICMP 又被丢弃或墙掉，本探测看不到。要精确确认请用
`ping -M do -s <载荷> <目标>` 逐点试（需管理员/root）。
Windows 暂不支持该探测（用的是另一套套接字选项），本节会直接写「未能定性」。

### `dnsfind` —— 找出能用的 DNS

```bash
python3 -m campusnet dnsfind
```

**UDP 和 TCP 分别测，而且两侧的错误分开打。** 只看 ✗ 分不出「没响应」和「TCP 被 RST」，
所以失败的那一侧会在下一行给出原因（`TimeoutError` / `OSError: [Errno 113]` / `rcode=` …）。

```bash
python3 -m campusnet dnsfind --apply    # 把结果写进系统配置
```

`--apply` 改的是 `/etc/resolv.conf` 这种系统文件，所以它有三条硬规矩：

1. **只写「UDP 和 TCP 都通」的服务器**。只通一侧的写进去，glibc 会照用不误，
   表现就是「偶尔卡几秒」—— 那次运行里 `192.0.2.99` 就是 UDP 8009 ms 超时的类型，
   它不该被任何工具自动写进配置。一台双通的都没有时，**拒绝写入**。
2. **写之前先备份**成 `resolv.conf.bak-<时间戳>`，并把恢复命令打出来：
   `sudo cp <备份> /etc/resolv.conf`。
3. `resolv.conf` 是符号链接（systemd-resolved / NetworkManager 托管）时**不写**，
   只提示改用 `resolvectl dns`。

### `pin` —— 把域名钉进 hosts

系统 DNS 也不可用时的临时手段：**彻底不查 DNS。**

```bash
python3 -m campusnet pin api.deepseek.com
python3 -m campusnet unpin api.deepseek.com    # 撤掉
```

> 下面这段是**示意输出**，不是本次采集的命令输出 —— 采集时刻意没跑 `pin`
> 和 `--apply`，因为它们会写系统文件。

```
  解析来源         192.0.2.53
  候选 IP          123.125.246.121, 60.28.220.199

  逐个做 TLS 证书校验（确认这些 IP 真的是 api.deepseek.com）
    123.125.246.121    ✅ 证书通过
    60.28.220.199      ✅ 证书通过

  [OK] 已写入 /etc/hosts（2 条）
```

> **每个 IP 都会做一次 TLS 证书校验**（连到 IP:443，用目标域名做 SNI，验证证书链）。
> 不通过的直接丢弃 —— 不能随便从别处抄一个 IP 就信，那等于把流量交给一个陌生服务器。

### `lanfind` —— 在局域网里找设备

```bash
python3 -m campusnet lanfind
python3 -m campusnet lanfind --ports 8899,11434   # 要探自己的端口，必须显式指定
```

**默认只探通用服务端口**（80, 443, 22, 445, 3389, 8080, 8443）。
远控、本地模型这类**个人端口不在默认值里** —— 仓库是公开的，默认带上它们
等于教别人去扫宿舍网里的个人服务，也容易被安全设备当成内网探测。
要探自己的端口，用 `--ports` 显式传。

`--wide` 会扫相邻 6 个 /24。早期版本一有命中就 `break`，导致 wide 实际只扫了第一个
/24，「其他区间一台都没有」这个结论从来没被真正测过；现在每个区间都跑完并逐行报告。

**它会诚实告诉你结论的可靠性：**

```
  网关可达    未知（网关是猜的，不作证据）
```

手机上常常读不到路由表（没有 `ip` 命令），只能按 `X.Y.Z.1` 猜。
**猜错的时候不能拿它当证据** —— 否则会得出「网络层不通」这种错误结论。

### `watch` —— 网络看门狗

网络出问题时，你**往往没法当场诊断** —— 因为诊断工具本身需要网络。
等你回到能上网的地方，现场已经没了。

```bash
python3 -m campusnet watch --target 223.5.5.5:443 --hours 8
```

它常驻，盯三个信号：**IP 变了**、**目标从通变不通**、**从不通变通**。
任何一个触发，立刻把当时的完整现场（DNS 状态、端口可达性、局域网扫描）写进日志。

> ⚠️ **日志含隐私。** 日志里有本机 IP、内网 DNS 地址、局域网扫描结果。
> `.gitignore` 已忽略 `*.log`，但提交前请自己再确认一次：
> `git status --short --ignored | grep '\.log'`。

---

## 测试

零依赖的最小测试（只跑纯函数和 `--help`，不发真实网络请求、不写任何系统文件）：

```bash
python3 -m unittest discover -s tests -v
```

---

## 平台支持

| 平台 | 读系统 DNS | 说明 |
|---|---|---|
| **Linux** | `/etc/resolv.conf` + `resolvectl status` | ✅ |
| **macOS** | `scutil --dns` | ✅ |
| **Windows** | `Get-DnsClientServerAddress` | ✅ 需要 PowerShell（系统自带） |
| **Android (Termux/proot)** | `/etc/resolv.conf` | ⚠️ 读不到路由表，网关靠猜 |

**读系统 DNS 的 Windows 实现是本项目最有价值的一段代码** —— 就是靠它发现了校园网自己的解析器。

---

## 写在最后：为什么学校要这么干

这些限制大多不是"刁难"，而是有理由的：

- **客户端隔离** —— 防止 ARP 欺骗和蠕虫横向传播。一台中毒的笔记本能在五分钟内感染整栋楼。
  学校网络的信任假设是「每个设备都可能是威胁」，家用路由器则是「我们是一家人」。
  **这是设计目标，不是 bug。**
- **出口认证** —— 记录谁在什么时候用了网络。《网络安全法》对公共场所网络有实名要求。
- **DNS 只给校内解析器** —— 便于过滤和审计，也降低了被 DNS 污染影响的面。
- **端口封锁** —— 抑制 P2P、挖矿、私搭服务。

**理解这些之后，会发现「和它对抗」通常不是好策略**：设备互联、远程使用这类需求，
先把用途问清楚（学校信息化中心对哪些用途是放行的），往往比研究怎么穿透隔离省事得多；
实在不属于放行范围，就换个网络环境（比如自己的热点）去做，而不是绕规则。

---

## 局限

- **它不能让你上网。** 认证没过、出口封了，这个工具帮不了你。
- **它不做任何规避。** 不绕过认证/计费/限速/设备数限制，也不提供隧道或穿透。
- **`pin` 是临时手段。** IP 会变，钉死的记录迟早失效。系统 DNS 可用时优先用它。
- **`lanfind` 的结论强度取决于能否读到路由表**（见上）。
- **`diagnose` 第 5 节只能给「内核已知的 MTU 上限」**，不构成端到端 MTU 结论。
- **`watch` 只记录，不告警。** 需要推送的话得自己接。
- **git 历史里仍有旧版本留下的真实内网地址。** 当前所有文件已换成文档保留地址，
  但历史提交（`git log -p`）里还找得到，需要的话由仓库所有者重写历史处理。

---

## License

[MIT](LICENSE)
