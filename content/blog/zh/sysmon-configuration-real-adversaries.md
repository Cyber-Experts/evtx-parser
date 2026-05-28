---
title: "捕获真实攻击者的 Sysmon 配置"
description: "对 Sysmon 的观点: 哪些 event ID 在 IR 中真正重要、为什么 olafhartong/sysmon-modular 是正确的基线、以及让你对真实攻击视而不见的配置错误。"
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon 是你可以部署到 Windows endpoint 上杠杆最高的东西。它是免费的，由 Microsoft 签名，配置良好的 Sysmon 将 Windows 从黑盒变成你实际可以调查的东西。另一方面，配置不当的 Sysmon 是相同的磁盘空间成本，但由于过于激进的过滤器，大部分可见性被排除了。我进入的环境中有第二种的比第一种多。

这是我在每次涉及 endpoint 可见性的 engagement 中主张的配置姿态。

## 值得磁盘空间的 EID

Sysmon 截至版本 15 定义了 29 个 event ID。你不需要全部。按每字节回报顺序，那些回本所花存储的:

- **EID 1 Process create**。DFIR 中最有用的单一事件。父进程、子进程、command line、integrity level、用户、两个进程 hash、process GUID。如果你从 Sysmon 不记录任何其他东西，就记录这个。
- **EID 3 Network connection**。每个出站 TCP/UDP 连接，带源进程、目的 IP、端口和进程 image。C2 检测事件。这里过滤器是必需的（默认安装会记录每个浏览器请求，你的保留期会在一周内烧光），但每事件的价值极高。捕捉从异常进程到异常目的地的出站（`rundll32.exe` 到住宅 IP，`mshta.exe` 到任何东西）。
- **EID 7 Image loaded**。带加载 image hash 和签名状态的 DLL 和 driver 加载。这是你如何捕捉 DLL 搜索顺序劫持、sideloading 和未签名 driver。记录所有内容代价高昂；记录未签名模块和从非标准位置加载的模块代价低且产量高。
- **EID 10 Process accessed**。带源进程、目标进程、授予的访问掩码和 call trace 的跨进程内存访问事件。这是凭证转储事件。`mimikatz` 用 `PROCESS_VM_READ` (`0x10`) 和 `PROCESS_QUERY_INFORMATION` (`0x400`) 打开 `lsass.exe`。每个现代 dumper 都这样。检测规则自然写出来。
- **EID 11 File created**。带写入进程的新文件创建。捕捉未能执行的 dropper 活动、ransomware staging 以及大多数 LOLBin 中介的 payload 写入。

这五个是基础。如果你只有这些，配置良好，你在它成为真实入侵之前已经捕获了大部分你会称为真实入侵的东西。

值得开启的下一层:

- **EID 8 CreateRemoteThread**。跨进程边界的线程注入。经典的进程注入事件。
- **EID 13 Registry value set**。通过 registry 的持久化。调整到 run keys、services、image file execution options 和 COM 劫持路径。
- **EID 17/18 Named pipe created/connected**。Cobalt Strike beacons 和许多后利用框架使用 named pipes 进行 SMB 和进程间通信。pipe 名称通常是从 engagement 到 engagement 都保留的默认值。
- **EID 22 DNS query**。带请求进程的出站 DNS。当 EID 3 因为从未打开 TCP/UDP socket 而错过连接时，捕捉基于 DNS 的 C2（DGA、DNS tunnel）。
- **EID 25 Process tampering**。Image 操纵事件（process hollowing、doppelganging）。Sysmon 13+。

EID 12（registry key/value create）、14（registry key/value renamed）、15（带 FileCreateStreamHash 的 file stream created）和 23（带 archive 的 file delete）在特定调查中有用，但产生太多量无法默认在所有地方记录。为你密切观察的主机或特定路径开启它们。

EID 2（process changed file creation time）是一个小众的 anti-timestomp 事件。在文件服务器上值得。其他地方可选。

EID 4、5、6（Sysmon 状态事件）是运行的，不是检测。记录它们以便你能知道 Sysmon 何时被篡改。

## 为什么 `olafhartong/sysmon-modular` 是正确的起点

有半打质量各异的公开 Sysmon configs。引用最多的两个是 SwiftOnSecurity 的 `sysmon-config` 和 Olaf Hartong 的 `sysmon-modular`。两个都好。`sysmon-modular` 是我因其结构而推荐的那个。

模块化布局按 EID 和技术将过滤器分割为单独的 XML 文件，在部署时连接。它给你带来的好处:

- **可 diff 性**。对单一技术的过滤器的更改在 git 中显示为单文件 diff。比较 4000 行单体 XML，其中小改动在噪音中消失。
- **每环境的 overlays**。你 commit 上游树并在自己的文件中将环境特定的排除作为 layer。当上游更新过滤器时，你 `git merge`，你的 overlays 存活下来。
- **覆盖驱动的编写**。过滤器按 MITRE ATT&CK 技术组织。你可以一眼看出哪些技术你有覆盖，哪些没有。差距分析就是文件树。
- **积极维护**。Hartong 针对新技术和新 Sysmon 版本更新仓库。SwiftOnSecurity config 在更新之间有长时间停滞。

从 `sysmon-modular` 开始。commit 到你的 config 管理树。将你的排除作为 layer。不要从头写自己的；你会遗漏东西。

## 让你视而不见的配置错误

我在真实 engagement 中看到的最损害可见性的模式:

**在 EID 1 中过于激进地排除**。本能是排除每个嘈杂的合法进程以保持量可管理。错误是按父路径或 image 排除，而不考虑攻击者可以从该父进程 spawn 什么。如果你排除 `services.exe` 的每个子进程，你就排除了 PsExec 安装的服务二进制文件运行的确切位置。按 `User`（运行已知良好二进制文件的系统帐户）、按 `IntegrityLevel`、按精确的 `CommandLine` 匹配排除，不要仅按父进程。

**按 image 名称排除 EID 3**。"排除 `chrome.exe` 的所有网络连接"是规范的坏规则。攻击者需要规避 EID 3 日志记录时做的第一件事就是劫持浏览器进程。按目的 IP 范围（RFC1918 到 RFC1918，你自己的基础设施）、按端口（你已验证的 IPC 端口集）或按进程+目的元组排除。永远不要只按 image。

**完全不记录 EID 7**。Image load 日志记录是按量最重的 Sysmon EID。禁用它的诱惑很强。禁用它的代价是 DLL sideloading（现代入侵中最常见的技术）对你不可见。中间路径: 将 `Image load` 过滤到未签名模块、从 `%APPDATA%`、`%LOCALAPPDATA%`、`%TEMP%`、`%PUBLIC%` 和 `%PROGRAMDATA%` 加载的模块，以及名称匹配已知滥用列表的模块。这将量减少一个数量级并保留信号。

**在用户可写路径上完全缺失 EID 11**。为 `%TEMP%`、`%APPDATA%\Roaming`、`%LOCALAPPDATA%` 和 `%PUBLIC%` 记录的 EID 11 几乎捕获每个 dropper。一些 configs 因为量而排除这些。量就是重点: 那是重要写入发生的地方。

**不包括你想要的 hash 算法**。`<HashAlgorithms>` 元素控制 Sysmon 计算哪些 hash。默认只有 SHA1。`IMPHASH` 是 import-hash，在恶意软件跟踪中大量使用；`SHA256` 是大多数威胁情报平台键入的。设置 `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` 以便事件与你的情报数据使用的内容对齐。

**不在父进程上记录 command line**。Sysmon EID 1 记录 `CommandLine`（子）和 `ParentCommandLine`（父）。一些 configs 禁用 `ParentCommandLine`。这扼杀了进程树调查中最有用的 pivot；没有它你有父 image 名称但不知道什么参数启动了那个父进程。

**完全不启用 EID 22（DNS）**。DNS 日志记录是最近的（Sysmon 10+），许多 configs 早于它。开启它。过滤嘈杂的主机（`*.windowsupdate.com`、你的内部 AD），记录其他一切。

## 磁盘空间权衡

典型工作站上配置良好的 Sysmon 每天产生 100-500 MB 的 EVTX。在繁忙的服务器上，1-5 GB。默认通道大小是 64 MB，这意味着 `Microsoft-Windows-Sysmon%4Operational.evtx` 文件在数小时内滚动，你可用的保留期很短。

修复是两步的。首先，提高通道大小。`wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` 将其设置为 4 GB，在大多数主机上给你数天到数周。其次，转发到具有更长保留期的中央 collector。WEC 有效；SIEM 代理有效；[Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) 仓库有用于通道订阅的 XML。

集中化保留比本地保留更重要，因为本地文件是攻击者可以清除的。在他们无法到达的 collector 上的转发副本是持久记录。两者都配置。

## 良好的 Sysmon 在调查中是什么样子

部署了 `sysmon-modular`、所有五个核心 EID 都在记录、EID 7 过滤到有趣的模块、转发到 collector 的主机，给你:

- 主机上每次执行的进程树，带 command lines、hashes 和用户上下文。
- 每个带原发进程的出站网络连接。
- 来自用户可写目录的每个 DLL 加载。
- 对 `lsass.exe` 的每个内存访问。
- 在 `%TEMP%` 和 `%APPDATA%` 中的每个文件创建。
- 每个带请求进程的 DNS 查询。

入侵故事从这些数据中自然读出。你不需要猜测。你不需要 carve。你从上到下读它，故事中的空白就是要追的问题。与 [AmCache](https://www.amcacheparser.com) 和 [Prefetch](https://www.prefetchparser.com) 交叉引用以获取二进制执行证据，与[注册表](https://www.registryparser.com)获取持久化，与 [USN journal](https://www.usnparser.com) 获取 Sysmon 的 EID 11 如果其过滤器关闭可能遗漏的文件系统变更。本站点上的 parser 以与 Security.evtx 相同的保真度读取 Sysmon 通道。

没有 Sysmon，你有 `Security.evtx` 和一个愿望清单。

## 延伸阅读

- Olaf Hartong 的 [sysmon-modular](https://github.com/olafhartong/sysmon-modular)。仓库。读 README，然后读三四个技术特定的 XML 文件以了解过滤器风格。
- Microsoft 的 [Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)。官方参考；薄但准确。
- Roberto Rodriguez 的 [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook)。Sysmon 驱动的 hunts，查询写得很清楚。
- [TrustedSec sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide)。过滤器语义的参考文档。
