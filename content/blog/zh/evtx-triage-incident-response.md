---
title: "EVTX 分诊：只有一小时与一台主机时该先读什么"
description: "应急响应中 Windows 事件日志分诊的实务操作顺序——哪些通道重要、哪些 Event ID 会骗你，以及 Sysmon 在哪里挑大梁。"
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

如果有人把一份疑似被入侵主机的 EVTX 文件包递给你，并只给你一小时，你没时间讲究优雅。你只有时间走一遍那种已经成功过足够多次、以至于在你读一条记录之前就值得信任的操作顺序。

这就是我的顺序。不是完整参考，也不适用于每一个案件——慢节奏的内部人员调查需要完全不同的姿态——但对"这玩意儿被打穿了吗？怎么打的？"这个标准问题，我跑这一套。

## 真正能把时间换回来的通道

默认 Windows 安装会带超过三百个 EVTX 通道。你大概只会看七个。一直重要的：

- `Security.evtx` —— 登录、特权使用、账户变更。每一次互动型事件的第一站。
- `Microsoft-Windows-Sysmon%4Operational.evtx` —— 如果部署了 Sysmon（也应该央求、施压、威胁直到它被部署），真正的信号住在这里。带命令行的进程创建、文件创建、网络连接、DNS、image load。`Security.evtx` 暗示却没明说的一切。
- `System.evtx` —— 服务安装、加载的驱动、启动事件、时间变更。常常是横向移动唯一留下服务安装痕迹的地方。
- `Application.evtx` —— 通常是噪声，但 Office 宏错误、.NET 异常和一些 EDR 副通道会在这里浮出来。
- `Microsoft-Windows-PowerShell%4Operational.evtx` —— 模块日志与流水线事件（若启用）。`4104` 脚本块日志，是你找到每一行恶意 PowerShell 的地方，前提是日志开了。两者同时开启时，它是仅次于 Sysmon 的第二重要通道。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` —— 计划任务的创建、删除与执行。读起来很短，回本很快。
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` —— WMI 订阅与消费者注册。读取成本低；能抓到一种特定的持久化模式。

如果主机有 Defender，也把 `Microsoft-Windows-Windows Defender%4Operational.evtx` 拿上。`1116` / `1117` 家族有时是对那个关键文件唯一的同时代提及。

其他都可以留到第二遍再看。

## 我第一个打开的不是 Security 日志

默认反应是去 `Security.evtx` 里 grep `4624`。我已经不在第一遍这么做了，你大概也该停。繁忙服务器上的 Security 日志每小时记录数千条合法登录。你还没把问题界定清楚就会被噪声淹没。

我第一个打开的，是过滤到怀疑时窗内 `EventID=1`（进程创建）的 `Sysmon%4Operational.evtx`，前提是它存在。Sysmon 给你父进程、按实际调用的命令行、用户、完整性级别，以及父子两端的哈希。这足以让你直接从屏幕上读出故事。

如果没有 Sysmon（在数量令人沮丧的企业 Windows 资产中仍然没有），我的下一步是过滤到 `4688` 的 `Security.evtx`，*前提是命令行审计已启用*。如果没审计命令行，你只能拿到光秃秃的程序名，几乎没用——那时我会跳到 AmCache、Prefetch 与 [USN journal](https://www.usnparser.com) 去重建运行过什么。

要大声说出来的推论：没有 Sysmon、也没有 `4688` 命令行的 EVTX 调查，基本就是在猜谜。如果你在事件发生前读到这段，先把这两个修好。

## 你终究不再需要查表的那些 Event ID

最终你会背下来。简短版，附我在 IR 里对每条的想法：

- `4624` —— 成功登录。先读 `LogonType`：`3` 是网络（文件共享、远程工具）、`10` 是 RDP / Terminal Services、`2` 是交互、`9` 是带显式凭据的 `runas`。`5` 是服务。`LogonType` 比事件本身承载的意义更多。
- `4625` —— 失败登录。爆发是喷洒攻击；横跨多账户的零散事件是撞库。
- `4634` / `4647` —— 注销与用户发起的注销。给会话画上括号时有用。
- `4648` —— 使用显式凭据的登录。横向移动归因真正要的那一条：当账户 A 用账户 B 的凭据启动进程或连接某处时，就是这条。多数防御者用得不够。
- `4672` —— 登录时被授予特殊特权。"这个账户刚刚等同于管理员"那一行。与前面的 `4624` 配对看。
- `4688` —— 进程创建。仅当启用命令行审计（组策略：*Audit Process Creation* 与 *Include command line in process creation events*）时有用。否则你只看到程序名。
- `4697` —— 服务被安装。通过 PsExec、Impacket-`smbexec` 等工具的横向移动住在这里。
- `4720` / `4732` / `4738` —— 账户创建、组成员变更、账户被修改。持久化最爱这些。
- `1102` —— Security 日志被清。一旦看到它，那之前的 Security 日志要么可疑要么缺失。事件本身的存在就是冒烟的枪。
- `5140` / `5145` —— 网络共享被访问。后者会记录文件名；开启后，经 SMB 的横向移动可被详细审计。
- `7045` —— 服务被安装（System 日志）。`4697` 在 System 通道侧的镜像。
- `Sysmon 1` —— 带完整上下文的进程创建。Sysmon 开启时，DFIR 里最有用的单一 Event ID。
- `Sysmon 3` —— 网络连接。能抓到 Defender 没抓到的出站 C2。
- `Sysmon 10` —— 进程访问。抓住对 `lsass.exe` 的凭据转储。
- `Sysmon 11` —— 文件创建。抓住没机会执行就被丢下的 dropper。
- `PowerShell 4104` —— 脚本块日志。记录每一条 PowerShell 命令的完整文本，包括混淆过的（多数情况下是解码后的）。

我桌边放一张打印的速查表，你也应该这么做。不够光鲜，但能省下真金白银的几分钟。

## 会骗你、或容易误读的事件

来自 `\\NT AUTHORITY\ANONYMOUS LOGON` 的 `4624 Type 3` 不是"攻击者进来了"。通常是配置错误的共享枚举、漏洞扫描器，或半打 Windows 内部机制之一。在升级前先核实。

针对一个服务账户每分钟一次的 `4625`，几乎一定是某处缓存了陈旧凭据。在你叫它"暴力破解"之前，先看源工作站字段。

在某些工具里，Security.evtx 的时间戳默认是生成它的主机的本地时间，在另一些工具里是 UTC。在新工具里加载文件包时，找一条能与已知外部事件（一次工单更新、一段 VPN 会话）对齐的登录，做一次健全性检查并确认偏移。我见过整份报告被偏移 4 小时，就因为有人忘了核实。

事件日志清除（`1102`）通常很吵，但选择性记录删除是另一种东西。`wevtutil cl` 清整条通道，可被发现。`phant0m` 与 `Invoke-Phant0m` 之类的工具改为挂起事件服务线程，不留清除事件，但会留下可见缺口。请找那个缺口，不要只盯 `1102`。

转发事件（`Microsoft-Windows-EventLog%4ForwardedEvents`）保留来源主机的 RecordID 与原始时间戳。如果你有从事件中存活下来的 WEC 订阅者，那些副本有时是仅存的完整记录。

如果 Security 日志显示 `1100`（事件服务关闭）之后跟着无法解释的缺口，那你看到的是更干净的抹证据手法之一。请与[注册表蜂巢](https://www.registryparser.com)、[Master File Table](https://www.mftparser.com)、Prefetch 做交叉验证。

## 缺记录时的雕刻与恢复

当活动文件被清或轮转时，EVTX 记录可以从未分配磁盘空间与 [pagefile.sys](https://www.pagefilesysparser.com) 中雕出。记录头（`2a 2a 00 00` 魔数）具有足够辨识度，按签名雕刻效果还可以。Yamato Security 的 `hayabusa` 与 `evtx_dump` 都能在记录流被打过补丁的畸形文件上工作。

如果你怀疑某台主机的日志被篡改了，也试试从 [RAM dump](https://www.ramparser.com) 恢复 EVTX 记录。事件日志服务会在内存里缓存近期记录；事件附近时间点的快照，有时含有从未落到磁盘的记录。

## 一条命中之后往哪里走

单一事件几乎不会结案。我顺手用的几个枢纽点，按顺序：

- 一条可疑的 `4624` → 找对应的 `4672`、之前的 `4625` 失败，以及随后用那个令牌创建了什么进程（按对应 `LogonId` 的 Sysmon 1）。
- 一条 `7045` 或 `4697` 服务安装 → 看 `Microsoft-Windows-TaskScheduler%4Operational.evtx` 里的后续任务，以及 [registry](https://www.registryparser.com) 里 `HKLM\SYSTEM\CurrentControlSet\Services\` 中的二进制路径。
- 针对 `lsass.exe` 的 Sysmon 10 → 请求进程的进程树、工作目录中的文件投放、对非企业目的地的网络连接。
- 带混淆内容的 PowerShell 4104 → 在沙箱里解码，然后到其他主机上找同一载荷落地的痕迹（多数企业攻击者会复用）。

## 在浏览器里读 EVTX

[本站的解析器](https://www.evtxparser.com) 完全在客户端读 EVTX：拖入一个文件，你就能得到一个可排序、可过滤的表，含通道、RecordID、EventID、时间、计算机和已渲染的 XML。不上传，这一点很重要，因为来自受监管环境的 EVTX 几乎都包含你不愿越过厂商边界的 PII。

## 延伸阅读

- JPCERT/CC 的 ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) —— 关于横向移动事件关联最有用的单一文档。值得慢读。
- Eric Zimmerman 的 [EvtxECmd](https://github.com/EricZimmerman/evtx) —— 带规范字段映射输出的离线解析器。
- Microsoft Threat Intelligence（即原 SwiftOnSecurity）作为基线维护的 Sysmon 配置：[sysmon-modular](https://github.com/olafhartong/sysmon-modular)。从这里开始，不要从零自己写。

把上面这一切翻成愤世嫉俗版：有了 Sysmon 与命令行审计，EVTX 能给你重建一次入侵所需的 80%。没有它们，你在对事件的剪影做取证，而不是事件本身。
