---
title: "事件日志清除与那些能幸存的缺口"
description: "攻击者如何清除 Windows 事件日志，磁盘上与转发通道里会留下什么证据，以及 wevtutil cl 与 Invoke-Phant0m 这类挂起线程的工具之间的差异。"
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

事件日志清除是每个操作者最先学到的反取证技术，也是留下最可用线索的那一种。后半句反直觉。清日志的初衷就是抹去证据，能把 `Security.evtx` 清干净的攻击者，确实抹掉了你本想读的几千条事件。但清除行为本身是吵的，那些试图更安静的技术留下另一种、同样诊断意义十足的签名，而大多数操作者忽略的通道，仍然能保留足以重建被清掉内容的线索。

知道什么能幸存很重要，因为它改变你向这台主机提的问题。"Security 日志里有什么"变成了"Security 日志里少了什么，这些事件去了哪里"。

## 1102、104、1100：吵的方式

一个想让 Security 日志消失的操作者的默认反应，是 `wevtutil cl Security`。这会产生：

- `Security.evtx` 中一条 `EventID=1102`，在清除后立即生成，记录执行清除操作的账户与时间。这条事件能在被清的日志里幸存，因为它是被清空文件中写入的第一条事件。把它当作冒烟的枪。账户名、源工作站、清除时间都在事件数据中。
- `System.evtx` 中由 `Microsoft-Windows-Eventlog` provider 产生的一条匹配的 `EventID=104`，包含被清除的通道名。这是 `1102` 在 System 日志的镜像。有时只剩其中一条，因为操作者清了多个通道而顺序决定了哪个能活下来。
- 如果操作者在清除之前停了服务，事件日志服务还会出一条标志服务关闭的 `1100`。`1100` 之后跟着无法解释的缺口、再跟着 `1102`，就是经典的"关停、动手、重启"模式。

这三条事件就是吵闹的签名。心里有数的攻击者要么不会生成它们，要么生成之后再*清一次*来抹掉它们，这会再产生一条 `1102` 与更小的幸存日志。每一次清除都会留下一条 `1102`。一台主机历史里出现多条 `1102` 这件事本身就是异常。

被清掉的事件不是唯一的受害者。清除一个通道会重置其底层 EVTX 文件，意味着磁盘上的文件被重写。旧文件的块进入未分配。在合理时间窗内做主机镜像，它们仍可从磁盘恢复，这是同一故事的另一条分支（在 carving 那篇里讲）。

## `wevtutil cl` 与挂起线程

更老练的操作者根本不清日志。他们挂起 Windows Event Log 服务（`eventlog`）的线程，做完想做的吵闹动作，再恢复线程。线程挂起期间，操作系统与应用程序产生的事件在 ETW 基础设施中排队，但不会写入 EVTX。线程恢复后，队列大体会被刷完，但在挂起窗口内溢出缓冲的事件就永远丢了。

这就是 `Invoke-Phant0m`（PowerShell，由 Halil Dalabasmaz 编写）的工作方式。Mimikatz 模块 `event::drop` 类似，但是是在服务进程内 hook ETW 回调。两者都留下：

- 没有 `1102`。什么都没被清除。
- 没有 `104`。同理。
- 一段缺口。挂起窗口之前与之后的事件都在；窗口之内的事件不见了。这就是检测点。

缺口可以通过两种方式发现。第一是连续 RecordID 健全性检查：EVTX 块头记录了 `FirstEventRecordIdentifier` 与 `LastEventRecordIdentifier`，你可以核验跨块的 RecordID 是否单调递增。挂起不会破坏 RecordID 计数器（被挂起的是服务，不是内核 ETW provider），但块内的时间戳会显示一个没有任何忙碌 provider 事件的窗口，在域控上一目了然。

第二是与那些"不重新提权就停不下来"的通道做对照。`Microsoft-Windows-EventLog%4Operational.evtx` 通道记录事件日志服务自身的生命周期。挂起线程不会在这里产生显式的"线程被挂起"事件，但服务的内部心跳（事件 `105`、`106`，以及在更高详细度下的特定 provider 调试事件）有时会记录这种不一致。

第三种，最难，是 [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config) 的轨迹。Sysmon 通过自己的驱动写入自己的通道，不受事件日志服务挂起影响。一台装了 Sysmon 的主机在挂起窗口期间会有连续的进程创建与 image load 记录。把 `Security.evtx` 中可疑缺口的时间，与 Sysmon 的 `Operational` 通道做交叉。如果 Sysmon 显示在缺口开始时运行了一个 `powershell.exe`，其命令行内容与 Phant0m 源码（或十几种公开变体之一）相符，你就有了答案。

## 转发事件通道

Windows Event Collector（WEC）是把事件转发到中心收集器的标准机制。在 Windows Event Collector 订阅者上，转发的事件落到 `Microsoft-Windows-EventLog%4ForwardedEvents`，保留来源主机的 `Computer` 字段、原始 `RecordID`，以及原始时间戳。

如果你的环境有 WEC，且收集器本身未被攻陷，转发事件通道有时是一台本地日志被清主机上发生的事情唯一完整的记录。这些事件在字节层面与发起主机生成的原始事件相同（除了收集器额外加的元数据），来源主机的 `RecordID` 让你能把转发副本拼回本地日志的 RecordID 时间线。

注意：WEC 订阅默认是拉式的，心跳为 15 分钟。速度快的攻击者可以在两次转发心跳之间清掉本地日志，收集器上只会有上一次成功拉取之前的事件。请把你关心的通道改为 `MinLatency` 模式（推送，30 秒批次延迟）。这会消耗网络与收集器吞吐；但在你第一次真正需要它的时候就会回本。

另一个注意：WEC 默认不转发。如果没人配过订阅，收集器上的通道是空的。在把调查押在这条证据路径之前，先确认候选收集器的订阅状态。

## 选择性删除与 EVTX 层面的问题

在保留其余事件的同时，从活动 EVTX 文件中选择性删除特定事件，从理论上是可以做到的：要懂格式、编辑文件并重新计算块 CRC。但在实际生产中没人这么干。事件日志服务持有该文件并锁住它；不停掉服务你无法从用户态编辑，而停掉服务又会产生 `1100`/`105` 事件。

现实里发生的是事后离线篡改。一个操作者外泄 EVTX 文件、在自己机器上改、再（在停掉服务之后）传回去替换活动文件，会留下：

- 编辑过的块上不一致的 CRC，除非他们正确地把块头 CRC 与记录区 CRC 都重新算了一遍。
- 如果他们没同步更新，块头里的 `LastEventRecordNumber` 也会不一致。
- RecordID 在块边界上不连续。

任何像样的解析器都会标记这些。`evtx_dump` 默认在 CRC 不匹配时发出警告。`EvtxECmd` 会在输出里记录差异。来自疑似被入侵主机的 EVTX 文件，在解析过程中出现的任何 CRC 警告，都应视作潜在篡改指示，并在做任何其他事情之前先对底层磁盘做镜像。

## 只在 `Microsoft-Windows-EventLog%4Operational.evtx` 浮现的内容

这个通道独立于 `Security.evtx`，大多数攻击者会忽略它。它记录：

- 事件日志服务的启动与停止（`105`、`106`）。
- 通道状态变更（订阅启动、通道启用/禁用）。
- Manifest 注册事件。

当事件日志服务被重启（操作者用了 `Stop-Service eventlog`，或他们打了补丁重启了主机），这里会出现与 `1100`/`105`/`106` 家族配对的事件。如果 `Security.evtx` 在 T 时刻显示 `1100`，且 `EventLog%4Operational.evtx` 在同一 T 显示了相应的服务状态变更，说明关停是有序的。如果 `Security.evtx` 显示一个缺口却没有 `1100`，但 `EventLog%4Operational.evtx` 显示服务被重启了，那么服务是在没有有序关停的情况下崩了或被杀掉了，这本身就可疑。

这个通道很小，读起来很快。把它加入你默认的分诊清单。

## 与主机产物做交叉验证

当 Security 日志没了或被动过手脚，能存活的产物就是熟悉的那一拨：

- EVTX 文件自身的 [Master File Table](https://www.mftparser.com)。`$STANDARD_INFORMATION` 与 `$FILE_NAME` 时间戳会显示该文件何时因为清除而被改写。
- 针对 `Security.evtx` 的 [USN journal](https://www.usnparser.com) 中的 `DATA_OVERWRITE` 与 `DATA_TRUNCATION` 事件。这些以日志术语提供高分辨率时间戳来标记清除。
- [Prefetch](https://www.prefetchparser.com) 里 `wevtutil.exe` 的执行记录，或与可疑清除时间对齐的 `powershell.exe` 运行。
- 操作者带进来用以清除的工具的 [Shimcache](https://www.shimcacheparser.com) 与 [AmCache](https://www.amcacheparser.com)，尤其当他们用的是非默认二进制时。
- 如果你抓了 [RAM dump](https://www.ramparser.com)，相关产物。事件日志服务的内存缓存中会有从未被刷到磁盘的记录。

Security 日志是一个来源。把它当作一个来源来对待。仅靠它的调查，离"一份被篡改的文件"只有一步之遥。[本站的解析器](https://www.evtxparser.com) 会在输出里标记块 CRC 不匹配与 RecordID 缺口，这是在你花一个小时去读它之前判断是否在看一份被篡改日志的廉价首轮检查。

## 延伸阅读

- Halil Dalabasmaz 的 [Invoke-Phant0m 源代码](https://github.com/hlldz/Invoke-Phant0m)。读读它在做什么，检测就顺势可得。
- Roberto Rodriguez 的 [ThreatHunter-Playbook 关于 1102 的条目](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html)，以及周边的清除检测材料。
- Microsoft 关于 [Windows Event Collector 订阅](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) 的文档，这是让你拥有转发事件这张安全网的 WEC 配置。
