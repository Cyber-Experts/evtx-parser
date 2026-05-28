---
title: "从这里开始：DFIR 分析师的 .evtx 指南"
description: ".evtx 是什么、哪些通道重要、必须掌握的 Event ID，以及它们在磁盘上的位置。本博客其他所有内容的导航起点。"
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` 是微软随 Vista 引入的二进制 Windows 事件日志格式，用来取代更老的 `.evt`。它几乎是每一次 Windows 应急响应的脊柱：登录、服务安装、计划任务、PowerShell 命令行、Sysmon 进程树，所有这些都会被序列化到这个格式里。本文是索引。先用一屏给出全景，再链接到针对真正重要的通道与 Event ID 的深入文章。

第一次接触 `.evtx`？先看[什么是 .evtx 文件](/zh/blog/what-is-an-evtx-file)和[如何打开它](/zh/blog/how-to-open-an-evtx-file)。本文后半部分默认你已经熟悉该格式，想知道一台主机起火时该先读什么。

## 文件位置

实时日志位于 `C:\Windows\System32\winevt\Logs\` 下。一个通道对应一个 `.evtx` 文件。你一定能见到的默认通道：

- `Security.evtx`。登录、特权使用、审计策略变更。多数案件中取证价值最高。
- `System.evtx`。驱动、服务、操作系统级错误。
- `Application.evtx`。应用程序级错误。
- `Setup.evtx` 与 `ForwardedEvents.evtx`。安装记录与转发的 WEF 流量。

此外是 `Microsoft-Windows-*` 下的应用程序通道。真正在案件中物有所值的几个：

- `Microsoft-Windows-Sysmon%4Operational.evtx`。仅当 Sysmon 已安装时存在。装上之后就是金矿。
- `Microsoft-Windows-PowerShell%4Operational.evtx`。Scriptblock 与模块日志。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`。计划任务的创建与运行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`。RDP 会话生命周期。

关于文件如何在字节层面布局（64 KB 块、XML 模板表、BinXML），参见[块级深入解读](/zh/blog/evtx-file-format-chunks)。

## 必须掌握的 Event ID

覆盖分析师常用支点的简短清单：

- [**4624** 成功登录](/zh/blog/understanding-event-id-4624)。通过 `LogonType` 来读。这一字段决定你看到的是控制台 (2)、网络 (3)、RDP (10) 还是 `runas /netonly` (9)。
- [**4625** 失败登录](/zh/blog/detecting-4625-brute-force)。爆发模式可能是侦察、暴力破解或密码喷洒，取决于哪些字段聚集在一起。
- [**1102** Security 日志被清除](/zh/blog/event-id-1102-cleared-log)。看到它，意味着你手上的日志存在已知的缺口。要大声地把这点写进报告。
- [**4104** PowerShell scriptblock](/zh/blog/powershell-4104-scriptblock)。脚本主体在解码与反射*之后*的版本。这个平台上最有用的免费防御控件。
- [**7045** 服务安装](/zh/blog/service-creation-event-id-7045)。MITRE ATT&CK 中被引用最多的持久化技术之一（T1543.003）。也是 PsExec 的标志。
- [**Sysmon 1** 进程创建](/zh/blog/sysmon-event-id-1-process-create)。当 Sysmon 在场时，Windows 能产生的最丰富的进程创建记录。

把它们串起来的工作流，请阅读[只有一小时与一台主机时的 EVTX 分诊](/zh/blog/evtx-triage-incident-response)。

## 这个网站的位置

主页上的解析器是 Rust crate [omerbenamram/evtx](https://github.com/omerbenamram/evtx) 编译为 WebAssembly，在 Web Worker 中运行。把 `.evtx` 拖进来，Worker 遍历所有块，你就得到一个可过滤的事件时间线和按记录展开的 XML。一切在浏览器中完成，不会上传。当你不想启动 EDR、也不想把文件从一台不属于你的系统上移走时，用它做即兴分诊。

如果你在[从一台运行中的主机收集 `.evtx`](/zh/blog/collecting-evtx-from-live-system)（KAPE、FTK Imager、`wevtutil`），那篇文章覆盖了四种标准方法以及各自的证据链取舍。

EVTX 几乎从不是你唯一需要的产物。把它与 [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[AmCache](https://www.amcacheparser.com)、[Shimcache](https://www.shimcacheparser.com)、[prefetch](https://www.prefetchparser.com)、[LNK](https://www.lnkparser.com) 解析器搭配使用。当你需要挖得更深时，[pagefile](https://www.pagefilesysparser.com) 与 [RAM dump](https://www.ramparser.com) 解析可以恢复磁盘日志已经丢失的内容。对于用户活动时间线，[SRUM](https://www.srumparser.com)、[jump lists](https://www.jumplistparser.com)、[recycle bin](https://www.recyclebinparser.com)、[recent file cache](https://www.recentfilecacheparser.com)、[browser history](https://www.browserforensics.app) 可以填补 EVTX 无法填补的空白。
