---
title: "什么是 evtx 文件?Windows 事件日志格式详解"
description: "evtx 文件是 Windows 事件日志的二进制格式。本文讲清楚它存在哪、内部结构是什么、与 .evt 有何不同,以及如何在不安装任何软件的情况下打开它。"
date: "2026-05-24"
faq:
  - question: "什么是 evtx 文件?"
    answer: "evtx 文件是 Windows Vista 引入的二进制 Windows 事件日志格式,由 EventLog 服务负责写入,记录系统、安全与应用程序事件。每台 Windows 机器在 C:\\Windows\\System32\\winevt\\Logs\\ 下都会有数十个 .evtx 文件,每个通道对应一个文件。"
  - question: "evtx 文件在 Windows 上存放在哪里?"
    answer: "默认路径是 C:\\Windows\\System32\\winevt\\Logs\\。其中流量最大的三个文件是 Security.evtx、System.evtx 和 Application.evtx。各应用专属通道也在同一目录下,文件名形如 Microsoft-Windows-Sysmon%4Operational.evtx。"
  - question: "evtx 与 evt 有什么区别?"
    answer: "evt 是 Windows XP 及 Server 2003 时代沿用的旧式二进制格式。evtx 在 Windows Vista(2007)中取而代之,采用基于 BinXML 的分块布局,支持更丰富的事件元数据、更大的日志体量,以及通过 wevtutil 与 Get-WinEvent 进行结构化查询。两种格式互不兼容。"
  - question: "如何打开 evtx 文件?"
    answer: "Windows 内置工具:事件查看器(eventvwr.msc)、命令行下的 wevtutil,或 PowerShell 中的 Get-WinEvent。跨平台方案:使用本站的浏览器解析器(无需安装、不上传文件),或在命令行下使用 evtxecmd。完整方案请参阅我们的「如何打开 evtx 文件」一文。"
  - question: "能在 macOS 或 Linux 上打开 evtx 文件吗?"
    answer: "可以。原生 Windows 工具无法使用,但有多款跨平台解析器:本站的浏览器解析器(任何带现代浏览器的操作系统)、python-evtx、Rust 的 evtx crate,以及通过 mono 运行的 evtxecmd。它们都不需要 Windows 主机。"
---

`.evtx` 文件是微软在 2007 年随 Windows Vista 推出、用以取代旧式 `.evt` 格式的二进制 Windows 事件日志格式。操作系统、驱动、服务或应用程序写入 Windows 事件日志的每一条事件,最终都会落到磁盘上的某个 `.evtx` 文件里。它们是任何一次 Windows 调查的脊柱。

## 速答

`.evtx` 文件由 Windows EventLog 服务写入 `C:\Windows\System32\winevt\Logs\`。每个**通道**对应一个文件(`Security.evtx`、`System.evtx`、`Application.evtx`,加上各应用专属通道)。文件内部是分块的二进制容器,装的是 `BinXML` 编码的记录 —— 并非纯文本。读取它需要使用事件查看器、`wevtutil`、`Get-WinEvent`,或第三方解析器。

## evtx 文件的位置

在所有受支持的 Windows 版本(从 Vista 到 Windows 11 / Server 2025)上,标准路径都是:

```text
C:\Windows\System32\winevt\Logs\
```

每个 `.evtx` 文件映射到一个事件通道。下面这些是你一定会看到的默认通道:

- `Security.evtx` —— 登录、特权使用、审计策略变更。多数案件中取证价值最高。
- `System.evtx` —— 驱动、服务、内核级错误。
- `Application.evtx` —— 应用层错误与信息性事件。
- `Setup.evtx` —— 安装记录。
- `ForwardedEvents.evtx` —— 通过 Windows 事件转发(WEF)从其他主机收集来的事件。

各应用专属通道存放在同一目录下,文件名中以 `%4` 替代路径分隔符:

- `Microsoft-Windows-Sysmon%4Operational.evtx` —— Sysmon 进程、网络与文件事件(在已安装时)。
- `Microsoft-Windows-PowerShell%4Operational.evtx` —— PowerShell 脚本块与模块日志。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` —— 计划任务的创建与执行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` —— RDP 会话生命周期。

发生轮换的通道会在同一目录下生成带时间戳的归档文件(`Security.evtx`、`Archive-Security-2026-05-23-…evtx`)。Windows 运行期间,活动文件由 EventLog 服务以独占方式保持打开。

## evtx 文件的内部结构

文件是一个二进制容器,而非纯文本。前 4 KB 是文件头(魔数为 `ElfFile\0`),其后是一连串 64 KB 的**块(chunk)**。每个块都有自己的块头(`ElfChnk`)、一张其中出现的 XML **模板**索引表,以及一段按 ID 引用这些模板的记录流。解析器会把记录级别的数值代入模板的占位符,从而重构出每一条事件 —— 这正是 `.evtx` 在磁盘上比纯字面量 XML 更紧凑的原因。

解码之后,每条记录都是一份分为两部分的 XML 文档:

- `<System>` —— 提供者名称、通道、Event ID、级别(1 Critical → 5 Verbose)、计算机名、安全上下文,以及 UTC 写入时间戳。
- `<EventData>` —— 提供者特定的参数:登录事件中的目标账号、进程创建事件中的镜像路径、被审计写入的注册表键等等。

仅凭 Event ID 一般不足以分诊,取证信号藏在 `<EventData>` 里。如需深入了解格式机制 —— 块结构、BinXML、模板、脏块恢复 —— 请参见 [EVTX 文件格式内幕](/zh/blog/evtx-file-format-chunks)。

## evtx 与 evt:为什么换格式

旧版 `.evt` 格式在 XP 与 Server 2003 上沿用至生命周期结束,新格式要解决的是它的三个硬伤:

- **固定大小的字符串。**`.evt` 的记录里携带的是消息表引用而非完整消息;一旦源 DLL 缺失或被升级,渲染时的字符串拼接就会失败。
- **缺乏结构化查询。**过滤必须线性读取并解析每一条记录。
- **每个文件只能容纳一个通道。**自定义应用日志只能各自发明非标准格式。

`.evtx`(Vista,2007)引入了 BinXML 记录、可任意嵌套的按通道分文件方案,通过 `wevtutil qe` 与 `Get-WinEvent -FilterHashtable` 提供 XPath 风格的过滤,以及一种可在写入中途存活的分块布局。代价是与旧格式彻底不兼容 —— `.evt` 与 `.evtx` 不可互换,在现代 Windows 上唯一仍能读取 `.evt` 的内置工具,是 `wevtutil` 加上其传统标志(且只能用于导出为 `.evtx`)。

## 如何打开 evtx 文件

下面五种常见路径,大致按使用门槛由低到高排列:

1. **在浏览器里打开,无需安装** —— 把文件拖到本站首页的解析器上。它在 Web Worker 中运行编译为 WebAssembly 的 Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate。任何数据都不会离开你的机器。适合不想搭建取证虚拟机的临时分诊。
2. **事件查看器(`eventvwr.msc`)** —— Windows 内置 GUI。打开事件查看器 → 操作 → 打开保存的日志… → 选择 `.evtx`。浏览很方便,大规模过滤偏弱。
3. **`wevtutil` / `Get-WinEvent`** —— 命令行与 PowerShell,均随 Windows 自带。`wevtutil qe path\to\file.evtx /f:text /lf:true` 会输出每一条记录;`Get-WinEvent -Path` 返回的是可继续通过 `Where-Object` 管道处理的对象。
4. **EvtxECmd** —— Eric Zimmerman 出品的解析器。通过 .NET 跨平台运行,速度快,可将每条记录连同完整 `<EventData>` 拍平为 CSV 中的一行。
5. **`python-evtx`** —— 纯 Python 实现,易于脚本化。比 Rust crate 慢,但在已有 Python 工具链时非常有用。

如需逐一查看每种方法对应的实际命令,请参阅 [如何打开 evtx 文件](/zh/blog/how-to-open-an-evtx-file)。

## 真实场景中你会在哪里遇到 evtx

- **应急响应。**作为分诊的一部分,从受害主机上提取出来。关心哪些通道取决于线索 —— 登录与特权滥用看 `Security`,进程树看 `Sysmon`,脚本块内容看 `PowerShell`。
- **合规审计。**审计方会要求在限定窗口内提供 `Security.evtx`,以核实登录与策略变更历史。
- **应用程序排错。**`Application.evtx` 加上各厂商通道,常常承载着应用自身日志里没有的崩溃与错误上下文。
- **威胁狩猎。**针对归档 `.evtx`(或转发到 SIEM 的实时通道)的长尾规则,能够捕捉到非工作时间 RDP 或服务账号 `LogonType` 漂移这类慢节奏的攻击模式。

最有用的单一切入点就是 Event ID。要看一份在真实 SOC 中确实能立住脚的精简清单 —— [4624 登录成功](/zh/blog/understanding-event-id-4624)、[4625 登录失败](/zh/blog/detecting-4625-brute-force)、[1102 日志被清空](/zh/blog/event-id-1102-cleared-log)、[4104 PowerShell 脚本块](/zh/blog/powershell-4104-scriptblock)、[7045 服务安装](/zh/blog/service-creation-event-id-7045)、[Sysmon 1 进程创建](/zh/blog/sysmon-event-id-1-process-create) —— 请参阅 [从这里开始的导览](/zh/blog/welcome)。
