---
title: ".evtx 文件是什么？Windows 事件日志格式解读"
description: ".evtx 文件是二进制的 Windows 事件日志。它们存放在哪里、里面是什么、与 .evt 有何不同，以及如何打开。无需安装。"
date: "2026-05-24"
faq:
  - question: ".evtx 文件是什么？"
    answer: ".evtx 文件是随 Windows Vista 引入的二进制 Windows 事件日志格式。它存储由 EventLog 服务写入的系统、安全与应用程序事件。每台 Windows 主机在 C:\\Windows\\System32\\winevt\\Logs\\ 下都有几十个 .evtx 文件，每个通道一个。"
  - question: ".evtx 文件存放在 Windows 的哪里？"
    answer: "默认位置是 C:\\Windows\\System32\\winevt\\Logs\\。三个高流量文件是 Security.evtx、System.evtx 与 Application.evtx。按应用程序划分的通道在同一文件夹下，命名形如 Microsoft-Windows-Sysmon%4Operational.evtx。"
  - question: ".evtx 与 .evt 有什么区别？"
    answer: ".evt 是 Windows 在 XP 和 Server 2003 时代使用的旧二进制格式。.evtx 在 Windows Vista（2007 年）取代了它，采用基于块和 BinXML 的布局，支持更丰富的事件元数据、更大的日志，以及通过 wevtutil 和 Get-WinEvent 进行的结构化查询。两种格式不可互换。"
  - question: "如何打开 .evtx 文件？"
    answer: "Windows 内置工具：Event Viewer（eventvwr.msc）、命令行的 wevtutil 或 PowerShell 中的 Get-WinEvent。跨平台：本站基于浏览器的解析器（无需安装，无需上传），或者命令行的 evtxecmd。所有选项请参阅 how-to-open-an-evtx-file 一文。"
  - question: "在 macOS 或 Linux 上能打开 .evtx 文件吗？"
    answer: "可以。Windows 原生工具无法使用，但有多种跨平台解析器：本站基于浏览器的解析器（任何带现代浏览器的操作系统）、python-evtx、Rust 的 evtx crate，以及通过 .NET 运行的 evtxecmd。它们都不需要 Windows 主机。"
---

`.evtx` 文件是 Microsoft 在 2007 年随 Vista 发布的二进制 Windows 事件日志格式，用于替换更旧的 `.evt`。操作系统、驱动、服务或应用程序写入 Windows 事件日志的每一条事件，最终都会落到磁盘上的 `.evtx` 文件里。它们是每一次 Windows 调查的脊梁。如果你在 Windows 上做 DFIR，那你在这些文件里花的时间，将比在任何其他工件类别上都更多。

## 一句话

`.evtx` 文件由 Windows EventLog 服务写入 `C:\Windows\System32\winevt\Logs\`。一个**通道**对应一个文件（`Security.evtx`、`System.evtx`、`Application.evtx`，以及按应用程序划分的通道）。内部上，每个文件都是按块组织的二进制容器，记录采用 `BinXML` 编码。不是纯文本。读取方法是 Event Viewer、`wevtutil`、`Get-WinEvent`，或第三方解析器。

## .evtx 文件存放位置

在所有受支持的 Windows 版本（Vista 到 Windows 11 和 Server 2025）上，标准位置：

```text
C:\Windows\System32\winevt\Logs\
```

每个 `.evtx` 文件对应一个事件通道。默认通道：

- `Security.evtx`。登录、特权使用、审计策略变更。多数案件中取证价值最高。
- `System.evtx`。驱动、服务、内核级错误。
- `Application.evtx`。应用程序级错误与信息事件。
- `Setup.evtx`。安装记录。
- `ForwardedEvents.evtx`。通过 Windows Event Forwarding（WEF）从其他主机收集的事件。

按应用程序划分的通道存放在同一文件夹，路径分隔符以 `%4` 表示：

- `Microsoft-Windows-Sysmon%4Operational.evtx`。Sysmon 的进程、网络、文件事件（已安装时）。
- `Microsoft-Windows-PowerShell%4Operational.evtx`。PowerShell scriptblock 与模块日志。
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`。计划任务的创建与运行。
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`。RDP 会话生命周期。

发生轮转的通道会在同一文件夹生成带时间戳的归档文件（`Security.evtx`、`Archive-Security-2026-05-23-...evtx`）。Windows 运行期间，活动文件由 EventLog 服务持有打开句柄。这正是为什么会有一篇[关于如何在运行中的主机上获取这些文件的收集文章](/zh/blog/collecting-evtx-from-live-system)。

## .evtx 文件里有什么

文件是二进制容器，不是纯文本。一个 4 KB 的文件头（魔数 `ElfFile\0`）后面跟随一连串 64 KB 的**块**。每个块有自己的块头（`ElfChnk`）、其中出现的 XML **模板**表，以及通过 ID 引用这些模板的记录流。解析器通过把记录级的值代入模板的占位符来重建每条事件。这正是 `.evtx` 在磁盘上比字面 XML 更紧凑的原因。

解码后，每条记录是一个由两部分组成的 XML 文档：

- `<System>`。提供程序名、通道、Event ID、级别（1 严重到 5 详细）、计算机名、安全上下文，以及 UTC 写入时间戳。
- `<EventData>`。提供程序自定义的参数：登录事件中的目标账号、进程创建中的镜像路径、被审计写入的注册表键，等等。

仅凭 Event ID 通常不足以做分诊。取证信号住在 `<EventData>` 里。关于该格式的细节（块、BinXML、模板、dirty chunk 恢复），请参阅[块级深入解读](/zh/blog/evtx-file-format-chunks)。

## .evtx 与 .evt：为什么格式发生了变化

Windows 在 XP 与 Server 2003 时代使用的旧 `.evt` 格式存在三大新格式要解决的硬限制：

- **固定大小的字符串。** `.evt` 记录承载的是消息表引用而非完整消息。当源 DLL 缺失或升级时，渲染时的连接会出问题。
- **缺乏结构化查询。** 过滤必须线性读取并解析每一条记录。
- **每个文件一个通道。** 自定义应用日志需要各自的非标准格式。

`.evtx`（Vista，2007）引入了 BinXML 记录、按通道存放并支持任意嵌套的文件、通过 `wevtutil qe` 与 `Get-WinEvent -FilterHashtable` 的 XPath 风格过滤，以及能容忍部分写入的块式布局。代价是与旧格式的完全不兼容。`.evt` 与 `.evtx` 不可互换，现代 Windows 中唯一能读取 `.evt` 的内置工具，是带旧式标志的 `wevtutil`（且仅用于导出为 `.evtx`）。

## 如何打开 .evtx 文件

五条常见路径，大致按摩擦从小到大：

1. **在浏览器里打开，无需安装。** 把文件拖到本站首页的解析器上。它在 Web Worker 中运行编译为 WebAssembly 的 Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate。没有任何东西离开你的机器。适合不想启动取证虚拟机时的临时分诊。
2. **Event Viewer（`eventvwr.msc`）**。Windows 内置 GUI。**操作 / 打开已保存的日志 / 选择 .evtx**。适合浏览，规模化过滤较弱。
3. **`wevtutil` / `Get-WinEvent`**。命令行与 PowerShell，二者都随 Windows 提供。`wevtutil qe path\to\file.evtx /f:text /lf:true` 转储每条记录。`Get-WinEvent -Path` 返回可以管道到 `Where-Object` 的对象。
4. **EvtxECmd**。Eric Zimmerman 的解析器。通过 .NET 跨平台、速度快，每条记录生成一行 CSV，并把 `<EventData>` 展平。
5. **`python-evtx`**。纯 Python，易于脚本化。比 Rust crate 慢，但在你已经用 Python 工具链时很有用。

每种方式的完整演练与实际命令，参见[如何打开 .evtx 文件](/zh/blog/how-to-open-an-evtx-file)。

## 在野外遇到 .evtx 的场合

- **应急响应。** 作为分诊的一部分从被入侵的主机上提取。感兴趣的通道取决于线索：登录与特权滥用看 `Security`，进程树看 `Sysmon`，scriptblock 内容看 `PowerShell`。配合 [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[AmCache](https://www.amcacheparser.com) 与 [prefetch](https://www.prefetchparser.com) 来印证执行。
- **合规审计。** 审计员请求特定时间窗的 `Security.evtx` 来核验登录与策略变更历史。
- **应用调试。** `Application.evtx` 以及按厂商划分的通道，往往包含应用自身日志中没有的崩溃与错误上下文。
- **威胁狩猎。** 针对归档的 `.evtx`（或转发实时通道的 SIEM）的长期规则，可以捕获缓慢推进的模式，比如深夜 RDP，或服务账户的 `LogonType` 漂移。

最有用的支点是 Event ID。真实 SOC 中物有所值的简短清单（[4624](/zh/blog/understanding-event-id-4624)、[4625](/zh/blog/detecting-4625-brute-force)、[1102](/zh/blog/event-id-1102-cleared-log)、[4104](/zh/blog/powershell-4104-scriptblock)、[7045](/zh/blog/service-creation-event-id-7045)、[Sysmon 1](/zh/blog/sysmon-event-id-1-process-create)），请参阅[起步导航](/zh/blog/welcome)。

## 延伸阅读

- [Microsoft 文档：Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [libevtx EVTX 格式规范](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx（Rust 解析器）](https://github.com/omerbenamram/evtx)
