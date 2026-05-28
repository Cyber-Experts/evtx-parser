---
title: "PowerShell 日志记录：开启 module logging 和 script block logging 后你能得到什么"
description: "PowerShell module logging、script block logging、transcripts 和 AMSI buffers 之间的实际差异，以及真正开启有用项的 GPO 设置。"
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

任何值得担心的攻击者工具包在某个时刻都会运行 PowerShell。Cobalt Strike beacons 启动它。Empire 和 Covenant 建立在它之上。living-off-the-land 指南都从它开始。好消息是，自 PowerShell 5.0 起，Microsoft 提供了日志记录，正确配置后，可以捕获 PowerShell 执行的所有内容的字面文本，包括去混淆后的混淆 payload。坏消息是，"正确配置后"这句话承担了很多分量。我接触的大多数环境只开启了四个相关日志中的一个，而不是全部四个，而且通常不是最有用的那个。

这篇文章讲的是你实际能得到什么，值得开启什么，以及哪里有缺口。

## 四个日志，按有用性排序

PowerShell 写入 `Microsoft-Windows-PowerShell%4Operational.evtx`。重要的 event ID：

- `4104` script block logging。PowerShell 编译并执行的每个 script block 的字面文本。如果一个 block 被内置启发式标记为可疑，则以 Warning 严重性记录；否则以 Verbose 记录，默认关闭。这是你想要的事件。
- `4103` module logging。记录每个模块的 pipeline 执行，带参数绑定。比 `4104` 文字少，结构性更强。对"哪些 cmdlet 运行了"有用，但没有 script body。
- `4105` 和 `4106` pipeline started 和 pipeline stopped。对加括号有用，对内容无用。
- `400` / `403`（遗留，PowerShell 2.0 时代）engine state changes。取证历史事件。你仍然会在有人强制进行 PS 2.0 降级攻击的主机上看到这些。

如果你只能开启一个东西，请将 `4104` 开为 Verbose。其他都是补充。

## `4104` 实际捕获什么

`4104` 事件包含 PowerShell 编译时的 script block 的完整文本。从"PowerShell 编译时"得出两件事：

- 事件中的文本在大多数情况下是 *去混淆后* 的表示。如果操作员运行 `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`，你既会得到外层的 `iex` 调用（它本身就是一个 `4104`），还会得到内部解码后 script block 的 *第二个* `4104`，因为 PowerShell 必须编译该 block 才能运行它。这是 `4104` 日志最有价值的属性。
- 大型脚本使用事件数据中的 `MessageNumber` 和 `MessageTotal` 跨多个事件分割。一个 50 KB 的脚本变成一连串事件，你必须在分析前重新组装。大多数工具会这样做；有些不会。如果你的 parser 显示片段，检查它是否处理这个链。

`Path` 字段显示源文件（如果有）。空的 `Path` 加上完全内联的 script body 等于"这是通过网络或从内存中来的"，是寻找交互式操作员活动与计划脚本的最佳启发式。

`ScriptBlockId` 是一个 GUID。同一主机上同一 block 的重新运行通常重用 GUID（因为缓存），如果你有支持跨主机搜索的 SIEM，这便于找到"运行此代码的所有主机"。

## Module logging：`4103` 增加了什么

Module logging 比 script block logging 更老更嘈杂。它挂钩在 pipeline 执行层，所以对于已记录模块中的每个 cmdlet 调用，你会得到一个 `4103`，包含 cmdlet 名称、绑定的参数和 payload 字符串。

在现代 IR 中，`4103` 在三种情况下最有用：

- 攻击者使用了绑定有趣参数的 cmdlet（`Invoke-WebRequest -Uri ...`、`New-Object Net.Sockets.TcpClient ...`、`Get-WmiObject -Class Win32_ShadowCopy`）。`4104` 显示源；`4103` 显示变量展开后解析的参数值。
- 攻击者使用了 encoded commands。`powershell -enc <base64>` 在相应的 `4104` 发出之前，生成一个 payload 中带有解码文本的 `4103`。
- 攻击者禁用了 `4104`（如果有本地 admin 权限，通过编辑注册表可以实现）。`4103` 位于单独的日志路径下，有时在 `4104` 被静音时仍保持开启。

注意点：module logging 仅记录明确启用的模块。GPO 设置需要 `*`（记录所有）或模块名称列表。`*` 是任何认真对待日志记录的环境的答案。你会听到的"性能影响"反对意见对于非常重的 PowerShell 工作负载是真实的，对于普通的车队桌面是错误的。

## Transcripts 不是 script block logs

有一个单独的设置叫 "Turn on PowerShell Transcription"，将每个会话的输入和输出写入配置目录下的文本文件。这与 `4104` 不是同一回事，人们经常混淆它们。

重要的差异：

- Transcripts 包括 cmdlet *输出*。`4104` 不包括。如果你想知道 `Get-ADUser` 实际返回了什么，transcripts 就是它。
- Transcripts 是文本文件。在受损主机上它们很容易删除和修改。`4104` 事件进入一个 EVTX 通道，需要日志清除或更糟才能干扰。
- Transcripts 默认到用户的 documents 文件夹，除非设置了 `OutputDirectory`。如果你不将 `OutputDirectory` 设为只写网络共享，transcripts 不是证据；它们是礼貌。

将 transcripts 开启并将 `OutputDirectory` 指向一个 UNC 路径，写入用户在那里有只写 NTFS 权限（无读取、无删除）。这给你 `4104` 没有的 cmdlet 输出痕迹，而不给攻击者修改或删除自己历史记录的选项。

## AMSI 和 buffer 角度

AMSI（Antimalware Scan Interface）是 runtime hook，允许 Defender 和其他 AV 产品在执行前检查 PowerShell 脚本内容。对取证的两个后果：

- 即使攻击者禁用了 PowerShell 日志记录，AMSI 仍然在执行前看到脚本内容，如果内容匹配签名，Defender 将在 `Microsoft-Windows-Windows Defender%4Operational.evtx` 中记录 `1116` 或 `1117`。Defender 事件在威胁检测记录中部分包含脚本文本。在 script block logging 关闭的主机上，这有时是恶意代码唯一存在的地方。
- 攻击者使用的"AMSI bypass"技术（在内存中给 `amsi.dll!AmsiScanBuffer` 打补丁、提供伪造的 `AmsiContext`、AMSI provider 的 COM 劫持）本身通常会为 bypass 代码生成 `4104` 事件，*在* bypass 生效 *之前*。Bypass 无法追溯关闭日志记录。所以即使在操作员成功使 AMSI 失效的主机上，他们做这件事的那一刻也被记录下来。

在 `4104` 中寻找的模式：包含字符串 `amsiInitFailed`、`AmsiScanBuffer`、`VirtualProtect` 或 `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` 的小 script blocks。这些是所有常见 bypass 的签名。

## 开启日志记录

GPO 设置位于 `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`。你想启用的三个：

- "Turn on PowerShell Script Block Logging" 启用。如果你想要加括号的 `4105`/`4106` 事件，勾选 "Log script block invocation start / stop events"；默认关闭，通常不值得这个数量。
- "Turn on Module Logging" 启用。模块名称：`*`。
- "Turn on PowerShell Transcription" 启用。`OutputDirectory`：UNC 路径。`Include invocation headers`：勾选。

如果你在 GPO 之外设置它们，对应的注册表路径：

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

应用到包含你必须调查的机器的 OU。在任何严肃的组织中，那就是"所有 OU"。

## 调查期间这看起来像什么

script block logging 开启的入侵按顺序告诉你：

1. 第一个带有非平凡 script block 来自非标准父进程的 `4104`。首次执行时间。
2. 当 loader 自我解包时的 `4104` 链。每层混淆被剥离并记录。
3. C2 框架的 runtime cmdlet（Invoke-Beacon、Invoke-Mimi、`Invoke-Kerberoast`，所有常见的攻击性 cmdlet 名称及其重命名变体）。
4. 交互式操作员的 hands-on-keyboard 命令。它们读起来像录制的 shell 会话，因为它们就是。

与 [Prefetch](https://www.prefetchparser.com) 交叉引用以查找 `powershell.exe` 何时运行，[LNK 文件](https://www.lnkparser.com)查找操作员打开的文件，[AmCache](https://www.amcacheparser.com)查找 PowerShell 二进制文件本身的 hash（它有时被重命名），以及[注册表](https://www.registryparser.com)查看 GPO 状态以确认在你正在阅读的事件时间日志记录确实开启。

script block logging 关闭的入侵几乎不告诉你关于 PowerShell 的任何信息，但告诉你很多关于你的检测态势的信息。先修复那个。

## 延伸阅读

- Microsoft 的 [PowerShell logging 文档](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)。官方参考。
- FireEye / Mandiant 的 [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility) 帖子。老但仍是最清晰的现场视角写作。
- Daniel Bohannon 的 [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) 项目。补充 `4104` 分析的去混淆工具包。
