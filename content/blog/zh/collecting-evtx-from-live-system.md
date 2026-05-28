---
title: "如何从运行中的 Windows 主机收集 .evtx 日志（4 种方法）"
description: "从一台运行中的 Windows 主机取出 .evtx 的四种方式：wevtutil、FTK Imager、KAPE 与原始 NTFS。附上每种方式的证据链取舍以及你实际会运行的命令。"
date: "2026-05-17"
howto:
  name: "如何从运行中的 Windows 主机收集 .evtx 日志"
  steps:
    - name: "用 wevtutil 导出"
      text: "以管理员身份执行 wevtutil epl Security C:\\triage\\Security.evtx，在不触碰实时文件的前提下封存活动 Security 通道的一份可携副本。"
    - name: "用 FTK Imager 获取"
      text: "打开 FTK Imager，Add Evidence Item，导航到 \\Windows\\System32\\winevt\\Logs\\，选中通道文件（包括归档的 *.evtx）并 Export Files。FTK 直接读取 NTFS，绕过 EventLog 服务的文件锁。"
    - name: "用 KAPE 批量收集"
      text: "运行 kape.exe --tsource C: --target EventLogs --tdest C:\\triage 一次性取出 winevt\\Logs\\ 下的所有 .evtx，并带上证据链元数据。配合 WindowsEventLogs 模块可在收集时就完成解析。"
    - name: "原始 NTFS 读取"
      text: "怀疑被篡改时，使用 RawCopy 或 tsk_recover 在文件系统层之下打开卷（\\\\.\\PhysicalDriveN 或 \\\\.\\C:），从 MFT 按字节读取每个 .evtx。EventLog 服务无法阻断这条路径。"
---

事件日志任务的第一道难关不是解析。是在不被 EventLog 服务打手的前提下把文件从主机上取出来。一台运行中的 Windows 上，该服务对 `C:\Windows\System32\winevt\Logs\` 下的活动 [`.evtx` 文件](/zh/blog/what-is-an-evtx-file) 持有打开句柄，因此一个朴素的 `copy` 会返回共享违规错误。我遇到过的几乎所有情况，下面这四种方法都能覆盖。

## wevtutil 与 Get-WinEvent：内置、最快

最省力的路径用的是 Microsoft 文档化的 API：

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

这会生成一个已封存的 `.evtx`，包含通道中当前的所有记录。无需第三方工具，需要管理员 shell。要大声说出来的注意点：`epl` 只抓取活动日志。同目录下被轮转出去的 `Archive-Security-*.evtx` 文件被留下。如果近期发生过轮转、你想要的记录在归档里，这种方法会漏掉。

PowerShell 则给出已解析的记录：

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

它给的是 CSV，不是 `.evtx`。在主机上做临时分诊很方便。对于[块级恢复、脏块检查或从未分配空间雕刻](/zh/blog/evtx-file-format-chunks) 则没用，因为你已经丢掉了二进制保真度。

## FTK Imager：NTFS 级获取

当你要的是文件而不是记录时，FTK Imager 是首选。把活动驱动器作为证据添加（物理驱动器或逻辑驱动器），定位到 `\Windows\System32\winevt\Logs\`，右键点击通道文件并 Export Files。FTK 直接读取底层 NTFS 结构，绕过 EventLog 服务持有的文件系统锁。它还会捕获 `wevtutil epl` 跳过的 `Archive-*.evtx`。

取舍：FTK 读取的文件可能正在被写入。活动通道的尾部块可能是脏的。多数解析器能优雅处理（包括[本站的浏览器解析器](/zh/blog/how-to-open-an-evtx-file)），但在写进报告之前请先在工作台上验证。对应的 [USN journal](https://www.usnparser.com) 项在你怀疑获取期间 EventLog 服务做了不标准的事情时，是一份有用的佐证。

## KAPE：以 IR 速度做批量收集

当任务涉及多台主机时，Kroll Artifact Parser and Extractor 一小时内就能回本。

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

`EventLogs` target 会扫掉 `winevt\Logs\` 下的所有 `.evtx` 以及相关的 ETW 文件。配合 `!EZParser` 或 `WindowsEventLogs` 模块，KAPE 在收集结束时还会对收集内容跑一遍 EvtxECmd，在原始证据旁边再给你一份解析后的 CSV。顺手用 `RegistryHives` 与 `FileSystem` target 也能把你反正都想要的 [registry](https://www.registryparser.com)、[MFT](https://www.mftparser.com)、[USN journal](https://www.usnparser.com)、[prefetch](https://www.prefetchparser.com) 数据一并拿走。

KAPE 的输出附带 copy log 元数据。这对证据链的重要性，比人们普遍认知的要高。

## 原始 NTFS 读取：怀疑被篡改时

要最大保真度，就降到文件系统层之下。Sleuth Kit 的 `tsk_recover` 与 `icat`，或者 Eric Zimmerman 的 `RawCopy.exe`，通过 `\\.\PhysicalDriveN` 或 `\\.\C:` 打开卷，沿 MFT 行走，按字节输出文件内容。EventLog 服务无法阻拦，因为读取不走 Win32 文件 API。

当 rootkit 在范围内、当你有理由认为内核过滤驱动正在拦截 `\winevt\Logs\` 的读取，或者你就是不信任运行中的操作系统时，使用这种方式。结果应与同一时刻采集的 [RAM dump](https://www.ramparser.com) 搭配。事件日志服务会在内存中缓存近期记录，篡改发生前几分钟拍下的快照，有时还包含从未落到磁盘的记录。

## 何时选哪种

- 单台主机，有管理员权限，有一小时：对每个重要通道执行 `wevtutil epl`，把目录打包，完事。
- 已经有磁盘镜像：对镜像跑 FTK Imager 或 `tsk_recover`。比在活动主机上更快，也无需与 SOC 协调。
- 多台主机、真正的 IR 任务：KAPE。在吞吐量上没有别的能与之相比。
- 怀疑实时篡改或 rootkit：在隔离主机网络后，对卷执行 RawCopy 或 TSK。

无论选择哪种，都要写下来。解析后的 CSV 完全不说明出处。案件笔记里写上 `KAPE 1.3.0.2 EventLogs target, hash file attached` 这一行，就是证据物与个人意见之间的区别。

## 延伸阅读

- [KAPE 文档](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)
