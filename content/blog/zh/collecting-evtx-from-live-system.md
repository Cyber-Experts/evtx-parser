---
title: "如何从运行中的 Windows 主机收集 .evtx 日志（4 种方法）"
description: "从在线 Windows 主机抓取 .evtx 的四种方式 —— wevtutil、FTK Imager、KAPE、原始 NTFS —— 各自的取证链权衡，以及实际用得上的命令。"
date: "2026-05-17"
howto:
  name: "如何从运行中的 Windows 系统收集 .evtx 日志"
  steps:
    - name: "用 wevtutil 导出"
      text: "以管理员身份运行 wevtutil epl Security C:\\triage\\Security.evtx，封装一份当前 Security 通道的可移植副本，不动正在使用的活动文件。"
    - name: "用 FTK Imager 取证"
      text: "打开 FTK Imager，Add Evidence Item → Physical or Logical Drive，定位到 \\Windows\\System32\\winevt\\Logs\\，选择通道文件（包括归档的 *.evtx）并 Export Files。FTK 直接读取 NTFS，绕过 EventLog 服务的文件锁。"
    - name: "用 KAPE 批量收集"
      text: "运行 kape.exe --tsource C: --target EventLogs --tdest C:\\triage，一次性拉取 winevt\\Logs\\ 下所有 .evtx 并附带取证链元数据。配合 WindowsEventLogs 模块可在收集时同步解析。"
    - name: "原始 NTFS 读取"
      text: "当怀疑被篡改时，用 RawCopy 或 tsk_recover 在文件系统层之下打开卷（\\\\.\\PhysicalDriveN 或 \\\\.\\C:），从 MFT 按字节读取每个 .evtx。EventLog 服务无法阻挡这条路径。"
---

事件日志调查的第一道难关不是解析,而是*把文件拿到手*。在运行中的 Windows 主机上,EventLog 服务对 `C:\Windows\System32\winevt\Logs\` 下活动的 [`.evtx` 文件](/zh/blog/what-is-an-evtx-file)持有打开的句柄,简单 `copy` 会失败。下面这四种方法基本覆盖所有场景。

## 内置方案:wevtutil / Get-WinEvent

最简单的方法是通过有文档支持的 API 导出记录(而不是文件):

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

这会生成一个封装好的 `.evtx`,其中包含日志中目前所有的记录。快速、无需第三方工具、以管理员身份运行。缺点是它只采集当前活动的 `.evtx`,不抓取已归档(轮转后)的文件。

PowerShell 等价命令:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` 返回的是解析后的记录而不是文件。适合快速分诊导 CSV,但失去了深度取证所需的二进制保真度 —— [块级恢复、脏块检查、雕刻(carving)](/zh/blog/evtx-file-format-chunks)都做不了。

## FTK Imager

要进行完整磁盘或文件系统级别的获取,FTK Imager 是行业标准。把在线磁盘作为证据加入(Physical Drive 或 Logical Drive),定位到 `\Windows\System32\winevt\Logs\`,右键通道文件,然后 Export Files。FTK 直接读取底层 NTFS 结构,绕过 EventLog 服务持有的文件系统锁。它还能导出 `wevtutil` 不会触及的归档 `*.evtx` 文件(那些文件名带时间戳的)。

代价是 FTK 读到的文件可能正在写入 —— 生成的 `.evtx` 末尾可能出现一个脏块。大多数解析器([包括本工具](/zh/blog/how-to-open-an-evtx-file))都能优雅处理,但值得验证。

## KAPE

对于规模化的应急响应,Kroll Artifact Parser and Extractor(KAPE)能在一次操作中自动收集所有取证相关文件:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

`EventLogs` target 会抓取 `winevt\Logs\` 下所有 `.evtx` 以及相关的事件跟踪文件。配合 `WindowsEventLogs` module 还能立刻执行解析,在原始文件旁边生成一份 CSV。任何涉及多台主机的 IR 任务都推荐使用。

## 原始 NTFS 读取

追求最高保真度 —— 怀疑文件系统 API 被劫持,或需要逐位获取时 —— 应在文件系统层之下读取卷。诸如 [The Sleuth Kit](https://www.sleuthkit.org/)(`tsk_recover`、`icat`)或 Eric Zimmerman 的 `RawCopy.exe` 通过 `\\.\PhysicalDriveN` 或 `\\.\C:` 打开卷,遍历 MFT,逐字节输出文件内容。EventLog 服务无法阻止这条路径,因为读取完全绕过了文件系统层。

## 什么场景用哪种

- **单机快速分诊,你已有管理员权限**:`wevtutil`。
- **完整取证获取,已经有磁盘镜像**:对镜像使用 FTK Imager 或 `tsk_recover`。
- **多台主机的 IR 任务**:KAPE。
- **怀疑 rootkit 或活跃篡改**:在主机网络隔离的前提下,对在线卷使用 RawCopy 或 TSK 走原始 NTFS。

无论选哪种,都要记录方法。证据链在事件报告里很重要 —— 一份解析后的 CSV 并不能说明它来自正在运行 EventLog 服务的在线主机,还是来自一份封装好的镜像。
