---
title: "在 Security.evtx 中检测横向移动"
description: "真实对手工具如何在 Windows 环境中跨主机移动，以及在 Security.evtx 中能抓住 PsExec、Impacket 与 WMIExec 的精确 Event ID 组合。"
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

横向移动是大多数入侵从"他们站住了脚"到"他们控住了域"的转折点，也是 Windows 日志最有用、同时最容易误导人的地方。你需要的事件都在 `Security.evtx` 与 `System.evtx` 里。孤立地读它们，哪里都到不了。按正确的搭配、加上正确的跨主机关联去读，才是一条有用的时间线与一堆 `4624` 之间的差别。

这是调查中我停止滚动、开始按 `LogonId` 做 grep 的部分。

## 骨架：攻击者移动时发生了什么

横向移动没有通用的模式，但有一个通用的*形态*：

1. 攻击者从主机 A 向主机 B 认证，要么使用当前用户的令牌（pass-the-hash、pass-the-ticket 或被盗的 Kerberos TGT/TGS），要么使用另一个账户的明文凭据。
2. 主机 B 上的某个东西执行了他们的载荷：一个服务、一项计划任务、一次 WMI 进程创建、一个远程 PowerShell 会话或一次 DCOM 调用。
3. 他们再出去取工具、取秘密，或者跳下一台。

每一步都留下事件。问题是你是否在看对的事件，以及工具链是否被埋点。

## 4624 LogonType 3 是正门

成功的网络登录（`EventID=4624` 且 `LogonType=3`）是日志里最常见的横向移动原语，同时也是 Windows 产生的最嘈杂的事件。500 席办公室里的一台文件服务器每天会产生几万条合法的这类事件。仅按 `LogonType=3` 过滤，你哪里都到不了。

能把你带到某处的：

- 事件数据中的 `IpAddress` 与 `WorkstationName`。异常聚集在这里。凌晨 02:14 UTC，一台工作站从不同子网登录到一台服务器，这不是没什么。
- `AuthenticationPackageName` 与 `LogonProcessName`。Kerberos 环境下、加入域的主机之间的 NTLM 登录（`NTLM` / `NtLmSsp`）默认就该可疑。一个干净的 Kerberos 环境，域内认证应当只用 Kerberos，NTLM 仅作为非 DNS 名访问和遗留的回退。
- `TargetUserName` 的模式。服务账户做交互登录是红旗。域管理员账户登录到工作站是红旗。

你要的支点：把每一条值得关注的 `4624 Type 3` 与同一 `TargetLogonId` 上对应的 `4672`（特殊特权）配对。如果这次登录获得了管理员特权，你就有了一个凭据滥用的候选。如果没有，攻击者在用更低权限的令牌操作，你有时间。

## 4648 是大多数防御者使用不够的事件

`4648`（"使用显式凭据尝试了一次登录"）在以账户 A 运行的进程为账户 B 调用凭据去做某事时产生。这是你做归因要的事件。当 `mimikatz` 或 `Rubeus` 注入了一张票据，操作者执行 `net use \\TARGET /user:CORP\admin <pass>`，你会在源主机上看到一条 `4648`，同时展示两边账户和目标。

要看的字段：

- `SubjectUserName` / `SubjectLogonId` —— 谁发起的。
- `TargetUserName` / `TargetServerName` —— 用谁的凭据、对谁。
- `ProcessName` —— 哪个二进制做了这次调用。`cmd.exe`、`powershell.exe`、`wmic.exe`、`psexec.exe`、`wmiprvse.exe`（基于 WMI 的执行），以及越来越多的 `pwsh.exe` 是常见嫌疑对象。

`4648` 是被入侵主机与下一跳之间的连接。如果你有可疑主机，先从它的 Security 日志里把 `4648` 转出来。它会按时间顺序、在同一处告诉你攻击者持有哪些凭据、试图把它们用到哪里。

## 4672 与特权的故事

`4672` 紧跟在 `4624` 之后，对任何最终获得至少一个敏感特权（`SeDebugPrivilege`、`SeTcbPrivilege`、`SeBackupPrivilege` 等）的登录都会产生。`Administrators`、`Domain Admins` 成员或任何具有令牌提升特权的账户的每一次登录都会生成它。

把它视作一个标签，而不是发现。有用的查询是"给我看每一条 `4672`，60 秒内被来自非 DC 源 IP 的 `4624 Type 3` 紧随其后"，这会浮现来自不该发出此类令牌的工作站的管理员令牌使用。没用的查询是"给我看每一条 `4672`"，那会返回每台服务器上的每一次服务启动。

## 4697 与 7045：作为远程执行的服务

PsExec、Impacket 的 `psexec.py` 与 `smbexec.py` 的工作方式，是把一个服务二进制写到目标的 `ADMIN$` 共享，通过服务控制管理器注册它、启动它，再拆掉。它会留下：

- 目标上的 `5145`，显示对 `\\target\ADMIN$` 的访问以及所写文件名（如果对象访问审计开启）。
- `System.evtx` 中的 `7045`，显示服务安装。服务二进制路径与服务名在事件数据中。PsExec 默认在 `%SystemRoot%` 中使用 `PSEXESVC`；Impacket 把两者都随机化，模式随版本变化，已有充分文档。
- 如果系统审计策略已设置，`Security.evtx` 中针对同一次服务安装的 `4697`。
- 来自操作者源工作站的 `4624 Type 3`。

签名是这个*组合*：来自异常来源的 `4624 Type 3`，紧接 `ADMIN$` 的 `5145`，再紧接一条二进制位于不该存在位置的服务的 `7045`。每条单独看都合理。但是在秒级、由同一个 `LogonId` 串起来的组合就不合理了。

`7045` 中值得留意的服务名：8 个随机小写字母（Impacket 默认）、`PSEXESVC`（PsExec 默认）、`WinExec` 或其变体，以及任何二进制路径位于 `C:\Windows\` 下、既未签名又不在系统正常服务集合里的服务。

## 5140 与 5145：SMB 共享访问细节

`5140` 记录共享被访问；`5145` 记录共享内被访问的文件名，*前提是*该共享开启了对象访问审计。多数环境因为噪声没开 `5145`。多数环境在事件发生时也希望自己开过。

对横向移动而言，值得关注的 `5145` 是来自异常来源、对 `ADMIN$`、`C$`、`IPC$`，以及任何 `SYSVOL`/`NETLOGON` 路径的访问。`psexec.py` 通过写入 `\\target\ADMIN$\<random>.exe` 放置服务二进制。`secretsdump.py` 读取 `\\target\C$\Windows\System32\config\SAM`（以及 SYSTEM、SECURITY）。每一条都是一个 `5145`，其 `RelativeTargetName` 应当醒目。

把 `5145` 与目标上的 [USN journal](https://www.usnparser.com) 搭配。日志中会有同一时间戳同一文件的 `FILE_CREATE`，给出文件确实落地的第二来源确认，以及一个可追查的 [MFT](https://www.mftparser.com) 记录引用。

## WMI 作为横向移动载体

基于 WMI 的远程执行（`wmic /node:... process call create`、Impacket 的 `wmiexec.py`、PowerShell 的 `Invoke-WmiMethod`）仅靠 Security.evtx 较难发现，因为它不安装服务。你能拿到：

- 目标上的 `4624 Type 3`。
- 目标上的一次进程创建，父进程为 `WmiPrvSE.exe`。若装了 Sysmon，这在 Sysmon `EventID=1` 中。若开启了命令行审计，`4688` 中也是同一画面。
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` 中显示消费者的 WMI 事件。

如果没装 Sysmon，基于 WMI 的横向移动在默认配置的事件日志里基本是隐形的。这是每一份配置基线都在拼命推 Sysmon 的原因之一。

## 跨主机关联

横向移动是图问题。主机 A 上一个指向主机 B 与账户 `corp\admin` 的 `4648` 是一条边。主机 B 上、来自主机 A 的 IP、`TargetUserName=admin` 的对应 `4624 Type 3` 是同一条边的另一端。DC 上由 `admin@CORP` 请求 `cifs/hostB` 票据的 `4769`（Kerberos 服务票据），是第三位证人。

实务中你想要全部：

- 源主机 `Security.evtx` 中的登录事件。
- 目标主机 `Security.evtx` 中的登录事件。
- 域控 `Security.evtx` 中的 TGT（`4768`）与 TGS（`4769`）事件。
- 任何 WEC 收集器中的转发事件，当某台主机本地日志被清时，有时是唯一完整的副本。

主机内部按 `LogonId` 串起，主机之间按时间戳 + 账户 + IP 串起。经典的 JPCERT/CC 论文对此有详细论述，是这一话题上最好的免费文档。

对能熬过日志清除的主机端工件，依靠 [Prefetch](https://www.prefetchparser.com) 提供攻击者工具执行的证据，依靠 [registry](https://www.registryparser.com) 的 `Services` 键追踪曾经安装又被移除的服务二进制，并依靠 [LNK files](https://www.lnkparser.com) 与 [jump lists](https://www.jumplistparser.com) 找操作者在动手会话里打开过的文件的证据。

## 延伸阅读

- JPCERT/CC 的 ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/)。参考文献，请读两遍。
- MITRE ATT&CK 的 [Lateral Movement 矩阵](https://attack.mitre.org/tactics/TA0008/) 及各技术的数据源映射。
- Impacket 的 [examples 目录](https://github.com/fortra/impacket/tree/master/examples)。如果你没读过 `psexec.py`、`wmiexec.py`、`smbexec.py` 在网络上到底做了什么，你的检测就是猜测。
