---
title: "Event ID 4688 解读：用于 DFIR 的 Windows 进程创建审计"
description: "在启用命令行审计的前提下，4688 是基础操作系统的进程创建记录。本文讲清它里面是什么、与 Sysmon 1 的区别，以及物有所值的分诊模式。"
date: "2026-05-24"
---

Event ID **4688**「已创建一个新进程」在每次进程被启动时触发于 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。它是基础操作系统能给到的、最接近 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create) 所提供遥测的事件，而在未部署 Sysmon 的主机上，它是你唯一的 `CommandLine` 来源。在配置得当的资产上，每一次进程创建都是这条记录之一。读得好，你无需打开 EDR 就能回答"什么跑过了"。

## 打开它，因为默认是半盲的

默认情况下 4688 已启用，但 `CommandLine` **不**会被捕获。没有命令行，记录只告诉你二进制路径、PID、父 PID，对参数一无所知。对分诊几乎无用。`powershell.exe` 没问题。`powershell.exe -enc SQBFAFgA...` 就有问题。

修复方法是一项组策略：

*计算机配置 / 管理模板 / 系统 / 审核进程创建 / 在进程创建事件中包含命令行*

或对应的注册表：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`。一经设置，每一条 4688 都会带上完整的 `CommandLine` 字段。代价是日志体量。收益是二进制名字之下整个调查面。打开它。

底层的审计策略也要开：`auditpol /set /subcategory:"Process Creation" /success:enable`。许多主机策略开着，但命令行没开。两个都要检查。

## 记录的内容

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

驱动每次调查的字段：

- `CommandLine`。完整 argv（GPO 开启时）。
- `NewProcessName`。二进制路径。与 `CommandLine` 一起就是完整执行。
- `ParentProcessName`。调用进程。Office 到 cmd、浏览器到 powershell、services 到 unsigned.exe 是经典链条。
- `SubjectUserName` 与 `SubjectLogonId`。谁启动了它，在哪个会话下。`SubjectLogonId` 可回到创建该会话的 [4624](/zh/blog/understanding-event-id-4624)。
- `TokenElevationType`。`%%1936` Default（无提升），`%%1937` Full（UAC 同意），`%%1938` Limited（被过滤）。非管理员会话中的 `1937` 是值得仔细看的特权切换。
- `MandatoryLabel`。完整性级别 SID。`S-1-16-12288` 是 High（已提升），`8192` Medium，`16384` System。

## 4688 与 Sysmon 1

有重叠。不是同一个东西。

| 字段 | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | 是（GPO 开启） | 是 |
| Image / NewProcessName | 是 | 是 |
| 父进程镜像 | 是（路径） | 是（路径 + CommandLine） |
| ParentCommandLine | 否 | 是 |
| 镜像哈希（SHA/MD5/IMPHASH） | 否 | 是 |
| ProcessGuid（跨主机稳定） | 否（PID 复用） | 是 |
| 用户 SID + 名字 | 是 | 是 |
| Logon ID | 是 | 是 |
| CurrentDirectory | 否 | 是 |
| 完整性级别 | 是 | 是 |
| 无需安装即可获得 | 是 | 需要 Sysmon |

两者都在时，[Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 是更丰富的记录。`ParentCommandLine`、镜像哈希、用于稳定父子链的 `ProcessGuid`。只有 4688 时，你用 PID 串链，而 Windows 会复用 PID，因此长时间线里可能有错误匹配。务必用时间戳交叉核对父子关系。两个都没有时（无 Sysmon、无命令行审计），[AmCache](https://www.amcacheparser.com)、[prefetch](https://www.prefetchparser.com)、[USN journal](https://www.usnparser.com) 是次优的执行证据。

## 物有所值的模式

1. **Office 到 Shell**。`ParentProcessName` 以 `winword.exe`、`excel.exe`、`outlook.exe`、`powerpnt.exe` 或 `mshta.exe` 结尾，`NewProcessName` 为 `cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe` 或 `regsvr32.exe`。文档应用产生 shell 是经典宏/钓鱼链。
2. **编码的 PowerShell**。`NewProcessName` 以 `powershell.exe` 结尾，`CommandLine` 匹配 `-enc`、`-encodedcommand`、`-e `（单字母）、`frombase64string`、`iex ` 或 `invoke-expression`。解码载荷。交叉检查同一会话上的 [4104 scriptblock 记录](/zh/blog/powershell-4104-scriptblock)。
3. **从用户可写路径运行的 LOLBin**。签名的 Microsoft 二进制（`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`、`msbuild`、`csc`）从 `C:\Users\`、`%TEMP%` 或 `C:\ProgramData\` 启动。这些位置的合法使用很少。
4. **svchost 孤儿**。`svchost.exe` 的 `ParentProcessName` 不是 `services.exe`（早期启动则可能是 `wininit.exe`）。真正的 `svchost` 永远由 `services.exe` 产生。冒充者很显眼。
5. **改名的二进制**。`NewProcessName` 以中性字眼（`update.exe`、`svc.exe`、`data.exe`）结尾，且位于非标准路径。可用时配合 Sysmon 1 的 `OriginalFileName` 字段。该字段能抓住被改名的 PsExec、Mimikatz、Impacket 二进制，绕开简单的按名检测。

## Sigma：Office 到 Shell

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Office add-ins running approved scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL 与 Splunk

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK 对应

4688 的大部分覆盖落在 T1059 Command and Scripting Interpreter 及其子技术下（.001 PowerShell、.003 Windows Command Shell、.005 Visual Basic、.007 JavaScript）。LOLBin 模式对应到 T1218 System Binary Proxy Execution（.005 Mshta、.010 Regsvr32、.011 Rundll32）。Office 到 Shell 的链路对应到 T1566.001 Phishing: Spearphishing Attachment 与 T1059 的组合。改名二进制的检测对应到 T1036.003 Masquerading: Rename System Utilities。

## 告警前先读的误报

- 软件更新代理合法地产生 shell：Chocolatey、WinGet、厂商 MSI 包装器。按 `SubjectUserSid`（LocalSystem）加上稳定的 `ParentProcessName` 模式加白，不要按用户账户。
- 漏洞扫描器与 EDR 产品产生的进程树看起来就像攻击者侦察：`net.exe`、`whoami.exe`、`systeminfo.exe`。给扫描器 IP 与主机打标签。
- Citrix 与 RDS 多会话主机上有合法的 `runas /netonly` 跨域访问链。请调查具体用户，不要看模式本身。
- 登录脚本（`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`）每次登录都触发，形成周期性链路。告警前先建立基线。

## 4688 没告诉你的事

没有文件哈希。没有 `ParentCommandLine`。没有 `ImageLoaded`（DLL 注入不是进程创建）。没有网络行为。要这些，你需要 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create)（更丰富的 4688）、Sysmon 7（image load）、Sysmon 3/22（network/DNS），以及 EDR 的行为遥测。4688 是进程可见性的下限。每台 Windows 主机都应当具备的最低限度。不能替代关键主机上的合格 EDR 加 Sysmon。

## 4688 在时间线中的位置

对于一台没有 Sysmon 的主机，一条典型的入侵后链路：

1. [4624](/zh/blog/understanding-event-id-4624)。初次登录，来自外部 IP 的 LogonType 3。
2. 又一条 4624。同一 `SubjectLogonId` 下的 LogonType 9（`runas /netonly`）。凭据转换。
3. **4688**。该会话下的 `powershell.exe -enc ...`。
4. [4104](/zh/blog/powershell-4104-scriptblock)。解码后的脚本主体，去抓第二阶段载荷。
5. **4688**。从 `%TEMP%` 运行的第二阶段二进制。
6. [7045](/zh/blog/service-creation-event-id-7045)。为持久化安装的服务。

六条记录就讲完整段故事。第 (3) 和 (5) 的 PID 通过 4688 的 `ProcessId` 与 `NewProcessId` 相连，但要按时间戳核实，因为 Windows 会复用 PID。Sysmon 在场时，`ProcessGuid` 链可替代这种脆弱的匹配。

## 延伸阅读

- [4688 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
