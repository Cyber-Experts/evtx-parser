---
title: "Sysmon Event ID 1 详解:面向 DFIR 分诊的进程创建"
description: "Sysmon 的事件 1 是 Windows 能产生的最丰富的进程创建记录。这里讲它包含什么,以及如何快速分诊。"
date: "2026-05-17"
---

Sysmon 是 Microsoft 出的免费工具,补充 [Windows 事件日志](/zh/blog/what-is-an-evtx-file)中基础 OS 无法以可用形式捕获的遥测。它的事件 ID 1 —— `ProcessCreate` —— 是 IR playbook 中引用最多的 Sysmon 记录。如果你只能从主机抽取一个 Sysmon 通道,就是这一个。

## 它在哪里以及捕获什么

Sysmon 写入通道 `Microsoft-Windows-Sysmon/Operational`(磁盘上:`Microsoft-Windows-Sysmon%4Operational.evtx`)。一条 ProcessCreate 记录包含:

```xml
<Data Name="UtcTime">2026-05-17 14:02:11.123</Data>
<Data Name="ProcessGuid">{...}</Data>
<Data Name="ProcessId">7842</Data>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="CommandLine">powershell -enc SQBFAFgA...</Data>
<Data Name="CurrentDirectory">C:\Users\alice\</Data>
<Data Name="User">CORP\alice</Data>
<Data Name="LogonId">0x3e7</Data>
<Data Name="Hashes">SHA256=...</Data>
<Data Name="ParentProcessGuid">{...}</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\winword.exe</Data>
<Data Name="ParentCommandLine">"winword.exe" /n /dde</Data>
```

驱动调查的字段:`CommandLine`(完整 argv,而不仅是二进制名)、`Image` + `Hashes`(实际运行的二进制,哈希可用于 VT / Hybrid Analysis),以及 `Parent*` 集合(调用进程 —— 寻找宏与 LOLBin 链的关键)。

## 三个透视搞定分诊

拿到一份分诊 Sysmon 文件,三个查询覆盖大多数情况:

1. **可疑父进程**:筛 `ParentImage` 以 `winword.exe`、`excel.exe`、`outlook.exe`、`mshta.exe` 或浏览器结尾,`Image` 是 shell(`cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe`)。文档类应用拉起 shell 几乎一定是恶意的。
2. **编码的 PowerShell**:`Image` 以 `powershell.exe` 结尾,`CommandLine` 包含 `-enc`、`-encodedcommand` 或 `FromBase64String`。解码载荷、看它做什么 —— 并交叉对照同主机的 [PowerShell 4104 脚本块](/zh/blog/powershell-4104-scriptblock)记录,看实际执行了什么。
3. **从异常位置运行的 LOLBin**:签名的 Microsoft 二进制(`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`)从 `C:\Users\`、`%TEMP%` 或 `C:\ProgramData\` 运行。

## 为什么父子链重要

单条 ProcessCreate 是快照;链才是故事。`ProcessGuid` 和 `ParentProcessGuid` 是 Sysmon 分配的 GUID,用以跨进程退出追踪血缘 —— 比 PID 更可靠,因为 PID 会被复用。重建这棵树(每条记录的 `ParentProcessGuid` 是另一条记录的 `ProcessGuid`),kill-chain 就一目了然:Outlook → Word → PowerShell → cmd → certutil → mshta。

## Sigma 规则样例 —— Office 应用拉起 shell

```yaml
title: Office Application Spawning Shell or Scripting Host (Sysmon)
id: 7a4c1f2b-6e3d-4a5f-9c2a-1b3d4e5f6a7c
status: stable
description: A Microsoft Office or document-rendering process spawned cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
      - '\acrord32.exe'
    Image|endswith:
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
  - Document automation pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
```

## KQL 样例 —— 带父进程上下文的编码 PowerShell

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` 是 Defender XDR 中对应 Sysmon 1 `ParentCommandLine` 的字段 —— [4688](/zh/blog/event-id-4688-process-creation) 没有提供。

## Splunk 样例 —— 从用户可写路径运行的 LOLBin

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## ATT&CK 对应

- **T1059 —— Command and Scripting Interpreter** 及子技术 `.001` PowerShell、`.003` Windows Command Shell、`.005` Visual Basic、`.007` JavaScript。
- **T1566.001 —— Phishing: Spearphishing Attachment**:Office → shell 链。
- **T1218 —— System Binary Proxy Execution** 及子技术 `.005` Mshta、`.010` Regsvr32、`.011` Rundll32、`.007` Msiexec。
- **T1036.003 —— Masquerading: Rename System Utilities**:`OriginalFileName` ≠ `Image` 的文件名。
- **T1055 —— Process Injection**:Sysmon 1 的 `IntegrityLevel` 和父链有助于发现 `lsass.exe` 或 `services.exe` 等进程的异常父进程。

## 看起来像攻击的误报

- **软件更新代理**常以 SYSTEM 身份拉起 shell(Chocolatey、WinGet、厂商 MSI)。给已知自动更新主机打标签。
- **漏洞扫描器**在带认证扫描时模仿攻击型进程树。给扫描器 IP 打标签。
- **Citrix / RDS** 多会话主机产生的密集进程创建流量与攻击者模式重叠。按源段过滤。
- **Defender / EDR 扫描**在按需扫描期间从异常路径运行签名的 Microsoft 二进制。

## 覆盖率提醒

Sysmon 只捕获它的配置告诉它捕获的内容。默认配置不记录任何东西;权威参考是 SwiftOnSecurity 的 `sysmon-config` 和 Olaf Hartong 的 `sysmon-modular`。没有正经配置,事件 1 记录会很稀疏,`CommandLine` 可能被遮蔽,`Hashes` 可能缺失。读日志时一并查看主机的 Sysmon 配置。
