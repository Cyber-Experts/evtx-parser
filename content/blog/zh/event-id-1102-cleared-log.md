---
title: "Event ID 1102 解读：Security 审计日志被清除（与什么得以幸存）"
description: "1102 是你无法抑制而不留下更多证据的唯一事件。它告诉了你什么，清除后什么得以保留，看到它后该去哪儿查。"
date: "2026-05-17"
---

Event ID **1102** 是 Windows 在有人清除审计日志时写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file) 的记录。设计上，它是攻击者较难抑制的记录之一。要干净地抑制它，要么在 EventLog 服务启动前替换其二进制，要么接受清除行为本身会留下一条自己的 1102。多数操作者选择第二种，寄望于没人在看。

如果你看到 1102，意味着具备足够特权的某人故意抹掉了审计轨迹。这在常规运维中基本不会发生；即便发生，也应当有工单。把任何不在批准维护时间窗内的 1102，视作事件，直到证伪。

## 记录里有什么

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

注意是 `UserData` 块，而不是常见的 `EventData`。1102 使用一个结构化的 user-data 模式，会把只看 `EventData` 的朴素解析器绊倒。这些字段告诉你是在哪个 logon 会话下，由谁清除了日志。以 `SubjectLogonId` 为支点，跳到对应的 [4624](/zh/blog/understanding-event-id-4624)，就能拿到产生该特权会话的源 IP、登录类型与凭据。

## 一同出现的伙伴

日志清除几乎从不是链路中唯一的反取证动作。在大致时间顺序上，常常和它一起触发的记录：

- `System` 通道的 **104**。与 1102 是同一行为，但由 SCM 为 Security 以外的通道记录。如果存在 104 而没有 1102，攻击者只清了 Security，忘了 System。
- **4719**，"系统审计策略已更改"。攻击者有时会在清除*之前*缩小审计范围，下次留下的记录更少。
- **4616**，"系统时间已更改"。清除前的时间戳改动会让时间线重建更难。
- 1102 之前一两个小时内的 4624 出现缺口。攻击者可能通过未被记录的旁路进入。

## 清除能幸存什么

清除内存中的事件日志，并不会影响：

- 其他通道。`System`、`Application`、`PowerShell/Operational`、`Sysmon/Operational`、`TaskScheduler/Operational`、转发事件通道。这些都不会因 Security 的清除而被清。
- 转发事件。如果 Windows Event Forwarding 把 Security 发到收集器，被清除的记录早已在另一台主机上。原始的 RecordID 与时间戳得以保留。
- 磁盘上的文件本身。被清除的 `Security.evtx` 会被替换为新文件。旧文件的簇通常仍残留在未分配空间中。EVTX 记录可从这些簇中[干净地雕刻出来](/zh/blog/carve-deleted-evtx-records)。
- 文件替换对应的 [USN journal](https://www.usnparser.com) 条目。清除这一行为本身就留下文件系统级的工件。
- 新文件的 [MFT](https://www.mftparser.com) 项，其创建时间戳应当与 1102 在秒级吻合。

一次"成功"的日志清除，远不像攻击者期望的那么干净。

## Sigma：日志被清

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

## KQL：与特权会话关联的清除

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

每一条 1102 都可追溯到一条授予 `SeSecurityPrivilege` 的 [4672](/zh/blog/event-id-4672-special-privileges)，再可追溯到一条 [4624](/zh/blog/understanding-event-id-4624)。这次连接补齐了画面。

## Splunk：篡改链

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

一个 LogonId 先动过审计策略（4719）或系统时间（4616），随后又清了日志（1102/104），就是篡改链。

## ATT&CK 对应

- T1070.001 Indicator Removal: Clear Windows Event Logs。标题。1102 *就是*主要指示器。
- T1562.002 Impair Defenses: Disable Windows Event Logging。1102 之前的 4719 对应到这里。
- T1070.006 Indicator Removal: Timestomp。与同一链路中的 4616 搭配。
- T1078.003 Valid Accounts: Local Accounts。本不该在当时登录的本地 Administrator 触发的 1102。

## 罕见但真实的误报

- 迁移或下架流程。技术人员在被下架的主机上清日志。应当始终走工单。
- 在检测开发期跑 clear-and-reproduce 循环的取证实验室。
- 部分遗留工具会清日志以"重置基线"。几乎永远是流程错误，但真实存在。

正常运维中没有出现 1102 的安全理由。即便是合法情况，事后也应当调查并归档。

## 在文件包中发现它时

当你把一个 [.evtx 文件加载到取证工具](/zh/blog/how-to-open-an-evtx-file) 中，最值得跑的前两个搜索是 `EventID:1102` 与 `EventID:104`。任一存在，你手上的日志就有已知缺口。基于它构建的任何时间线都不完整。在报告中大声写明这一点。然后去看那些幸存的：[registry](https://www.registryparser.com)、[USN journal](https://www.usnparser.com)、[MFT](https://www.mftparser.com)、[prefetch](https://www.prefetchparser.com)、[AmCache](https://www.amcacheparser.com)。它们合在一起，能重建 1102 试图抹去的大部分内容。

像 `Invoke-Phant0m` 这种工具通过挂起事件服务的线程而不是清日志来彻底绕过 1102。如果你看到 Security 出现长达数小时的沉默却没有 1102，也没有系统关机，那就是同一个问题的另一种形态。

## 延伸阅读

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [1102 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)
