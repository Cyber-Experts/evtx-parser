---
title: "Event ID 1102 详解:安全审计日志被清空(以及还有什么留下来)"
description: "1102 是攻击者无法在不留下更多证据的前提下抑制的事件之一。这里讲它告诉你什么,以及清空之后还有什么会幸存。"
date: "2026-05-17"
---

Event ID **1102** 是 Windows 在 [`Security` 通道](/zh/blog/what-is-an-evtx-file)审计日志被清空时写入的记录。按设计,它是攻击者最难抑制的记录之一 —— 因为要抑制它,要么得在 EventLog 服务启动前成功替换它,要么得接受清空动作本身会留下一条自己的 1102。

对防御者而言这意味着:看到 1102,说明有人以足够的权限有意抹掉了审计轨迹。这几乎从来不是正常的管理员动作。

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

注意这里是 `UserData` 块而不是常见的 `EventData` —— 1102 是少数几条使用结构化 user-data schema 的记录之一。字段告诉你*谁*在哪个登录会话下清了日志。用 `SubjectLogonId` 透视找到对应的 [4624](/zh/blog/understanding-event-id-4624),就能拿到产生这个特权会话的源 IP 和登录类型。

## 1102 触发时还会有什么

清日志几乎从来不是*唯一*的反取证动作。常见的伙伴事件,按大致时间顺序:

- **104** 在 `System` 通道 —— 同一动作,由 SCM 记录。如果有 104 但没有 1102,说明攻击者只清了 Security 日志,忘了 System。
- **4719** —— 「系统审计策略被更改」。有时攻击者在清日志*之前*降低审计覆盖率,以便下一轮少留记录。
- **4616** —— 「系统时间被更改」。预先制造时间偏差让时间线重建更困难。
- **1102 之前一两个小时的 4624 缺口** —— 攻击者可能走了不记日志的旁路。

## 清空之后什么会幸存

清掉内存中的事件日志并不会影响:

- **其它通道**:`System`、`Application`、`PowerShell/Operational`、`Sysmon/Operational`、`TaskScheduler/Operational`、转发事件通道 —— 这些都不会被 Security 的清空波及。
- **已转发的事件**:如果配置了 Windows 事件转发(WEF)到中央收集器,被清掉的记录已经在另一台主机上。
- **磁盘上的文件本身**:被清掉的 `Security.evtx` 会被一份新文件替换;*被删除的*原始文件所在的簇通常仍在未分配空间中,可以用 NTFS 工具雕刻出来。
- **文件替换在 USN journal 中的条目**:连清空操作都会留下文件系统级的痕迹。

「成功」的日志清空很少像攻击者希望的那样干净。

## Sigma 规则样例 —— 日志被清空

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
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

如果你在批准的维护窗口之外看到 1102,按事件对待 —— 没得商量。

## KQL 样例 —— 清日志与特权会话关联

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

每一条 1102 都能追溯到一条授予 `SeSecurityPrivilege` 的 [4672](/zh/blog/event-id-4672-special-privileges) —— 而 4672 又能追到一条 [4624](/zh/blog/understanding-event-id-4624)。这一连串 join 才完整。

## Splunk 样例 —— 反取证伴生链

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

一个先动了审计策略(4719)或系统时间(4616)、再清了日志(1102/104)的 `LogonId`,就是篡改链。

## ATT&CK 对应

- **T1070.001 —— Indicator Removal: Clear Windows Event Logs**:头号技术。1102 *就是*这一技术的主要指示。
- **T1562.002 —— Impair Defenses: Disable Windows Event Logging**:1102 之前的 4719(审计策略更改)对应这里。
- **T1070.006 —— Indicator Removal: Timestomp**:同链中和 4616(系统时间更改)配对。
- **T1078.003 —— Valid Accounts: Local Accounts**:本不该在那个时间登录的本地 Administrator 触发的 1102。

## 误报 —— 罕见但真实存在

- **迁移 / 退役流程**:工程师在退役主机上清日志。这种操作必须有工单。
- **取证 / 测试实验室**:检测开发过程中清空再复现的工作流。
- **某些遗留工具**:为了重置基线而清日志 —— 几乎一定是流程错误,但确实会发生。

由于该信号直接是反取证,即使是合法的 1102 也应在事后调查并记录。正常运维里不存在「安全」的 1102 理由。

## 这对解析意味着什么

[把 .evtx 文件载入取证工具时](/zh/blog/how-to-open-an-evtx-file),*第一个*值得跑的搜索是 `EventID:1102` 和 `EventID:104`。如果其中任一存在,手里这份日志就有已知缺口,基于它构建的任何时间线都不完整。在报告里大声标注出来。
