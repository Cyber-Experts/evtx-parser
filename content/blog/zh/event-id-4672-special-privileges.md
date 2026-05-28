---
title: "Event ID 4672 解读：在 Windows 中发现特权登录"
description: '4672 在登录被授予 SeDebugPrivilege 或 SeTcbPrivilege 等敏感特权时触发。把它读成等同于管理员的登录信号，审计策略其余部分就顺理成章。'
date: "2026-05-24"
---

Event ID **4672**「为新登录分配了特殊特权」在每次登录会话被授予一组固定的敏感 Windows 特权之一时触发于 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。实务上，每一次成功的、等同于管理员的登录都会产生一条 4672，紧随对应的 [4624](/zh/blog/understanding-event-id-4624) 之后写入。多数工作站上 4672 很罕见。在域控和管理员跳板机上则是常态。这种不对称正是它有用的原因。

本周如果你只按一个字段过滤 Security，就跑"过去七天所有的 4672"。这是你能写出的最便宜的"给我看资产里每一次特权会话"的查询。

## 在哪里触发

在登录实际发生的主机上，同 [4624](/zh/blog/understanding-event-id-4624)。一次到 `SERVER01` 的网络登录，会在 `SERVER01` 上产生 4624 和 4672，而不是发起方工作站。要在规模上从 4672 检测出什么，至少需要从服务器与 DC 收集 Security。预算允许的话，再加上管理员工作站和跳板机。

## 记录的内容

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

字段：

- `SubjectLogonId`。与对应的 [4624](/zh/blog/understanding-event-id-4624) 的 `LogonId` 相同。这是你的支点。每一条 4672 都把一条 4624（以及该会话中之后的每一条记录）精确绑定到该登录所获得的特权集。
- `PrivilegeList`。实际的特权袋。Windows 只记录审计策略中定义为"敏感"的特权。一次登录可能持有比该记录显示的更多特权。被省略的（`SeLockMemoryPrivilege`、`SeIncreaseBasePriorityPrivilege` 等）是与安全无关的，被有意从该记录中剪除。
- `Subject*`。该登录归属的主体。几乎总是与对应的 4624 相同。

4672 本身没有 `IpAddress`、`LogonType` 或 `WorkstationName`。要拿到这些，需通过 `SubjectLogonId` 连接到 4624。仅凭 4672 告警的分析师常常忽略这一点，最后得到无法增强的记录。

## 特权及其意义

| 特权 | 显示名 | 重要原因 |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | 读写任意进程内存，包括 `lsass.exe`。Mimikatz 需要它。 |
| `SeTcbPrivilege` | Act as part of the OS | 事实上的 `LocalSystem`。本应只在 LocalSystem 出现。 |
| `SeImpersonatePrivilege` | Impersonate a client after auth | Potato 家族（PrintSpoofer、JuicyPotato、RoguePotato、GodPotato）使用的特权。 |
| `SeAssignPrimaryTokenPrivilege` | Replace a process token | 令牌冒充工具。 |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | 绕过 ACL 读写任意文件，包括注册表蜂巢。`reg save HKLM\SAM` 靠它工作。 |
| `SeTakeOwnershipPrivilege` | Take ownership | 覆盖文件 ACL。 |
| `SeLoadDriverPrivilege` | Load drivers | BYOVD（bring-your-own-vulnerable-driver）所必需。 |
| `SeSecurityPrivilege` | Manage audit log | 读取或清除 Security。触发 [1102](/zh/blog/event-id-1102-cleared-log) 所必需。 |
| `SeSystemEnvironmentPrivilege` | Modify firmware | bootkit、EFI 篡改。 |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | 几乎所有登录都有。不是分诊信号。 |

一些是每次管理员登录的预期特权（`SeDebugPrivilege`、`SeBackupPrivilege`）。另一些应当更稀少（`SeLoadDriverPrivilege`、`SeTcbPrivilege`）。信号是*意料之外*的特权出现在*不应有的*账户上。

## 模式

### 谁会出 4672 的基线

健康的资产中，4672 的产生者是一个小且已知的集合：

- `LocalSystem`（S-1-5-18）。每台主机，所有时段，服务启动时。
- `NetworkService`（S-1-5-20）。在运行可冒充服务的服务器上常见。
- 少数管理员，按 SID 而不是名字识别。

其他任何都是你不知道的新管理员、特权提升事件，或配置错误的账户。

最便宜的基线查询：过去 30 天内 4672 中不同的 `SubjectUserSid`，按频率排序。前 N 之外的都值得看一看。

### 在无特权账户上出现 SeImpersonatePrivilege

如果一条 4672 在既不是管理员、也不是 `*Service` SID 的账户上显示 `SeImpersonatePrivilege`，几乎肯定是 Potato 系列的提升。这些漏洞利用让一个 `IIS_IUSRS` 或服务令牌调用者获得 `SYSTEM`。4672 *在特权被获得的瞬间*触发，比任何带着新特权诞生的可见进程都早。

### 不在管理员组却拿到 SeDebugPrivilege

`SeDebugPrivilege` 按策略授予本地管理员。出现在非管理员账户上，要么策略被修改（通常被攻击者用来开启 LSASS 访问），要么攻击者注入到了管理员进程。

### 业务时间外的特权登录

周日凌晨 3 点真实管理员账户的 4672，是最便宜的下班时间告警之一。结合对应 4624 的 `LogonType` 与 `IpAddress` 做上下文判断。

### 服务账户漂移

历史上只触发 `SeImpersonatePrivilege` 与 `SeAssignPrimaryTokenPrivilege` 的服务账户，突然产生带 `SeBackupPrivilege` 与 `SeDebugPrivilege` 的 4672，意味着有人改了它的组成员关系。配合 4732 或 4728 找成员关系变更。

## Sigma：非管理员上的 SeDebugPrivilege

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

按环境调整 `filter_known_admins`。有些公司用 SID 列表而不是名字模式。

## KQL：Potato 家族的提升

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Splunk：管理员登录基线

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

每周跑一次。异常会以新账户的形式出现在前 50。

## ATT&CK 对应

- T1134.001 Token Impersonation/Theft。无特权账户上的 SeImpersonatePrivilege。
- T1003.001 LSASS Memory。SeDebugPrivilege 是前提。
- T1068 Exploitation for Privilege Escalation。任何意料之外的特权获得。
- T1078 Valid Accounts。来自异常来源的合法管理员账户的 4672。
- T1562.002 Disable Windows Event Logging。调用 `ClearEventLog` 需要 SeSecurityPrivilege。在 [1102](/zh/blog/event-id-1102-cleared-log) 之前刚好携带该特权的一条 4672，就是面包屑。

## 看起来像攻击的误报

- 备份软件（Veeam、Commvault）会从服务账户日常触发带 `SeBackupPrivilege` + `SeRestorePrivilege` 的 4672。按服务账户 SID 建立基线。
- 监控代理（SCOM、自定义 WMI 收集器）会广泛触发 4672。给代理所在主机打标签。
- 在特权上下文下的部分登录脚本运行器，会在登录时产生 4672 链。
- Hyper-V、VMM、容器主机会从 `LocalSystem` 与托管服务账户产生密集的 4672。

信号是*新*的产生者，而不是*持续*的。一年里每天都触发的 4672 来源是配置。本周才出现的，是线索。

## 4672 没告诉你的事

- 没有进程信息。你看到特权授予，看不到这个特权进程做了什么。要往前追，把 `SubjectLogonId` 接到同一会话中的 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 记录。
- 没有直接的源 IP。需通过 `SubjectLogonId` 连接到 [4624](/zh/blog/understanding-event-id-4624)。
- 不是每一次特权行动。只记录*登录时的授予*。后续使用（例如 `RtlAdjustPrivilege` 切换 `SeDebugPrivilege` 的开关）会产生 4673/4674，而不是另一条 4672。
- 当 Special Logon 审计关闭时会被漏掉。审计子策略是 *Audit Special Logon*。现代 Windows 默认开启，但值得核实。

## 4672 在时间线中的位置

教科书式的提升与清理链：

1. [4624](/zh/blog/understanding-event-id-4624)。来自攻击者控制 IP 的 LogonType 3，低权限用户。
2. *（静默）*。基于 SeImpersonatePrivilege 的提升（PrintSpoofer 等）。
3. **4672**。新登录会话以 LocalSystem 身份获得 SeImpersonatePrivilege + SeTcbPrivilege。提升在此可见。
4. [4688](/zh/blog/event-id-4688-process-creation)。通过被冒充的令牌以 SYSTEM 身份运行 `cmd.exe` 或 `powershell.exe`。
5. [4104](/zh/blog/powershell-4104-scriptblock)。针对 LSASS 的 `Invoke-Mimikatz` 或 `comsvcs.dll MiniDump`。让这一切能运作的就是 SeDebugPrivilege。
6. [1102](/zh/blog/event-id-1102-cleared-log)。Security 日志被清。步骤 3 中获得的 SeSecurityPrivilege 让这件事得以发生。
7. **4672**。第二次特权会话，以从 LSASS 内存提取出来的域管理员身份。

步骤 3 与 7 中的 4672 是最便宜的检测点。没有它们，你只能仅凭进程事件来拼出冒充过程。更慢，也更容易漏掉。

## 延伸阅读

- [4672 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
