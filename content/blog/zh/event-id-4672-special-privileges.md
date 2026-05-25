---
title: "Event ID 4672 详解:检测 Windows 特权登录"
description: "每当一次登录被授予 SeDebugPrivilege 或 SeTcbPrivilege 等敏感权限时,4672 就会触发。把它视为「这次登录等价于管理员」的信号,你其余的审计策略就有了主心骨。"
date: "2026-05-24"
---

Event ID **4672** ——「为新登录分配了特殊权限」—— 每当一个登录会话被授予一组固定的 Windows 敏感权限时,就会写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。实务上这意味着:每一次成功的管理员等价登录都会产生一条 4672,紧跟在对应的 [4624](/zh/blog/understanding-event-id-4624) 之后。在大多数工作站上 4672 很罕见;在域控和管理员跳板机上则持续出现。这种不对称正是它的价值所在。

如果你只能用一个字段过滤 Security 记录,「给我看过去一周所有的 4672」就是最便宜的「展示资产中每一次特权会话」查询。

## 它在哪里触发

总在登录实际发生的主机上 —— 与 [4624](/zh/blog/understanding-event-id-4624) 相同。一次到 `SERVER01` 的网络登录会在 `SERVER01` 上(而不是发起的工作站上)产生 4624,以及(若为特权)4672。要规模化地从 4672 检测出任何东西,你至少需要从服务器和 DC 收集 Security;如果容量允许,还要包括管理员工作站和跳板机。

## 记录里有什么

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

字段含义:

- **`SubjectLogonId`** —— 与对应 [4624](/zh/blog/understanding-event-id-4624) 上一致的 `LogonId`。这是你的透视点:每条 4672 把恰好一条 4624(以及该会话之后所有记录)绑到这次登录拿到的权限集合上。
- **`PrivilegeList`** —— 实际的权限袋。Windows 只在这里记录一组固定的「敏感」权限(由审计策略定义);一次登录可能持有比记录显示更多的权限。被省略的那些 —— `SeLockMemoryPrivilege`、`SeIncreaseBasePriorityPrivilege` 等 —— 与安全无关,是被刻意从这条记录里剪掉的。
- **`Subject*`** —— 该登录所属的主体。几乎总是与对应 4624 的同名字段一致。

4672 本身没有 `IpAddress`、没有 `LogonType`、没有 `WorkstationName`。要拿这些,你得通过 `SubjectLogonId` 关联到 4624。

## 这些权限及其含义

| 权限 | 显示名 | 为什么重要 |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | 读/写任意进程的内存 —— 包括 `lsass.exe`。Mimikatz 需要这个。 |
| `SeTcbPrivilege` | Act as part of the operating system | 实际上就是 `LocalSystem`。应只出现在 LocalSystem 自己身上。 |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | `SeImpersonatePrivilege` 利用家族(PrintSpoofer、JuicyPotato、RoguePotato)所用的权限。 |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | 令牌冒充工具。 |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | 绕过 ACL 读/写任意文件 —— 包括注册表 hive。`reg save HKLM\SAM` 靠这俩。 |
| `SeTakeOwnershipPrivilege` | Take ownership of files | 覆盖文件 ACL。 |
| `SeLoadDriverPrivilege` | Load and unload device drivers | BYOVD(自带易受攻击驱动)攻击所需。 |
| `SeSecurityPrivilege` | Manage auditing and security log | 读/清 Security 事件日志。触发 [1102](/zh/blog/event-id-1102-cleared-log) 所需。 |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkit、EFI 篡改。 |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | 大多数登录都有;不是分诊信号。 |

其中有些是你预期每次 admin 登录都有的(`SeDebugPrivilege`、`SeBackupPrivilege`)。另一些应该更稀有(`SeLoadDriverPrivilege`、`SeTcbPrivilege`)。信号在于*意外的*权限出现在了*不该出现的*账号上。

## 分诊模式

### 1. 基线化哪些主体会触发 4672

在一个健康的资产里,4672 的产生方是一个*小而已知*的集合:

- `LocalSystem`(S-1-5-18)—— 所有主机,所有时间,服务启动时。
- `NetworkService`(S-1-5-20)—— 在运行支持冒充服务的服务器上常见。
- 一小撮管理员,按 SID 而不是名字识别。

其他任何人产生的 4672 要么是:一个你不知道的新管理员、一次提权事件,或一个配置错误的账号。

最便宜的基线查询:过去 30 天内 4672 的 distinct `SubjectUserSid`,按频次排序。Top N 之外的任何条目都值得看一眼。

### 2. 非特权账号上的 SeImpersonatePrivilege

如果一条 4672 在一个既不是管理员也不是 `*Service` SID 的账号上显示 `SeImpersonatePrivilege`,它几乎一定是「Potato」家族提权(PrintSpoofer、JuicyPotato、RoguePotato、GodPotato)。这些利用让 `IIS_IUSRS` 或服务令牌调用方拿到 `SYSTEM`。4672 *在权限被获得的瞬间*触发 —— 比任何带新权限派生出来的可见进程都更早。

### 3. 不属于管理员组却有 SeDebugPrivilege

`SeDebugPrivilege` 按策略授予本地管理员。在非管理员账号上看到它,意味着策略被改过 —— 通常是攻击者为了拿到 LSASS 访问而改的 —— 或者攻击者注入到了管理员进程里。

### 4. 业务时间外的特权登录

周日凌晨 3 点真实管理员账号的一条 4672,就是最便宜的「非工作时间管理员活动」告警。结合对应 4624 的 `LogonType` 和 `IpAddress` 看上下文。

### 5. 服务账号漂移

历史上只触发 `SeImpersonatePrivilege` 和 `SeAssignPrimaryTokenPrivilege` 的服务账号,突然产生带 `SeBackupPrivilege` 和 `SeDebugPrivilege` 的 4672,意味着有人改了它的组成员关系。配合 4732/4728 查成员变更。

## Sigma 规则样例 —— 非管理员被授予 SeDebugPrivilege

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
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

按环境调优 `filter_known_admins`;有些组织用 SID 列表而不是名字模式。

## KQL 样例 —— Potato 家族提权

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

## Splunk 样例 —— 管理员登录基线

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

每周跑一次;异常会以「top 50 出现新账号」的形式显现。

## ATT&CK 对应

- **T1134.001 —— Access Token Manipulation: Token Impersonation/Theft**:非特权账号上的 SeImpersonatePrivilege。
- **T1003.001 —— OS Credential Dumping: LSASS Memory**:SeDebugPrivilege 是先决条件。
- **T1068 —— Exploitation for Privilege Escalation**:任何意外的权限获取。
- **T1078 —— Valid Accounts**:合法管理员账号的 4672,但来源异常。
- **T1562.002 —— Impair Defenses: Disable Windows Event Logging**:调用 `ClearEventLog` 需要 SeSecurityPrivilege;带该权限的 4672 紧接 [1102](/zh/blog/event-id-1102-cleared-log) 是面包屑串。

## 看起来完全像攻击的误报

- **备份软件**(Veeam、Commvault)在服务账号上常态触发带 `SeBackupPrivilege` + `SeRestorePrivilege` 的 4672。按服务账号 SID 基线化。
- **监控代理**(SCOM、自定义 WMI 收集器)读取安全相关数据时会广泛触发 4672。给代理主机打标签。
- **某些登录脚本**运行器在特权上下文下,登录时会产生 4672 链。
- **Hyper-V / VMM / 容器宿主**会从 `LocalSystem` 和托管服务账号产出密集的 4672 流量。

信号在*新出现*的产生方,不是*周期性*的那个。每天都触发了一年的 4672 产生方是配置;这周刚冒出来的才是线索。

## 4672 不会告诉你的东西

- **没有进程信息**:你看到权限被授予,但看不到被授权的进程做了什么。要往后追,把 `SubjectLogonId` 透视到同一会话里的 [4688](/zh/blog/event-id-4688-process-creation) / [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 记录。
- **没有直接的源 IP**:得通过 `SubjectLogonId` 关联到 [4624](/zh/blog/understanding-event-id-4624) 才能拿到。
- **不是每次特权动作**:只记录*登录时的授予*。后续使用(例如 `RtlAdjustPrivilege` 切换 `SeDebugPrivilege` 开/关)会产生 4673/4674,而不是另一条 4672。
- **若 Special Logon 审计关闭则错过**:对应的审计子类是 *Audit Special Logon*,成功事件必须启用。现代 Windows 默认开启,但值得验证。

## 4672 在时间线中的位置

教科书式的提权与清场链:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— 攻击者控制 IP 的 LogonType 3,低权限用户。
2. *(无声)* —— 基于 `SeImpersonatePrivilege` 的提权(PrintSpoofer 或类似)。
3. **4672** —— 一个新登录会话被授予 `SeImpersonatePrivilege` + `SeTcbPrivilege`,以 `LocalSystem` 身份运行。**提权在这里可见。**
4. [**4688**](/zh/blog/event-id-4688-process-creation) —— 通过被冒充的令牌以 SYSTEM 身份运行的 `cmd.exe` 或 `powershell.exe`。
5. [**4104**](/zh/blog/powershell-4104-scriptblock) —— 针对 LSASS 的 `Invoke-Mimikatz` 或 `comsvcs.dll MiniDump` —— SeDebugPrivilege 让这一切成立。
6. [**1102**](/zh/blog/event-id-1102-cleared-log) —— Security 日志被清空。步骤 3 的 SeSecurityPrivilege 启用了这一动作。
7. **4672** —— 从 LSASS 内存中提取出的域管理员身份发起的第二个特权会话。

步骤 3 和 7 的 4672 是这条链最便宜的检测点。没有它们,你只能从进程事件拼凑出冒充关系 —— 更慢,也更容易漏。
