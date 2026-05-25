---
title: "Event ID 4720 详解:检测 AD 中的恶意账户创建"
description: "4720 每次创建用户账号都会触发 —— 本地或 AD。把它和 4722/4724/4732 一起读,几分钟内就能发现持久化和横移账户。"
date: "2026-05-24"
---

Event ID **4720** ——「用户账户已创建」—— 每当一个新用户账户被配置时,就会写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。在域控上,它在每个新 AD 用户时触发;在工作站或成员服务器上,它在每个新本地账户时触发。在成熟的组织里,4720 流量几乎都由 HR 驱动且可预测。这种可预测正是它的价值所在:攻击者创建一个后门账号会显眼,正因为合法流量太规律。

这是平台产生的最便宜的持久化检测记录之一。

## 它在哪里触发

- **域账户**:4720 落在处理创建的 DC 上。要在所有 DC 上采集。
- **本地账户**:4720 落在创建账户的主机上。要从成员工作站抓到这个信号需要 WEF 或逐主机采集 —— 很多组织跳过了工作站的 Security 转发,完全丢失了这个信号。

如果攻击者在已攻陷的服务器上创建一个*本地*账号(常作为备份凭证),4720 只会在那台服务器上。覆盖很重要。

## 记录里有什么

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

驱动调查的字段:

- **`TargetUserName`** —— 新账号。字面名字是第一道分诊信号:`svc_*`、`backup*`、`admin2`、`test`、`guest2`,与合法账号相似的名字(`administrator`、`administr0r`),以及短随机串,都值得细看。
- **`SubjectUserName` / `SubjectLogonId`** —— *谁*创建的。透视到创建该会话的 [4624](/zh/blog/understanding-event-id-4624)。工作站上业务时间外由 `LocalSystem` 触发的 4720 不是真正的配置流程。
- **`UserAccountControl`** —— *初始*的 UAC 标志集合。`0x10`(示例)是 `NORMAL_ACCOUNT`;危险标志会出现在后续 4738(账号变更)记录里。完整 UAC 位图见 MS-SAMR。
- **`PrimaryGroupId`** —— 513(Domain Users)正常;新账号上 512(Domain Admins)是天大的异常,正常配置流程里绝不会发生。
- **`SidHistory`** —— *新建*账号上非空的 `SidHistory` 强烈提示是迁移工具 —— 或者在错误上下文里,是一个伪造的认证产物。

## 4720 不会单独出现的记录

账号创建几乎从来不是单一事件。最小序列:

| 事件 | 含义 | 为什么关心 |
|---|---|---|
| **4720** | 用户账号已创建 | 主标题。 |
| **4722** | 用户账号已启用 | 账号被设为允许登录。没有 4722,账号存在但无法登录。 |
| **4724** | 密码重置(管理员触发) | 有人 —— 可能不是创建者 —— 设置或重置了密码。 |
| **4738** | 用户账号已变更 | UAC 标志、过期、组、属性变更。 |
| **4732** | 添加到启用安全的本地组 | 若该本地组是 `Administrators`,这就是权限授予。 |
| **4728** | 添加到启用安全的全局组 | 若该全局组是 `Domain Admins` 或 `Enterprise Admins`,提权。 |
| **4756** | 添加到启用安全的通用组 | `Schema Admins`、`Enterprise Admins`、自定义委派。 |

后门账号很少创建后就保留默认权限。完整链 —— `4720 → 4722 → 4724 → 4738 (UAC 标志) → 4732/4728 (加组)` —— 在几秒内完成,这才是真正的持久化事件。

## 分诊模式

1. **新账号 → 几分钟内加入管理员组**:4720 在一小时内之后跟着 4732/4728 加到特权组,而特权组添加*没有*被变更管理系统中的工单引导。把 4720 的 `TargetSid` 与 4732/4728 上的 `MemberSid` 配对。
2. **非工作时间创建**:由非自动化配置服务账号的 `SubjectUserName` 在业务时间外触发的 4720。
3. **相似名字**:`Levenshtein(TargetUserName, real_admin_name) <= 2` 对照现有用户表。`administrato`、`administr0r`、`helpd3sk` —— 都是真实案例。
4. **由最近被攻陷的账号创建**:4720 的 `SubjectLogonId` 追溯到来自异常 IP 的 4624,或者主体平常不使用的某台工作站的 4624 LogonType 3。
5. **工作站上由 `LocalSystem` 创建**:`SubjectUserSid = S-1-5-18` 的 4720,出现在非域控或已知配置服务器以外的地方。几乎必然是恶意的。
6. **`PrimaryGroupId == 512`**:正常配置中绝不会出现。硬告警。

## Sigma 规则样例

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

高置信度变体:把 4720 和 1 小时内对特权组的 4732/4728 组合起来,按 `TargetSid` 限定。

## KQL 样例 —— 4720 + 权限授予

KQL(Sentinel)——「新账号 → 管理员组」透视:

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Splunk 样例

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## ATT&CK 对应

- **T1136.001 —— Create Account: Local Account**:工作站/服务器本地账号。
- **T1136.002 —— Create Account: Domain Account**:DC 记录的创建。
- **T1136.003 —— Create Account: Cloud Account** —— *不会*触发 4720(云账户创建在 Azure AD 审计日志 / 统一审计日志,不在 Windows Security)。
- **T1098 —— Account Manipulation**:4720 后跟随组提权或属性变更。

## 看起来完全像攻击的误报

- **批量迁移工具**(ADMT、Quest Migration Manager)会高速创建带 `SidHistory` 的账户。流量形态和快速攻击者一致;对已知迁移窗口做基线。
- **入职流水线**在 HR 驱动的配置流程里在可预测时间触发 4720。如果你对每个非工作时间的 4720 都告警,会被夜里跑过午夜的 HR 系统淹没。
- **SCCM / Intune / Jamf 风格**的管理工具会创建本地账户做 OS 配置。`SubjectUserSid` 是已知构建主机上的 `S-1-5-18`(LocalSystem);标记这些主机。
- **服务安装器**在首次运行时为某些遗留产品创建本地服务账号。基线化该安装器。

可靠的 4720 检测总是把创建和后续信号(加组、密码改成已知弱模式、立刻从异常主机登录)组合起来。单独的创建过于嘈杂。

## 4720 不会告诉你的东西

记录不包含新账号的*密码*(Windows 在任何地方都不记录密码)。它也不显式包含*目标域*的 SID;域要从 `TargetDomainName` 读,或从 `TargetSid` 的域部分推导。

成员工作站上的本地账户创建对 DC 不可见。如果你不从工作站采集 Security(大多数组织不采集),你会漏掉每一个本地后门账号。Sysmon 和真正的 EDR 能填补一部分(碰到本地 SAM 时的文件创建 / 注册表变更模式),但 4720 转发是最便宜的方式。

## 4720 在时间线中的位置

教科书式持久化链:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— 被钓鱼用户的初始域登录。
2. [**4769**](/zh/blog/event-id-4769-kerberoasting) 爆发 —— 对域服务账号的 kerberoasting。
3. **4624** —— 在某成员服务器上以被攻陷服务账号身份登录。
4. [**4688**](/zh/blog/event-id-4688-process-creation) —— `net user svc_backup2 P@ssw0rd! /add /domain`(或通过 PowerShell `New-ADUser` 同等命令)。
5. **4720** —— 账号在 DC 上创建。
6. **4724** —— 密码已设置。
7. **4722** —— 账号已启用。
8. **4728** —— 加入 Domain Admins。
9. [**7045**](/zh/blog/service-creation-event-id-7045) —— 服务器上安装服务,以新账号运行。

只仪表化 4720,你就能在第 5 步抓到持久化 —— 比 6-9 造成任何破坏都更早。这就是价值。
