---
title: "Event ID 4720 解读：检测 AD 中的恶意账户创建"
description: "4720 在每次创建用户账户时触发，本地账户或域账户都会。把它和 4722、4724、4732 一起读，几分钟就能抓到持久化与横向移动账户。"
date: "2026-05-24"
---

Event ID **4720**「已创建一个用户账户」在每次新用户被配置时落到 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。在域控上，每个新 AD 用户都会触发它。在工作站或成员服务器上，每个新本地账户都会触发它。在成熟的环境里，4720 流量绝大部分由 HR 驱动且可预测。正是这种可预测性让它变得有用。攻击者创建后门账户之所以醒目，恰恰因为合法流量太规整。

这是这个平台所能产出的、成本最低的持久化检测记录之一。我仅凭它就结过案。

## 在哪里触发

- 域账户：4720 落在处理创建操作的 DC 上。请覆盖所有 DC 收集。
- 本地账户：4720 落在创建该账户的主机上。要从成员工作站抓到它，需要 WEF 或按主机收集。许多公司跳过了工作站 Security 转发，整个就丢掉了这一信号。

如果攻击者在已被攻陷的服务器上创建*本地*账户（常作为备用凭据），4720 只会在那台服务器上。覆盖比规则更重要。

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

驱动调查的字段：

- `TargetUserName`。新账户。字面上的名字就是第一道分诊信号：`svc_*`、`backup*`、`admin2`、`test`、`guest2`、与合法账户的相似名（`administrator`、`administr0r`），以及短随机串都值得多看一眼。
- `SubjectUserName` 与 `SubjectLogonId`。谁创建的。跳到创建该会话的 [4624](/zh/blog/understanding-event-id-4624)。下班时间从工作站上以 `LocalSystem` 触发的 4720，不是真实的配置工作流。
- `UserAccountControl`。UAC 标志的*初始*集。示例中的 `0x10` 是 `NORMAL_ACCOUNT`。危险标志会出现在随后的 4738 记录中。
- `PrimaryGroupId`。513（Domain Users）是常见的。新账户上的 512（Domain Admins）是震耳欲聋的，在真实的配置流程里永远不该出现。
- `SidHistory`。刚创建的账户上非空，要么是迁移工具，要么在错误的上下文中就是伪造的认证产物。

## 4720 从不孤单

账户创建几乎从不是单一事件。最小序列：

| 事件 | 含义 | 为什么重要 |
|---|---|---|
| **4720** | 用户账户已创建 | 标题。 |
| **4722** | 用户账户已启用 | 账户被设为允许登录。如果缺少 4722，账户已存在但还不能登录。 |
| **4724** | 密码重置（管理员驱动） | 某个人，可能不是创建者，设置或重置了密码。 |
| **4738** | 用户账户已修改 | UAC 标志、过期、组、属性变更。 |
| **4732** | 成员被加到启用安全的本地组 | 如果本地组是 `Administrators`，这就是特权授予。 |
| **4728** | 成员被加到启用安全的全局组 | 如果全局组是 `Domain Admins` 或 `Enterprise Admins`，是提升。 |
| **4756** | 成员被加到启用安全的通用组 | `Schema Admins`、`Enterprise Admins`、自定义委派。 |

后门账户很少在创建后保留默认特权。完整链路（4720、4722、4724、4738、4732/4728）会在秒级内完成，是真正的持久化事件。

## 分诊模式

1. **新账户几分钟内进入管理员组**。4720 之后在一小时内出现到特权组的 4732 或 4728，且该特权组添加并未由工单先行。把 4720 的 `TargetSid` 与 4732/4728 的 `MemberSid` 配对。
2. **下班时间创建**。下班时间由一个不是跑自动化配置的服务账户的 `SubjectUserName` 触发的 4720。
3. **相似名**。对现有用户表的 `Levenshtein(TargetUserName, real_admin_name) <= 2`。`administrato`、`administr0r`、`helpd3sk`。都真实见过。
4. **由最近被攻陷的账户创建**。`SubjectLogonId` 可追溯到一条来自异常 IP 的 4624，或一条来自该 subject 平时不用的工作站的 LogonType 3 的 4624。
5. **在工作站上由 LocalSystem 创建**。在非域控或非已知配置服务器上 `SubjectUserSid = S-1-5-18` 的 4720。几乎一定是恶意的。
6. **PrimaryGroupId == 512**。正常配置中永远不会出现。硬告警。

## Sigma

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

更高置信度的变体是：在 1 小时内把 4720 与到特权组的 4732 或 4728 串起来，按 `TargetSid` 作用域。

## KQL：4720 加特权授予

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

## Splunk

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

- T1136.001 Create Account: Local Account。工作站与服务器本地账户。
- T1136.002 Create Account: Domain Account。DC 记录的创建。
- T1136.003 Create Account: Cloud Account。*不会*触发 4720。云账户创建在 Entra ID 审计日志/统一审计日志中。
- T1098 Account Manipulation。当 4720 之后跟随组提升或属性变更时。

## 看似攻击的误报

- 批量迁移工具（ADMT、Quest Migration Manager）以高速创建账户并设置 `SidHistory`。形态与快速攻击者一致。请把已知的迁移窗口列入基线。
- HR 驱动的入职配置流水线在可预测的时间触发 4720。对每一次下班时间的 4720 都告警，你会被那些跨过午夜的 HR 任务淹没。
- SCCM、Intune、Jamf 等管理工具为 OS 配置创建本地账户。已知构建主机上的 `SubjectUserSid` 为 `S-1-5-18`。给它们打标签。
- 某些遗留产品的服务安装程序在首次运行时创建本地服务账户。把安装程序列入基线。

可靠的 4720 检测总是把创建与一个跟随信号结合（加入某组、密码改为已知弱模式、来自异常主机的立即登录）。孤立的创建事件噪声太大。

## 4720 没告诉你的事

记录中不包含新账户的密码（Windows 永远不会在任何地方记录这个）。它也不显式包含目标域的 SID。你从 `TargetDomainName` 读取域，或从 `TargetSid` 的域部分推导。

成员工作站上的本地账户创建对 DC 不可见。如果不从工作站收集 Security（多数公司不会），你会漏掉每一个本地后门账户。Sysmon 和一款真正的 EDR 能补足一部分缺口（在本地 SAM 被触碰时的文件创建与注册表变更模式），但 4720 转发是最便宜的控件。当日志转发关闭时，[registry](https://www.registryparser.com) 蜂巢快照是佐证。

## 4720 在时间线中的位置

教科书式的持久化链路：

1. [4624](/zh/blog/understanding-event-id-4624)。被钓鱼用户的初次域登录。
2. [4769](/zh/blog/event-id-4769-kerberoasting) 爆发。针对域服务账户的 Kerberoasting。
3. 在成员服务器上以被攻陷的服务账户身份的 4624。
4. [4688](/zh/blog/event-id-4688-process-creation)。`net user svc_backup2 P@ssw0rd! /add /domain`（或通过 PowerShell 的 `New-ADUser`）。
5. **4720**。DC 上创建账户。
6. 4724。设置密码。
7. 4722。启用账户。
8. 4728。加入 Domain Admins。
9. [7045](/zh/blog/service-creation-event-id-7045)。在服务器上以新账户运行的服务被安装。

仅仅检测 4720 这一条，你就能在第 5 步抓住持久化，在第 6 到 9 步造成伤害之前。这就是它的价值。

## 延伸阅读

- [4720 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
