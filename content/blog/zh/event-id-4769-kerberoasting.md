---
title: "Event ID 4769 解读：Kerberos 服务票据与 kerberoasting"
description: "4769 是 DC 对每一次服务票据请求的记录。按加密类型来读，可以发现 kerberoasting；与 4768 配在一起读，可以发现 pass-the-ticket。"
date: "2026-05-24"
---

Event ID **4769**「请求了 Kerberos 服务票据」在任意账户为某个服务请求一张 TGS（Ticket Granting Service）票据时，于每一台域控上触发。每一次 SMB 连接、每一次 SQL 登录、每一次 Web SSO 命中，都会在处理该请求的 DC 上产生一条。它是繁忙 DC 的 [Security 通道](/zh/blog/what-is-an-evtx-file) 中体量最大的记录，也是凭据被离线破解之前 kerberoasting 唯一可靠出现的地方。

如果你只在 DC 上检测三种 Security 记录，它就是其中之一。

## 它住在哪里

`4769` 只写入到发出它的**域控**的 Security 通道。客户端看不到。目标服务看不到。要看到一个域的全部 4769 记录，你必须从每台 DC 收集。在 DC 上跑 KAPE 的 `EventLogs` target，或者通过 WEF 把 Security 转发到收集器，都能用。WEF 是成熟环境的做法。

## 记录里有什么

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

驱动分诊的字段：

- `TargetUserName`。请求者（用户账户，`user@DOMAIN` 形式）。
- `ServiceName`。被请求的 SPN。这里若是用户账户而不是 `host/...` 或某个服务类，就值得怀疑。
- `TicketEncryptionType`。决定这条记录是否重要的字段。现代域使用 `0x12`（AES-256-CTS-HMAC-SHA1-96）或 `0x11`（AES-128）。**`0x17` 是 RC4-HMAC**：旧式、弱，是 Mimikatz 与 Rubeus `kerberoast` 模式*唯一*请求的加密类型。一条针对服务账户票据、TicketEncryptionType 为 `0x17` 的 4769，就是教科书式的 kerberoasting 指纹。
- `Status`。`0x0` 是成功。其他为拒绝（代码见 `[MS-KILE]`）。
- `IpAddress`。请求方主机。配合该主机上的 [4624](/zh/blog/understanding-event-id-4624) 看出生成该会话的登录。

## TicketEncryptionType：决定一切的字段

| 值 | 算法 | 状态 |
|---|---|---|
| 0x01 | DES-CBC-CRC | Win7 起默认禁用 |
| 0x03 | DES-CBC-MD5 | Win7 起默认禁用 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | 现代 |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | 现代（多数账户的默认） |
| **0x17** | **RC4-HMAC-MD5** | **旧式。kerberoasting 必需。** |
| 0x18 | RC4-HMAC-EXP | 导出级 RC4，极罕见 |

如果域已做基线，并在服务账户上把 `msDS-SupportedEncryptionTypes` 设为仅 AES，那这些账户应当根本不会出现 `0x17`。攻击者明确请求 `0x17`，因为破解 RC4 加密的服务票据成本极低。AES 则不然。破解工具*必须*请求 0x17。

这是记录中信号最高的字段。

## kerberoasting 的模式

Kerberoasting（T1558.003）的过程：

1. 攻击者用任意域用户认证（无需管理员权限）。
2. 攻击者枚举注册在用户账户（不是计算机账户）上的 SPN，通常通过 LDAP `(servicePrincipalName=*)` 过滤到 user 对象。
3. 攻击者用标准 Kerberos 协议为每一个 SPN 请求一张 TGS，使用 `etype=23`（RC4）。这就是你要找的 4769。
4. DC 痛快地发放票据，用服务账户的 NTLM 哈希加密。
5. 攻击者拿走加密 blob，在 Hashcat 里离线破解（`-m 13100`）。

4769 的指纹：

- `ServiceName` 是 `MSSQLSvc/...`、`HTTP/...`、`LDAP/...`，或者任何指向用户账户的 SPN（不是 `host/...` 或 `cifs/...`，那些是计算机账户）。
- `TicketEncryptionType` 是 `0x17`。
- 在短时窗内，来自同一来源，针对多个 SPN 的爆发。

一个相关模式 **AS-REP roasting**（T1558.004）改用 [4768](/zh/blog/event-id-4768-kerberos-tgt)，针对带 `DONT_REQUIRE_PREAUTH` 的账户。不同记录，同一家族。

## Pass-the-ticket、golden、silver

4769 也能揭示票据伪造，但信号更微妙。

- 在合理时间窗内，*没有*同一 `LogonGuid` 的前置 4768 却出现的 4769：怀疑金票。攻击者拿伪造 TGT 直接去请求 TGS。
- 出现了 4769 *并且*目标上有了对应的服务认证，但*任何* DC 上都看不到 4769：怀疑银票。攻击者直接伪造了 TGS，DC 根本没被问过。
- 目标上的 4624 与据称发放该票据的 4769 之间 `LogonGuid` 对不上：伪造票据。

这些都属于按缺失检测的模式。需要所有 DC 与目标服务都有完整日志覆盖。WEF 覆盖缺口会产生长得一模一样的假阳性。在告警前先刻画自己的采集情况。

## 分诊流程

1. 在所有 DC 的语料中过滤 `TicketEncryptionType == 0x17` 的 4769。
2. 在 30 分钟窗口内按 `IpAddress` 与 `TargetUserName` 分组。统计每个来源的不同 `ServiceName`。
3. 30 分钟内单一来源以 0x17 请求超过 3 个不同 SPN，在几乎任何环境都是 kerberoasting。
4. 把源 IP 跳到其 [4624](/zh/blog/understanding-event-id-4624)，找出发起攻击的凭据。
5. 把被请求的 SPN 跳到拥有者服务账户。轮换其密码。在数小时（不是数天）内对被破解的哈希做复位。

## Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

`filter_machine` 排除以 `$` 结尾的计算机账户 SPN。Kerberoasting 只针对用户账户 SPN。

## KQL 与 Splunk

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK 对应

- T1558.003 Kerberoasting。标题。
- T1558.001 Golden Ticket。同 `LogonGuid` 没有 4768 的 4769。
- T1558.002 Silver Ticket。目标上有可观测的服务认证却没有 4769。
- T1078 Valid Accounts。已知服务账户在意料之外的 IP 上出现的 4769。
- T1550.003 Pass the Ticket。4769 之后紧随 `LogonProcessName: Kerberos` 的 [4624](/zh/blog/understanding-event-id-4624) LogonType 3。

## 你将会看到的误报

- 旧应用（部分老的 SQL Server 连接器、某些 Java/JBoss 应用）会显式请求 RC4。表现为来自一小撮稳定主机的稳定、白天的 0x17。建立基线并排除。
- Kerberos 强化迁移中的前 AES 域，会广泛产生 0x17，直到 `msDS-SupportedEncryptionTypes` 在每一个账户上都被设置。烦人，但不恶意。
- 漏洞扫描器（Tenable、Qualys、BloodHound 枚举脚本）会复现 kerberoasting 流量。给扫描器主机打标签。
- 跨林迁移中的账户迁移工具，可能请求异常的组合。

信号是*爆发*模式，不是单条记录。来自一台主机的稳定 0x17 是配置。来自一台主机、几分钟内对多个 SPN 的爆发式 0x17，就是攻击。

## 4769 没告诉你的事

记录里不包含加密票据本身。破解发生在攻击者外泄出去的东西上，不在 DC 的网络流量里。仅凭 4769 你无法分辨"票据被发放但从未使用"与"票据被破解、凭据被重用"。链路的后半段，需要目标服务上的 [4624](/zh/blog/understanding-event-id-4624)（LogonType 3、AuthenticationPackage Kerberos），最好再加上 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 显示凭据被重用之后跑了什么。把 4769 当作金丝雀，不要当作警报。

## 4769 在时间线中的位置

经典的入侵后 kerberoasting 链路：

1. 工作站上的 [4624](/zh/blog/understanding-event-id-4624)。被钓鱼凭据带来的初始接入。
2. **4769** ×N，从该工作站到一台 DC，全部 `etype=0x17`，全部在 5 分钟内针对带用户 SPN 的服务账户。Kerberoasting。
3. *(离线、不可见)*。攻击者在 Hashcat 中破解最弱服务账户的哈希。
4. [4768](/zh/blog/event-id-4768-kerberos-tgt)。以被攻陷的服务账户身份，在另一台主机上发出 TGT 请求。
5. 在高价值服务器上的 4624 LogonType 3，AuthenticationPackage Kerberos。
6. [7045](/zh/blog/service-creation-event-id-7045)。在被攻陷账户下安装服务用于持久化。

第 2 步的 4769 爆发，是你最早也最便宜的检测点。比攻击者作为服务账户回来要早数小时甚至数天。

## 延伸阅读

- [4769 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)
