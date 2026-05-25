---
title: "Event ID 4769 详解:Kerberos 服务票据与 kerberoasting"
description: "4769 是 DC 对每次服务票据请求的记录。从加密类型读它,你能发现 kerberoasting;和 4768 一起读,你能发现 pass-the-ticket。"
date: "2026-05-24"
---

Event ID **4769** ——「请求了 Kerberos 服务票据」—— 每当任何账号为某个服务请求一张 TGS(Ticket Granting Service)票据时,就会在每台域控上触发。每个 SMB 连接、每个 SQL 登录、每个 Web SSO 命中都会在处理请求的那台 DC 上产生一条这样的记录。它是繁忙 DC 上量最大的 [Security 通道](/zh/blog/what-is-an-evtx-file)记录 —— 也是在凭证被离线破解之前,kerberoasting 唯一可靠出现的地方。

如果你只能在域控上仪表化三条 Security 记录,这就是其中之一。

## 它在哪里

`4769` 写入**颁发域控**的 `Security` 通道 —— 不是客户端,也不是目标服务。要看到一个域所有 4769 记录,必须从每台 DC 采集。DC 上的 KAPE `EventLogs` target,或通过 WEF 把 `Security` 转发到收集器,都行;大多数成熟组织走 WEF 路线。

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

驱动分诊的字段:

- **`TargetUserName`** —— *请求方*(用户账户,形如 `user@DOMAIN`)。
- **`ServiceName`** —— 被请求的 SPN。这里是用户账户(而不是 `host/...` 或某个服务类)就可疑。
- **`TicketEncryptionType`** —— 决定这条记录是否重要的值。现代域跑的是 `0x12`(AES-256-CTS-HMAC-SHA1-96)或 `0x11`(AES-128)。**`0x17` 是 RC4-HMAC** —— 遗留、弱,而且是 Mimikatz/Rubeus 的 `kerberoast` 模式*唯一*请求的加密类型。针对服务账号票据的、`0x17` 的 4769 就是教科书级的 kerberoasting 指纹。
- **`Status`** —— `0x0` 是成功;其它是被拒(状态码在 `[MS-KILE]` 中有文档)。
- **`IpAddress`** —— 请求主机。和该主机上的 [4624](/zh/blog/understanding-event-id-4624) 配对,看产生会话的登录。

## TicketEncryptionType —— 决定一切的字段

简表如下:

| 值 | 算法 | 状态 |
|---|---|---|
| 0x01 | DES-CBC-CRC | 自 Win7 起默认禁用 |
| 0x03 | DES-CBC-MD5 | 自 Win7 起默认禁用 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | 现代 |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | 现代(大多数账号的默认) |
| **0x17** | **RC4-HMAC-MD5** | **遗留。kerberoasting 必需。** |
| 0x18 | RC4-HMAC-EXP | 出口级 RC4,极罕见 |

如果域已基线化,并且服务账号的 `msDS-SupportedEncryptionTypes` 设为仅 AES,这些账号就根本不该出现 `0x17`。攻击者显式请求 `0x17`,因为破解 RC4 加密的服务票据计算成本很低;AES 不是。破解工具需要 RC4 哈希,所以请求*必须*是 0x17。

这是整条记录上信号最强的字段。

## kerberoasting 模式

Kerberoasting(MITRE T1558.003)的过程:

1. 攻击者用任意域用户账号认证(无需管理员)。
2. 攻击者枚举注册在用户账号(非计算机账号)上的 SPN,通常通过 LDAP `(servicePrincipalName=*)` 过滤到用户对象。
3. 攻击者用 `etype=23`(RC4)通过标准 Kerberos 协议为每个 SPN 请求 TGS。**这就是你要找的 4769。**
4. DC 高兴地颁发票据,用*服务账号的* NTLM 哈希加密。
5. 攻击者从内存(或线缆上)拉出加密的 blob,用 Hashcat(`-m 13100`)离线破解。

4769 指纹:

- `ServiceName` 是 `MSSQLSvc/...`、`HTTP/...`、`LDAP/...`,或任何指向*用户*账户的 SPN(而不是计算机账号的 `host/...` 或 `cifs/...`)。
- `TicketEncryptionType` 是 `0x17`。
- 同一来源在短时窗口内对许多 SPN 发起的爆发请求,就是铁证。

第二个相关模式 —— **AS-REP roasting**(T1558.004)—— 使用 [4768](/zh/blog/event-id-4768-kerberos-tgt)(TGT 请求)代替,针对设置了 `DONT_REQUIRE_PREAUTH` 的账号。不同记录,同一攻击家族。

## Pass-the-ticket / 黄金 / 白银票据

4769 也揭示票据伪造,但信号更微妙。

- 同主机同一 `LogonGuid` 在合理窗口内*没有*先前的 4768(TGT 请求)却有 4769 —— **黄金票据**嫌疑。攻击者出示了伪造的 TGT,直接走 TGS 请求,从不真正请求过 TGT。
- 目标上有 4769 *以及*由此而来的服务认证,但任何 DC 上都*没有*可见的 4769 —— **白银票据**嫌疑。攻击者直接伪造了 TGS;DC 从未被询问。
- 目标服务上的 4624 与据称颁发票据的 4769 之间 `LogonGuid` 不匹配 —— 伪造票据。

这些是按*缺失*检测的模式,这意味着它们需要跨所有 DC 和目标服务的完整日志覆盖。WEF 覆盖缺口会产出一模一样的误报;告警前先刻画你的采集。

## 分诊流程

1. 在 DC 语料库的所有 4769 中筛 `TicketEncryptionType == 0x17`。
2. 按 30 分钟窗口按 `IpAddress` 和 `TargetUserName` 分组。统计每个来源的不同 `ServiceName`。
3. 30 分钟内同一来源 >3 个不同的 SPN 以 0x17 请求,几乎在哪里都是 kerberoasting。
4. 把源 IP 透视到原始主机上的 [4624](/zh/blog/understanding-event-id-4624) —— 找出发起攻击的凭证。
5. 把被请求的 SPN 透视到拥有它们的服务账号。轮换这些密码。在小时级而不是天级内重置被破解的哈希。

## Sigma 规则样例

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

`filter_machine` 子句排除计算机账户 SPN(总以 `$` 结尾);kerberoasting 只针对用户账户的 SPN。

## KQL / Splunk 样例

KQL(经 `SecurityEvent` 接入 Defender XDR / Sentinel):

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

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK 对应

4769 语料覆盖:

- **T1558.003 —— Kerberoasting**:头号用例。
- **T1558.001 —— Golden Ticket**:同一 `LogonGuid` 没有 4768 的 4769。
- **T1558.002 —— Silver Ticket**:目标上观察到服务认证而没有对应 4769。
- **T1078 —— Valid Accounts**:已知服务账号来自非预期 IP 的 4769。
- **T1550.003 —— Pass the Ticket**:4769 后跟着带 `LogonProcessName: Kerberos` 的 [4624](/zh/blog/understanding-event-id-4624) LogonType 3。

## 你会遇到的误报

- **遗留应用**(某些老 SQL Server 连接器、某些 Java/JBoss 应用)显式请求 RC4。它们表现为来自一小群稳定主机的稳定、白天 0x17 流量。基线化并排除。
- **预 AES 域**在 Kerberos 加固迁移期间会广泛发出 0x17,直到每个账号都设了 `msDS-SupportedEncryptionTypes`。烦人;非恶意。
- **漏洞扫描器**(Tenable、Qualys、BloodHound 枚举脚本)会复制 kerberoasting 流量。给扫描器主机打标签。
- **账户迁移工具**在跨林移动期间可能请求异常的票据组合。

信号是*爆发*模式,不是单条记录。同一主机稳定的 0x17 是配置;某主机几分钟内对很多 SPN 爆发的 0x17 才是攻击。

## 4769 不会告诉你的东西

记录不包含加密的票据本身 —— 破解发生在攻击者外泄的东西上,不是 DC 出来的线上数据。仅凭 4769,你无法区分「票据颁发了但从未使用」和「票据被破解,凭证被重用」。后半段链需要目标服务上由此产生的 [4624](/zh/blog/understanding-event-id-4624)(LogonType 3,AuthenticationPackage Kerberos),最好还有 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 显示凭证被重用后跑了什么。把 4769 当金丝雀,不要当警铃。

## 4769 在时间线中的位置

经典后渗透 kerberoasting 链:

1. [**4624**](/zh/blog/understanding-event-id-4624) 工作站上 —— 通过被钓鱼的用户凭证初始接入。
2. **4769** ×N 从该工作站 IP 到一台 DC,全部 `etype=0x17`,5 分钟内全部针对用户 SPN 服务账号 —— kerberoasting。
3. *(离线、不可见)* —— 攻击者在 Hashcat 中破解最弱的服务账号哈希。
4. **4768** —— 以被攻陷服务账号身份发起 TGT 请求,来自另一台主机。
5. **4624** 高价值服务器上的 LogonType 3,AuthenticationPackage Kerberos,使用该服务账号。
6. [**7045**](/zh/blog/service-creation-event-id-7045) —— 以被攻陷账号身份为持久化安装服务。

第 2 步的 4769 爆发是你最早、最便宜的检测点 —— 比攻击者以服务账号身份回来要早几小时到几天。
