---
title: "Event ID 4768 解读：Kerberos TGT 请求与 AS-REP roasting"
description: "4768 是 DC 对每一张发放出去的 TGT 的记录。通过结果码与预认证标志去读它，就能发现 AS-REP roasting、暴力破解，以及对非约束委派的滥用。"
date: "2026-05-24"
---

Event ID **4768**「请求了 Kerberos 认证票据（TGT）」在任何人请求一张票据授予票据时，于域控上触发。每一次域登录都从这里开始。把它和 [4769](/zh/blog/event-id-4769-kerberoasting)（服务票据）配在一起，你就能看到林中每一个账户完整的 Kerberos 生命周期。

在 DC 上，4768 是 [Security 通道](/zh/blog/what-is-an-evtx-file) 中仅次于 4624 体量最大的记录。多数是噪声。高信号的切片活在两个特定字段里，其中一个就是 AS-REP roasting 的指纹。

## 在哪里触发

与 [4769](/zh/blog/event-id-4769-kerberoasting) 一样，4768 只落在发放它的**域控**上。客户端看不到。目标服务也看不到。要从 4768 检测出什么，需要从每台 DC 收集 Security。一次性任务可以走 KAPE 风格，稳态环境用 WEF。

## 记录内容

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

重要字段：

- `TargetUserName`。请求 TGT 的账户。永远是用户或计算机账户。`ServiceName` 永远是 `krbtgt`。
- `Status`。Kerberos 结果码。`0x0` 是成功。失败才让 4768 有用：`0x6` 未知用户、`0x12` 客户端被锁、`0x17` 密码过期、`0x18` 密码错误。
- `TicketEncryptionType`。与 4769 同一套编码：`0x12` 与 `0x11` AES（现代），**`0x17` RC4**（旧式，也是 AS-REP roasting 的指纹）。
- `PreAuthType`。`2` 是标准的加密时间戳预认证。`0` 意味着**没有使用预认证**（AS-REP roasting 的前提）。`15`、`16`、`17` 是基于 PKINIT 证书的预认证值。
- `IpAddress`。请求方主机。配合客户端侧的 [4624](/zh/blog/understanding-event-id-4624) 拿到完整上下文。
- `CertIssuerName`、`CertSerialNumber`、`CertThumbprint`。PKINIT（智能卡或证书登录）下被填充。基于密码的登录则为空。

## 4768 揭示的两类攻击模式

### AS-REP roasting（T1558.004）

主用途。一些账户在 `userAccountControl` 中设置了 `DONT_REQUIRE_PREAUTH`（UAC bit 22 = `0x400000`）。对这些账户，DC 在响应 TGT 请求时**不**要求加密时间戳预认证。它返回的 AS-REP 中包含可被攻击者离线破解、恢复账户密码哈希的材料。

进行中的 AS-REP roast 在 4768 上的指纹：

- `PreAuthType = 0`（无预认证）。
- `TicketEncryptionType = 0x17`（RC4，破解工具需要的）。
- `Status = 0x0`（DC 痛快地发放了 AS-REP）。
- 常常聚簇出现。攻击者会一次性测试几十个账户，看哪些禁用了预认证。

带 `DONT_REQUIRE_PREAUTH` 的真实账户，几乎只为遗留兼容性而存在：非常老的 Unix Kerberos 客户端、一些古旧的设备。数量少、位置可预测。在与无预认证 Kerberos 无关的账户上出现的 `PreAuthType=0` 的 4768，就是信号。

### 密码暴力破解或喷洒

失败的 Kerberos 预认证产生 `Status=0x18`（"密码错误"）的 4768。与捕获 NTLM 失败的 [4625](/zh/blog/detecting-4625-brute-force) 不同，4768 才是基于 Kerberos 的密码攻击的归宿。现代工具集（Rubeus、kerbrute）直接说 Kerberos，因为 DC 对 NTLM 试探的失败响应比对 Kerberos 的更快也更安静，而许多 SOC 只盯着 4625。

4768 上的暴力破解指纹：

- 同一源 IP 在短窗内针对同一 `TargetUserName` 的多条 `Status=0x18`。暴力破解。
- 一个源 IP 在多个 `TargetUserName` 上各打一两次的多条 `Status=0x18`。密码喷洒。
- 同一来源先出现 `Status=0x6`（"未知用户"）爆发，再出现 `Status=0x18`。用户枚举先于暴力破解。

## 决定分诊的状态码

| Status | 含义 | 字段解读 |
|---|---|---|
| `0x0` | KDC_ERR_NONE | 成功。 |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | 用户名不存在。爆发 = 枚举。 |
| `0x12` | KDC_ERR_CLIENT_REVOKED | 账户被锁、禁用或过期。 |
| `0x17` | KDC_ERR_KEY_EXPIRED | 密码过期。 |
| `0x18` | KDC_ERR_PREAUTH_FAILED | 密码错误。爆发 = 暴力破解或喷洒。 |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | 在新的 TGT 请求时首先返回给客户端。真正的成功随后到来。不要仅凭它告警。 |
| `0x25` | KRB_AP_ERR_SKEW | 时钟漂移 > 5 分钟。常常是来自故意把时钟设错的主机的 AS-REP roasting 试探。 |

## 分诊流程：AS-REP roasting

1. 在所有 DC 上过滤 `PreAuthType == 0` AND `TicketEncryptionType == 0x17` 的 4768。
2. 按 `IpAddress` 分组。来自已知迁移主机的单一账户是配置。来自一个源的多账户是攻击。
3. 把每个 `TargetUserName` 跳到其 `userAccountControl`。`DONT_REQUIRE_PREAUTH` 真的需要设置吗？几乎肯定不需要。
4. 把源 IP 跳到该主机上的 [4624](/zh/blog/understanding-event-id-4624)，找出发起攻击所用的凭据。
5. 轮换每个被破解账户的密码。把不需要 `DONT_REQUIRE_PREAUTH` 的账户上的它移除。

## 分诊流程：Kerberos 暴力破解

1. 过滤 `Status == 0x18` 的 4768。
2. 在 15 分钟窗口内按 `IpAddress` 分组。统计不同的 `TargetUserName`。
3. 15 分钟内单一来源超过 5 个账户是喷洒。同窗口内对单一账户超过 10 次失败是暴力破解。
4. 与同一来源的 `Status == 0x6` 做交叉。暴力破解前的枚举是教科书顺序。

## Sigma：AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL：Kerberos 密码喷洒

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk：AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK 对应

- T1558.004 AS-REP Roasting。基于 `PreAuthType=0 + etype=0x17` 的主检测。
- T1110 Brute Force 及子技术 `.001` Password Guessing 与 `.003` Password Spraying。`Status=0x18` 模式。
- T1558.001 Golden Ticket。伪造 TGT 会完全绕过 4768。这里的检测靠*缺失*：与同一来源、同一窗口的前置 4768 缺失而出现的 [4769](/zh/blog/event-id-4769-kerberoasting)，就是怀疑。
- T1187 Forced Authentication。在 4768 中并不直接可见，但随之而来的 TGT 请求会出现。

## 看似攻击的误报

- 老旧的 Java 或 Unix Kerberos 栈在遗留应用筒仓中，有时默认无预认证且使用 RC4。它们表现为稳定主机在白天的稳定 4768 流量。建立基线。
- 智能卡推广期的 PKINIT 迁移。如果你没见过，合法的 `PreAuthType=15/16/17` 切换看起来会很反常。注意推广窗口。
- Kerberos 库的 bug。某些客户端在时钟漂移时积极地重新请求 TGT，产生噪声。与 `Status=0x25` 做交叉。
- 跨域信任穿越。跨林认证两边都会产生 4768。`IpAddress` 是另一林的 DC。给它打标签。

## 4768 没告诉你的事

记录里不包含攻击者真正拿走、用于离线破解的 AS-REP 材料。你只看到请求被发出。除了元数据，看不到返回了什么。你也看不到客户端视角：哪个应用发起了请求，运行在哪个用户上下文中。要看这个，你需要客户端侧的 [4624](/zh/blog/understanding-event-id-4624)，以及当 `kerbrute.exe` 或 Rubeus 在本地运行时的 [4688](/zh/blog/event-id-4688-process-creation)。

也要注意，4768 仅在初次 TGT 请求与续期时触发。一旦客户端在缓存中持有有效 TGT，在续期前它就不会再为 TGT 找 KDC。它派生出的服务票据会产生 [4769](/zh/blog/event-id-4769-kerberoasting)，而不是 4768。盗取了长期 TGT（金票）的攻击者，可以在不再生成另一条 4768 的情况下任意发出 4769。

## 4768 在时间线中的位置

AS-REP roasting 从头到尾：

1. [4624](/zh/blog/understanding-event-id-4624)。初次低权限域登录（被钓鱼的凭据）。
2. *(LDAP，如果设置了 SACL，可能是一条 4662)*。攻击者枚举 `userAccountControl`，找带 `DONT_REQUIRE_PREAUTH` 的账户。
3. **4768** 爆发。对每个候选账户的 `PreAuthType=0`、`etype=0x17`、`Status=0x0`。检测点。
4. *(离线、不可见)*。攻击者在 Hashcat 中（模式 18200）破解恢复出来的 AS-REP 材料。
5. **4768**。以被攻陷账户身份发出的新 TGT 请求，这次是正常预认证的。
6. [4769](/zh/blog/event-id-4769-kerberoasting)。被攻陷账户能触达的所有服务的服务票据。
7. 目标服务上的 [4624](/zh/blog/understanding-event-id-4624) LogonType 3。

第 3 步是金丝雀。第 5 步起才是真正的入侵。两者之间的窗口——几分钟到几天——是防御方在凭据真正活跃在野外之前唯一能行动的窗口。

## 延伸阅读

- [4768 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)
