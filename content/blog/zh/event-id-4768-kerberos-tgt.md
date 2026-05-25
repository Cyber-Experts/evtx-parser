---
title: "Event ID 4768 详解:Kerberos TGT 请求与 AS-REP roasting"
description: "4768 是 DC 对每次 TGT 颁发的记录。从结果码和预认证标志读它,你能发现 AS-REP roasting、爆破和非约束委派滥用。"
date: "2026-05-24"
---

Event ID **4768** ——「请求了 Kerberos 身份认证票据(TGT)」—— 每当有人请求一张票据授予票据时,就会在域控上触发。每一次域登录都从这样一个请求开始。把它和 [4769](/zh/blog/event-id-4769-kerberoasting)(服务票据)配对,你就看到了林中每个账号完整的 Kerberos 生命周期。

在 DC 上,4768 是仅次于 4624 的最高量 [Security 通道](/zh/blog/what-is-an-evtx-file)记录。其中大部分是噪声;高信号的切片活在两个特定字段里 —— 其中一个就是 AS-REP roasting 的指纹。

## 它在哪里触发

和 [4769](/zh/blog/event-id-4769-kerberoasting) 一样,4768 只落在颁发的**域控**上。客户端看不到,目标服务也看不到。要从 4768 检测出任何东西,你需要从每台 DC 采集 Security —— 一次性任务用 KAPE 风格,持续运行用 WEF。

## 记录里有什么

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

重要的字段:

- **`TargetUserName`** —— 请求 TGT 的账号。总是用户或计算机账号;`ServiceName` 总是 `krbtgt`。
- **`Status`** —— Kerberos 结果码。`0x0` 是成功。失败才让 4768 有用:`0x6` = 未知用户、`0x12` = 客户端被锁定、`0x17` = 密码过期、`0x18` = 密码错误。
- **`TicketEncryptionType`** —— 和 4769 同一种编码:`0x12`/`0x11` AES(现代),**`0x17` RC4**(遗留,也是 AS-REP roasting 的指纹)。
- **`PreAuthType`** —— `2` 是标准的加密时间戳预认证;`0` 意味着**没有使用预认证**(AS-REP roasting 的前提条件);`15`/`16`/`17` 是基于证书的 PKINIT 预认证值。
- **`IpAddress`** —— 请求主机。配对该主机上客户端侧的 [4624](/zh/blog/understanding-event-id-4624) 看完整上下文。
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** —— PKINIT(智能卡 / 证书登录)时填充。基于密码的登录为空。

## 4768 揭示的两个攻击模式

### 1. AS-REP roasting(T1558.004)

头号用途。某些账号在 `userAccountControl` 中设置了 `DONT_REQUIRE_PREAUTH` 标志(UAC 第 22 位 = `0x400000`)。对这些账号,DC 在响应 TGT 请求时**不**要求加密时间戳预认证 —— 这意味着它返回的 AS-REP 中包含可被攻击者离线破解以恢复该账号密码哈希的材料。

正在进行的 AS-REP roast 的 4768 指纹:

- `PreAuthType` 是 `0`(无预认证)。
- `TicketEncryptionType` 是 `0x17`(RC4 —— 破解工具需要的)。
- `Status` 是 `0x0`(DC 高兴地颁发了 AS-REP)。
- 常成簇:攻击者会批量测试几十个账号,看哪些禁用了预认证。

带 `DONT_REQUIRE_PREAUTH` 的真实账号几乎只为遗留兼容存在(非常老的 Unix Kerberos 客户端,某些上古设备)。它们数量极少且位置可预测。一条 `PreAuthType=0` 的 4768,目标是一个*不该*使用无预认证 Kerberos 的账号,就是信号。

### 2. 基于密码的爆破 / 喷洒

失败的 Kerberos 预认证产生 `Status=0x18`(「密码错误」)的 4768。和 [4625](/zh/blog/detecting-4625-brute-force)(捕获 NTLM 失败)不同,4768 是基于 Kerberos 的密码攻击落地的地方。现代工具(Rubeus、kerbrute)直接说 Kerberos,因为 DC 对 NTLM 尝试的失败比对 Kerberos 的回应更快 —— 而许多 SOC 只看 4625。

4768 爆破指纹:

- 短时间窗口内同一源 IP 针对同一 `TargetUserName` 多次 `Status=0x18` —— 经典爆破。
- 同一源 IP 跨多个 `TargetUserName` 多次 `Status=0x18`,每个账号一两次 —— 密码喷洒。
- 同一来源在 `Status=0x18` 之前一阵 `Status=0x6`(「未知用户」)—— 爆破前的用户枚举得到确认。

## 你会看到的 Status 码

完整列表很长;驱动分诊的是这些:

| Status | 含义 | 实际通常意味着什么 |
|---|---|---|
| `0x0` | KDC_ERR_NONE | 成功。 |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | 用户名不存在。爆发 = 枚举。 |
| `0x12` | KDC_ERR_CLIENT_REVOKED | 账户被锁定 / 禁用 / 过期。 |
| `0x17` | KDC_ERR_KEY_EXPIRED | 密码过期。 |
| `0x18` | KDC_ERR_PREAUTH_FAILED | 密码错误。爆发 = 爆破或喷洒。 |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | 新 TGT 请求时*先*返回给客户端的;之后会跟一次真正成功。不要单独告警。 |
| `0x25` | KRB_AP_ERR_SKEW | 客户端与 DC 时钟偏差 > 5 分钟。常见于故意设错时钟的主机做 AS-REP roasting。 |

## 分诊流程 —— AS-REP roasting

1. 对全部 DC 的 4768 筛 `PreAuthType == 0` 且 `TicketEncryptionType == 0x17`。
2. 按 `IpAddress` 分组。来自已知迁移主机的单账号是配置;同一来源多账号才是攻击。
3. 把每个 `TargetUserName` 透视到它的 `userAccountControl` —— `DONT_REQUIRE_PREAUTH` 真的需要置位吗?几乎一定不需要。
4. 源 IP → 该主机上的 [4624](/zh/blog/understanding-event-id-4624) 找出发起攻击所用的凭证。
5. 轮换每个被破解账号的密码;从不需要的账号上去掉 `DONT_REQUIRE_PREAUTH`。

## 分诊流程 —— Kerberos 爆破

1. 筛 4768 中 `Status == 0x18`。
2. 按 15 分钟窗口按 `IpAddress` 分组;统计不同 `TargetUserName`。
3. 15 分钟内同一来源 >5 个账号是喷洒;同一窗口同一账号 >10 次失败是爆破。
4. 同来源对比 `Status == 0x6` —— 爆破前枚举是教科书顺序。

## Sigma 规则样例 —— AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL 样例 —— Kerberos 密码喷洒

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk 样例 —— AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK 对应

- **T1558.004 —— AS-REP Roasting**:以 `PreAuthType=0 + etype=0x17` 为头号检测。
- **T1110 —— Brute Force** 及子技术 `.001` Password Guessing 和 `.003` Password Spraying —— `Status=0x18` 模式。
- **T1558.001 —— Golden Ticket**:伪造的 TGT 完全绕过 4768。这里靠*缺失*检测 —— 同来源/窗口内没有先前 4768 的 [4769](/zh/blog/event-id-4769-kerberoasting)(TGS 请求)就是嫌疑。
- **T1187 —— Forced Authentication**:在 4768 中不直接可见,但由此产生的 TGT 请求会可见。

## 看起来像攻击的误报

- **老 Java / Unix Kerberos 栈**在遗留应用孤岛中有时默认不带预认证的 RC4。它们表现为来自稳定主机的稳定、白天 4768 流量。基线化。
- **PKINIT 迁移**期间智能卡推广:合法的 `PreAuthType=15/16/17` 在你没见过时看着像异常。注意推广窗口。
- **Kerberos 库 bug**:某些客户端在时钟偏差时会积极重新请求 TGT,产生噪声。和 `Status=0x25` 交叉对照。
- **域信任穿越**:跨林认证在两侧都产生 4768。`IpAddress` 是另一片林的 DC;标记它。

## 4768 不会告诉你的东西

记录**不**包含攻击者捕获的实际 AS-REP 材料(那是他们离线破解的东西)。你看到请求被颁发;除了元数据,你看不到返回了什么数据。你也看不到*客户端*视角 —— 什么应用发起了请求、在哪个用户上下文里运行,等等。后者要看客户端侧的 [4624](/zh/blog/understanding-event-id-4624)(以及如果 `kerbrute.exe` 在本地运行,还要 [4688](/zh/blog/event-id-4688-process-creation))。

还要注意 4768 仅在*初次* TGT 请求和续约时触发。客户端缓存了有效 TGT 后,在续约前不再和 KDC 通信;它派生出的*服务*票据产生 [4769](/zh/blog/event-id-4769-kerberoasting),而不是 4768。这两条记录描述同一协议的不同阶段 —— 偷了长寿命 TGT(黄金票据)的攻击者可以任意发出 4769,永远不再产生 4768。

## 4768 在时间线中的位置

AS-REP roasting 从头到尾的链:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— 初始低权限域登录(被钓鱼凭证)。
2. *(LDAP,有时是 4662 如果 SACL 已设)* —— 攻击者枚举带 `DONT_REQUIRE_PREAUTH` 的账号 `userAccountControl` 标志。
3. **4768** 爆发 —— 对每个候选账号 `PreAuthType=0`、`etype=0x17`、`Status=0x0`。**这是检测点。**
4. *(离线、不可见)* —— 攻击者在 Hashcat(mode 18200)中破解恢复的 AS-REP 材料,获得明文密码。
5. **4768** —— 以被攻陷账号身份发起新的 TGT 请求,这次正常预认证。
6. [**4769**](/zh/blog/event-id-4769-kerberoasting) —— 该账号能访问的所有服务的票据。
7. [**4624**](/zh/blog/understanding-event-id-4624) 目标服务上的 LogonType 3。

第 3 步是金丝雀。从第 5 步开始才是真正的攻陷。它们之间的窗口 —— 几分钟到几天 —— 是防御者在凭证流入野外之前唯一能动作的时间窗。
