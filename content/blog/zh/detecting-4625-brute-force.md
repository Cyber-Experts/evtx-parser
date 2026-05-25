---
title: "Event ID 4625 详解:检测爆破、密码喷洒与账户枚举"
description: "4625 是登录失败记录。读对了,你能在攻击得手前发现密码喷洒、凭证填充和 Kerberos 滥用。"
date: "2026-05-17"
---

Event ID 4625 ——「账户登录失败」—— 每当一次身份认证尝试被拒绝时,就会写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。它是捕获凭证攻击活动最有用的一条记录 —— 前提是你读对了字段。

## 真正重要的字段

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

`Status` 和 `SubStatus` 的组合告诉你登录失败的*原因*:

- `0xc0000064` —— 账户不存在(用户名枚举)。
- `0xc000006a` —— 密码错误(经典)。
- `0xc0000234` —— 账户被锁定。
- `0xc0000072` —— 账户被禁用。
- `0xc0000071` —— 密码过期。
- `0xc0000133` —— Kerberos 票据时钟偏差(AS-REP roasting 常见)。
- `0xc000018b` —— SID 错误 —— 工作站并不在它以为的那个域里。

针对有效和无效用户名的一阵 `0xc0000064` 是侦察。针对一个账号的一阵 `0xc000006a` 是爆破。针对许多账号、用*同一个密码*的一阵 `0xc000006a` 是密码喷洒。

## 检测模式

最简单的分诊查询:

1. **喷洒检测**:把 4625 记录按 `IpAddress` 分组(没有 IP 时按 `WorkstationName`),统计 10 分钟窗口内不同 `TargetUserName` 的数量。同一来源在这个窗口内 >5 个账号,几乎在哪里都算可疑。
2. **爆破**:按 `TargetUserName` 分组,统计每分钟失败次数。针对单账号 >10 次/分钟,通常是机器人。
3. **锁定根因**:把 4740(账户被锁定)和前置的 4625 配对 —— `WorkstationName` 字段会显示哪台设备触发了锁定,这非常关键,因为常常是某台域加入服务器存有过期凭证,而不是攻击者。

## 「之后」和「之前」同样重要

一阵 4625 之后从同一 `IpAddress` 出现一条 [4624](/zh/blog/understanding-event-id-4624) 才是要立刻处置的情况 —— 攻击者找到了一组有效凭证。本页面的解析器允许你把表格筛选到某个源 IP,并在时间线上观察级别与事件 ID 随时间的跳变。爆破后紧跟一个峰值的模式很显眼。

## Sigma 规则样例 —— 密码喷洒

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL 样例 —— 针对单账号的爆破

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk 样例 —— 爆破前的枚举

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

信号在于*演进*顺序 —— 先枚举确定有效用户名,再对这些账号爆破。

## ATT&CK 对应

- **T1110.001 —— Brute Force: Password Guessing**:单账号,多次 `0xC000006A` 失败。
- **T1110.003 —— Brute Force: Password Spraying**:多账号,单账号失败次数少,单一来源。
- **T1110.004 —— Brute Force: Credential Stuffing**:多账号、单一来源,泄露名单未命中时常见 `0xC0000064`(账号不存在),与 `0xC000006A` 命中交织。
- **T1078 —— Valid Accounts**:4625 之后同一来源出现 [4624](/zh/blog/understanding-event-id-4624) 成功 = 被攻陷。
- **T1556 —— Modify Authentication Process**:异常的 `LogonProcessName`(除 `User32`、`NtLmSsp`、`Kerberos`、`Advapi`、`Schannel` 之外的值)提示认证机制被篡改。

## 看起来像攻击的误报

- **存储凭证过期** —— 密码改了之后,用户的映射驱动器、计划任务或服务账号配置还在用旧密码重试。模式是:一个 `TargetUserName`,一个 `IpAddress`(有时是一个 `WorkstationName`),稳定的 `0xC000006A` 节律。定位那台存有过期凭证的主机并修复。
- **配置错误的自动化**:某个脚本用错密码在循环里重试。形态和爆破一样;告警前先问问负责人。
- **漏洞扫描器**在带认证扫描时会产生密集的 4625 流量。给扫描器 IP 打标签。
- **锁定策略配置错误**:解锁过激的帮助台流程会产生重复的 4625 → 4740 → 4624 循环。

## 4625 里看不到的东西

来自域控的 NTLMv2 和 Kerberos 失败,`IpAddress` 不一定能用 —— 该字段可能为空或为 `-`。这种情况要看对应的 DC 事件(Kerberos 预认证失败看 [4768](/zh/blog/event-id-4768-kerberos-tgt)/4771),或网络层数据。不要因为「没有源 IP」就放弃调查 —— 转向 DC 通道。

`LogonProcessName` 和 `AuthenticationPackageName` 告诉你这次尝试被哪个认证栈处理。最有用的是 `NtLmSsp`(NTLM)、`Kerberos` 和 `Negotiate`(在两者中选一)。`User32` 是本地控制台;`Schannel` 是基于 TLS 的。
