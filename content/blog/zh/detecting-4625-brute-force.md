---
title: "Event ID 4625 解读：检测暴力破解、喷洒与枚举"
description: "4625 是登录失败记录。读得对，你能在它演变为成功之前发现密码喷洒、撞库和 Kerberos 滥用。"
date: "2026-05-17"
---

Event ID 4625「账户登录失败」在每一次认证尝试被拒绝时触发于 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。它是当场抓获凭据攻击最有用的一条记录，同时也是分析师最容易误读的一条，因为主消息很泛，答案在更深两层的字段里。

## 决定判断的字段

一条典型记录：

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` 与 `SubStatus` 一起告诉你登录失败的原因。真正要关心的那一对是 `SubStatus`。值得记住的代码：

- `0xC0000064`：账户不存在。用户名枚举。
- `0xC000006A`：密码错误。经典。
- `0xC0000234`：账户被锁定。
- `0xC0000072`：账户被禁用。
- `0xC0000071`：密码过期。
- `0xC0000133`：Kerberos 时钟漂移。常见于攻击者刻意伪造时钟的 AS-REP roasting 尝试。
- `0xC000018B`：SID 错。工作站以为自己在某个其实不在的域里。少见而有趣。

混合有效和无效用户名的 `0xC0000064` 爆发是侦察。针对一个账户的 `0xC000006A` 爆发是暴力破解。针对多个账户、用*同一个*密码的 `0xC000006A` 爆发是喷洒。同一个 Event ID，三种不同的事件。

## 物有所值的分诊查询

1. 喷洒检测。按 `IpAddress`（如果 IP 字段为空则按 `WorkstationName`）对 4625 分组，统计 10 分钟内不同的 `TargetUserName`。该窗口内单一来源对 5 个以上账户，在几乎任何环境都可疑。
2. 暴力破解。按 `TargetUserName` 分组，统计每分钟的失败数。每分钟超过 10 次针对一个账户，几乎一定是自动化的。
3. 锁定根因。把 4740（账户锁定）与前面紧邻的 4625 配对。`WorkstationName` 字段会告诉你是哪台设备触发了锁定。多数情况下是带着过期缓存凭据的域加入服务器，而不是攻击者。分诊重要是因为帮助台对两者处理方式相同，SOC 必须决定升级哪一个。

## "之后"决定响应

来自同一 `IpAddress` 的 4625 爆发之后紧跟一个 [4624](/zh/blog/understanding-event-id-4624)，是真正要采取行动的情形。攻击者找到了一组可用凭据。时间线上的演进毫无悬念：密集失败、突然沉默、单次成功。

## Sigma：密码喷洒

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
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

## KQL：针对单个账户的暴力破解

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk：从枚举走向暴力

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

信号是*演进*本身：先枚举找到有效用户名，再做定向密码尝试。一个手里有新鲜用户名列表的真实操作者，会在几分钟内把这两种形态都展现出来。

## ATT&CK 对应

- T1110.001 Brute Force: Password Guessing。针对单一账户的大量 `0xC000006A` 失败。
- T1110.003 Brute Force: Password Spraying。多账户，单一来源，每个账户失败次数很少。
- T1110.004 Credential Stuffing。多账户，单一来源，`0xC0000064`（账户不存在，泄漏列表未命中）与 `0xC000006A`（命中）混合。
- T1078 Valid Accounts。同一来源的 4625 爆发后紧跟 [4624](/zh/blog/understanding-event-id-4624) 成功。沦陷。
- T1556 Modify Authentication Process。异常的 `LogonProcessName`（不是 `User32`、`NtLmSsp`、`Kerberos`、`Advapi`、`Schannel` 中的任何一个）暗示存在篡改。

## 装扮成攻击的误报

- 密码变更后的缓存凭据变陈旧。用户映射的驱动器、计划任务或服务配置在用旧密码反复重试。形态是一个 `TargetUserName`、一个 `IpAddress`、稳定的 `0xC000006A` 节奏。在告警前先找到那台带陈旧凭据的主机并修好。
- 配置错误的自动化。错密码的脚本在循环重试。和暴力破解形态一样。先去和负责人沟通。
- 漏洞扫描器在认证扫描期间产生密集的 4625 流量。给扫描器 IP 打标签。
- 锁定策略扰动。帮助台积极的解锁流程会制造重复的 4625 到 4740 到 4624 循环。烦人。但无恶意。

## 4625 隐藏了什么

通过 DC 的 Kerberos 与 NTLMv2 失败，未必都带有有用的 `IpAddress`。该字段可能为空或 `-`。对于这些，转去看 DC 的记录：Kerberos 预认证失败的 [4768](/zh/blog/event-id-4768-kerberos-tgt) 与 4771。"没有源 IP，就不调查" 是错误的直觉。请去看 DC 的日志。

`LogonProcessName` 与 `AuthenticationPackageName` 字段告诉你是哪个认证栈处理了这次尝试。有用的值：`NtLmSsp`（NTLM）、`Kerberos`、`Negotiate`（择其一）、`User32`（本地控制台）、`Schannel`（基于 TLS）。其他的，再仔细看。

## 延伸阅读

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
