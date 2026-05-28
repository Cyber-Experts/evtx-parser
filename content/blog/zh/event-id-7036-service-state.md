---
title: "Event ID 7036 解读：用于 DFIR 分诊的服务状态变更"
description: "7036 在服务每次启动或停止时触发。与 7045 配对，它确认持久化是否真的跑起来了。单独来看，也能揭示服务滥用、防御规避与启动期异常。"
date: "2026-05-24"
---

Event ID **7036**「{service} 服务进入了 {state} 状态」在 Service Control Manager 看到服务发生转移时触发于 [`System` 通道](/zh/blog/what-is-an-evtx-file)。启动、停止、暂停、恢复每一次都会产生一条。单独来看体量大、容易被忽视。与 [7045](/zh/blog/service-creation-event-id-7045) 搭配，它就是"安装了后门"与"安装了后门并跑了起来"之间的区别。

对应急响应来说，这是操作系统能给你的、成本最低的"是否执行了"记录。

## 它住在哪里

它住在该服务运行所在主机的 `System` 通道。不涉及 DC、不必担心按通道转发。它就在 `System.evtx` 里。Provider：`Service Control Manager`。

## 记录的内容

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

就这些。两个参数和一个二进制标签。比大多数 Security 记录小得多，这也是分析师会跳过它的原因。

- `param1`。服务的*显示名*（不是短名）。这里的 `Background Intelligent Transfer Service` 是 `BITS` 给用户看的名字。要跳到服务定义，通常需要短名。SCM 把短名以 UTF-16 blob 的形式塞进 `Binary`（`42 00 49 00 54 00 53 00` 解码为 `BITS`）。
- `param2`。新状态：`running`、`stopped`、`paused`、`resumed`，或挂起的中间态（`start pending`、`stop pending`）。多数规则盯的是 `running` 与 `stopped`。

没有 `AccountName`，没有 `ImagePath`，没有 `ProcessId`。7036 告诉你*什么*变了状态，而不是*谁*触发的。要知道为什么，得配合其他记录。

## 7036、7045、7035、7034：分别是什么

System 通道里关于服务的四个事件经常被混淆：

| 事件 | 何时 | 提供什么 |
|---|---|---|
| **7045** | 服务被安装 | 显示名、短名、`ImagePath`、`AccountName`、`StartType`。持久化点。 |
| **7036** | 服务启动/停止 | 仅显示名。执行点。 |
| **7035** | 发出服务控制 | 谁发起的 start/stop（SID）、发了什么控制。默认通常关闭。 |
| **7034** | 服务意外崩溃 | 服务未经清理地终止。 |

模式很重要：在同一显示名上，7045 之后几秒出现 `running` 的 7036，就是教科书式的"已安装并已运行"序列。一个没有对应 7036 的 7045，意味着服务被注册但未执行：要么攻击者收拾掉了，要么安装程序中止了，要么启动被推迟。

数分钟内没有 `running` 7036 的 7045 本身就是异常。请调查安装为何未触发。常见原因：等待下次启动、设为手动启动而攻击者还未触发、启动失败（找 7034 / 7000 错误）。

### 防御规避：停掉安全服务

最常被滥用的模式。攻击者停掉 `WinDefend`、`MsMpEng`、`Sense`、`SecurityHealthService`、`EventLog`、`WdNisSvc`，或某款 EDR 产品的服务。每一次都会为对应显示名生成一条 `stopped` 的 7036。当审计策略或 Defender 被尝试篡改时，这是能存活下来的记录之一。

值得告警的名字（显示名；随 Defender 或 EDR 版本变化）：

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- 匹配 `*CrowdStrike*`、`*SentinelOne*`、`*Carbon*`、`*Cylance*`、`*Sophos*`、`*ESET*`、`*Symantec*` 的任何项

针对其中任一的 `stopped` 7036，尤其在计划维护窗口之外，应当是硬告警。许多攻击者会用 `sc stop`、`net stop`、`Stop-Service` 或 `taskkill /im`。这四种都会产生 7036。

### 服务名抢注

7036 按显示名触发，即便底层服务是恶意的。注意那些看起来合法但与任何已安装 Microsoft 服务都不匹配的显示名：`Windows Update Service`（真名是 `Windows Update`）、`Windows Defender Service`（真名是 `Windows Defender Antivirus Service`）、`Microsoft Telemetry`（根本没这个服务）。从已知良好的主机上为显示名建立基线并对比差异。

### 启动期异常

重启后，SCM 会以大致稳定的顺序起来自动启动服务。在启动期的 7036 序列里出现一个新的自动启动服务，特别是上一次启动里没有的，就是一个新的持久化点。把它与上一次关机及之前的 7045 对照。

## Sigma：安全服务被停

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL：7045 到 7036 的序列

核心枢纽。同一主机上持久化安装之后 5 分钟内有执行：

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

7036 中的 `DisplayName` 并不总是字面等于 7045 中的 `ServiceName`（一个是显示名、一个是短名）。要么启发式匹配，要么为重要的小集合预先准备一份映射。

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK 对应

- T1562.001 Impair Defenses: Disable or Modify Tools。安全服务的 `stopped` 7036。
- T1543.003 Create or Modify System Process: Windows Service。同一服务的 7036 `running` 与 7045 配对。
- T1569.002 System Services: Service Execution。指向非标准二进制的 `ImagePath` 的 7036 `running`，常常是横向移动的一部分（PsExec、基于 SCM 的远程执行、Impacket `psexec.py`）。
- T1489 Service Stop。瞄准可用性（勒索软件加密数据库前停掉 SQL Server）。

## 看似攻击的误报

- Windows Update 会以可预测的顺序重启十多个服务。频繁、迅速。
- Defender 签名更新有时会重启 `WinDefend` 本身。`stopped` 后紧跟来自 `MsSecFlt.exe` 的 `running` 是正常模式。恶意的那种是 `stopped` 之后*没有* `running`。
- EDR 升级会停掉再启动 EDR 服务。把厂商的升级窗口打上标签。
- 系统睡眠与休眠在入睡时产生一批 `stopped`、唤醒时产生一批 `running`。不要孤立地对它们告警。
- 容器与 Hyper-V 工作负载会经常起停服务。

## 7036 没告诉你的事

- 没有 `AccountName`。从对应的 7045 或 SCM 数据库里取。
- 没有 PID。不能直接把一条 7036 映射到 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 记录，需要按 `ImagePath` 与时间戳相关联。4688 关闭时，[prefetch](https://www.prefetchparser.com) 缓存是次级佐证。
- 没有发起者。你看不到是谁调用了 Stop-Service。要知道，你需要 7035（常默认禁用），或者调用 `net stop` / `sc stop` / `taskkill` 的 [4688](/zh/blog/event-id-4688-process-creation)，又或者 `Stop-Service` 的 [4104](/zh/blog/powershell-4104-scriptblock)。
- 服务短名映射。显示名在 `param1`。短名在二进制 blob 里，必须解码。多数解析器自动处理。如果你查的是原始 `EventData`，得自己来。

## 7036 在时间线中的位置

横向执行加防御规避：

1. [4624](/zh/blog/understanding-event-id-4624)。来自攻击者控制主机的 LogonType 3，AuthenticationPackage Kerberos。
2. [4688](/zh/blog/event-id-4688-process-creation)。`services.exe` 为 SCM 操作生成子进程（或 PsExec 的 `psexesvc.exe`）。
3. [7045](/zh/blog/service-creation-event-id-7045)。服务安装，`ImagePath` 在标准安装路径之外。
4. **7036 `running`**。安装实际触发。执行确认。
5. 对 `WinDefend` 或 EDR 的 **7036 `stopped`**。在载荷运行之前的防御规避。
6. [4688](/zh/blog/event-id-4688-process-creation)。服务账户下的载荷进程。
7. 安装器服务的 **7036 `stopped`**。收尾。

7036 出现在第 4、5、7 步，同一次入侵的三个不同阶段。单看 7036 难以使用。在上下文中，它把持久化记录（7045）与实际执行以及周边的防御规避动作串起来。

## 延伸阅读

- [Microsoft 文档：7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
