---
title: "Event ID 7036 详解:服务状态变化在 DFIR 分诊中的用途"
description: "7036 每次服务启动或停止都会触发。和 7045 配对,它能确认持久化是否真的执行了 —— 单独看,也能揭示服务滥用、防御规避和启动异常。"
date: "2026-05-24"
---

Event ID **7036** ——「{服务}服务进入了{状态}状态」—— 每当服务控制管理器(SCM)看到一次服务转移时,就会写入 [`System` 通道](/zh/blog/what-is-an-evtx-file)。每次服务启动、停止、暂停和恢复都产生一条。单独看它量大且容易忽略;与 [7045](/zh/blog/service-creation-event-id-7045)(已安装服务)配对,它是「安装了后门」和「安装了后门并已运行」之间的差别。

对应急响应来说,这是 OS 给你的最便宜的「它执行了吗?」的记录。

## 它在哪里

总是在服务运行所在主机的 **`System` 通道**。不涉及 DC,不必担心按通道转发 —— 它就在 `System.evtx` 里。提供者是 `Service Control Manager`。

## 记录里有什么

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

就这些。两个参数和一个二进制标签 —— 比大多数 Security 记录小得多,所以分析师常常跳过它。

- **`param1`** —— 服务的*显示名*(不是短名)。这里的 `Background Intelligent Transfer Service` 是 `BITS` 的面向用户名字。要透视到服务定义,常常需要短名;SCM 也会把短名以 UTF-16 编码的 blob 形式写到 `Binary` 里(这里的 `42 00 49 00 54 00 53 00` 解码为 `BITS`)。
- **`param2`** —— 新状态:`running`、`stopped`、`paused`、`resumed`,或少数几个挂起中间状态(`start pending`、`stop pending`)。`running` 和 `stopped` 转移是大多数规则的关键。

没有 `AccountName`、没有 `ImagePath`、没有 `ProcessId` —— 7036 告诉你*什么*改了状态,不告诉你*谁*触发了变更。要拿原因,得配对其它记录(见下)。

## 7036 vs 7045 vs 7035 vs 7034

四个与服务相关的 System 通道事件常常被混淆:

| 事件 | 触发时机 | 提供的信息 |
|---|---|---|
| **7045** | 服务已安装 | 显示名、短名、`ImagePath`、`AccountName`、`StartType`。持久化点。 |
| **7036** | 服务启动/停止 | 仅显示名。执行点。 |
| **7035** | 发送了服务控制 | 谁发起了启动/停止(SID),发送了什么控制。默认通常未开;开启时很有价值。 |
| **7034** | 服务意外崩溃 | 未正常停止就终止的服务。恢复动作。 |

模式很重要:**7045 后几秒内出现同显示名的 7036 `running`,就是教科书式的「已安装并已运行」序列。** 7045 *没有*匹配的 7036 意味着服务被注册但从未执行 —— 要么攻击者清理了,要么安装器中止了,要么启动被推迟。

## 分诊模式

### 1. 持久化验证 —— 与 7045 配对

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

三条记录,一次 PsExec 横移执行。7036 这一对告诉你服务确实运行了(不只是被安装)。对*持久*后门,第二条 7036(stopped)可能缺失,或者会在几小时/几天后主机重启时才出现。

7045 之后几分钟内没有 7036 `running` 本身就是异常 —— 调查为什么安装没触发。常见原因:安装器为下次重启准备、服务设为手动启动而攻击者还没触发,或启动失败(查 7034 / 7000 错误)。

### 2. 防御规避信号 —— 停止安全服务

最被滥用的模式:攻击者停止 `WinDefend`、`MsMpEng`、`Sense`、`SecurityHealthService`、`EventLog`、`WdNisSvc`,或某个 EDR 产品的服务。每个都会产生对应显示名的 7036 `stopped`。如果有人在尝试审计策略 / Defender 篡改,这是幸存下来的记录之一。

要告警的名字(显示名;按 Defender / EDR 版本不同):

- `Windows Defender Antivirus Service` → 服务 `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- 任何匹配 `*CrowdStrike*`、`*SentinelOne*`、`*Carbon*`、`*Cylance*`、`*Sophos*`、`*ESET*`、`*Symantec*`

对其中任何一个的 7036 `stopped` —— 尤其是预定维护窗口之外 —— 都应该硬告警。许多攻击者用 `sc stop`、`net stop`、`Stop-Service` 或 `taskkill /im` —— 四种都会产生 7036。

### 3. 服务名拼写仿冒

7036 触发的是显示名,即便底层服务是恶意的。注意看起来合法但实际不匹配任何已安装 Microsoft 服务的显示名:`Windows Update Service`(真名是 `Windows Update`)、`Windows Defender Service`(真名是 `Windows Defender Antivirus Service`)、`Microsoft Telemetry`(没有此服务)。基线一台已知良好主机的显示名并 diff。

### 4. 启动异常

重启后 SCM 会以大致稳定的顺序拉起 auto-start 服务。启动 7036 序列里出现一个新 auto-start 服务 —— 尤其是上次启动里没有的 —— 就是一个新的持久化点。交叉对照上次关机时或之前对应的 7045。

## Sigma 规则样例 —— 安全服务被停止

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

## KQL 样例 —— 7045 → 7036 序列

头号透视。持久化安装后 5 分钟内同主机执行:

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

7036 里的 `DisplayName` 不会总是字面等于 7045 里的 `ServiceName`(一个是显示名,一个是短名)—— 启发式匹配或为少数关键服务预计算一份映射。

## Splunk 样例

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK 对应

- **T1562.001 —— Impair Defenses: Disable or Modify Tools**:针对安全服务的 7036 `stopped`。
- **T1543.003 —— Create or Modify System Process: Windows Service**:同服务下的 7036 `running` 与 7045 配对。
- **T1569.002 —— System Services: Service Execution**:`ImagePath` 指向非标准二进制的 7036 `running`,常作为横移的一部分(PsExec、基于 SCM 的远程执行)。
- **T1489 —— Service Stop**:针对可用性 —— 停止服务以便其它动作(勒索软件加密数据库前停止 SQL Server)。

## 看起来完全像攻击的误报

- **常规 Windows Update** 会以可预测顺序重启十几个服务。模式重复且短暂。
- **Defender 特征更新**有时会重启 `WinDefend` 本身 —— `stopped` 紧接着由 `MsSecFlt.exe` 触发的 `running` 是正常模式。恶意的是 `stopped` 之后*没有* `running`。
- **EDR 升级**会停止并重启 EDR 服务。给厂商的升级窗口打标签。
- **系统睡眠 / 休眠**会在入睡时产生一批 `stopped`、唤醒时产生一批 `running`。配合 `wake source` 事件就很明显;不要单独告警。
- **容器 / Hyper-V** 工作负载会持续起停服务。

## 7036 不会告诉你的东西

- **没有 `AccountName`**:记录不说服务以哪个安全上下文运行。要从对应 7045 或 SCM 数据库拿。
- **没有 PID**:你无法直接把 7036 映射到 [4688](/zh/blog/event-id-4688-process-creation) / [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 记录,要按 `ImagePath` 和时间戳关联。
- **没有发起者**:你看不到*谁*调用了 Stop-Service。后者需要 7035(默认通常禁用)、调用方 `net stop` / `sc stop` / `taskkill` 的 [4688](/zh/blog/event-id-4688-process-creation),或 `Stop-Service` 的 [4104](/zh/blog/powershell-4104-scriptblock)。
- **服务短名映射**:显示名在 `param1`;短名在 binary blob 中需解码。多数解析器自动处理;查原始 `EventData` 时必须自己处理。

## 7036 在时间线中的位置

横移执行 + 防御规避组合:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— 来自攻击者控制主机的 LogonType 3,AuthenticationPackage Kerberos。
2. [**4688**](/zh/blog/event-id-4688-process-creation) —— `services.exe` 拉起 SCM 操作的子进程(或 PsExec 的 `psexesvc.exe`)。
3. [**7045**](/zh/blog/service-creation-event-id-7045) —— 服务已安装,`ImagePath` 在标准安装路径之外。
4. **7036** `running` —— 安装确实触发了。**这是执行确认。**
5. **7036** `stopped` 针对 `WinDefend` / EDR —— 载荷运行前的防御规避。
6. [**4688**](/zh/blog/event-id-4688-process-creation) —— 服务账号下的载荷进程。
7. **7036** `stopped` 针对安装器服务 —— 清理。

7036 在第 4、5、7 步出现 —— 同一次入侵的三个不同阶段。单独看难用;在上下文里它把持久化记录(7045)与实际执行和周边防御规避动作绑在一起。
