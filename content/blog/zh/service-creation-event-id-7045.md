---
title: "Event ID 7045 详解:作为持久化信号的服务安装"
description: "服务创建是最显眼的持久化技术之一。事件 7045 捕获每次安装 —— 读这三个字段就能抓住大多数情况。"
date: "2026-05-17"
---

Event ID **7045** ——「系统中安装了一个服务」—— 每当服务控制管理器注册一个新服务时,就会写入 [`System` 通道](/zh/blog/what-is-an-evtx-file)。在原版系统上它噪声不小(驱动安装、更新),但在稳态的企业环境里足够安静,异常会显现。它也是 MITRE ATT&CK 引用最多的持久化技术之一:T1543.003。

## 记录里有什么

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

五个字段,其中三个对 IR 重要。

## 先读的三个字段

**`ImagePath`** 是最有用的字段。合法服务位于 `C:\Windows\System32\`、`C:\Program Files\` 或 `C:\Program Files (x86)\`。任何二进制位于 `C:\Windows\Temp\`、`C:\Users\<user>\AppData\`、`C:\ProgramData\` 或随机命名目录的服务都值得细看。`ImagePath` 也可能是 `cmd.exe /c …` 或 `powershell.exe -e …` —— 这些几乎一定是恶意的;合法服务不会 shell out。

**`AccountName`** 通常是 `LocalSystem`。一个在域用户或不符合组织模式的特定服务账号下安装的服务很反常。

**`StartType`** 为 `auto start` 意味着每次启动时运行。`demand start` 意味着手动。持久化几乎总要 `auto start`;一次性横移执行可能用 `demand start` 并自己清理 —— 这就让 7045 成为唯一留下的产物。

## 横移执行模式

当攻击者运行 `PsExec` 或任何通过 SCM 在另一台主机上远程执行的工具时,你会在*目标*主机上得到一条 7045,`ImagePath` 类似 `%SystemRoot%\PSEXESVC.exe`(默认)或某个改名后的等价物。服务出现、运行,通常几秒内就被删除。7045 是服务本身消失后很久仍存在的指纹。

7045 的 `ImagePath` 以 `.exe` 结尾,几秒后跟着来自特定源主机的 [4624 LogonType **3**](/zh/blog/understanding-event-id-4624),就是教科书式的 PsExec 签名。SMBExec、WMIExec、Impacket 的 `psexec.py` 等变体产生略微不同的 `ImagePath` 值,但整体模式相同。

## 7045 不会告诉你的东西

7045 在*安装*时触发,而不是每次后续启动。要看服务实际在跑,需要 7036(「服务进入运行状态」)。要看底层进程,需要带匹配 `Image` 路径的 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create) 或 [4688](/zh/blog/event-id-4688-process-creation)。

对于在审计日志开始前*已安装*的服务(例如 OS 安装期间),没有 7045 —— 它们存在于 `HKLM\SYSTEM\CurrentControlSet\Services\` 注册表里,必须在那里枚举,不能从事件日志查。

## 分诊流程

1. 在 System 通道筛 `EventID:7045`。
2. 按 `ImagePath` 排序或透视 —— 标准安装路径之外的都可疑。
3. 对每个可疑项,按时间戳 + 源主机拉对应的 4624 —— 找出安装它的凭证。
4. 按 `Image` 匹配 `ImagePath` 拉 Sysmon event 1,看实际执行。
5. 注意 [**7036**](/zh/blog/event-id-7036-service-state) / 7034 / 7035 序列显示的是一次性运行还是持久服务。

## Sigma 规则样例 —— 从非标准路径安装的服务

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## KQL 样例 —— PsExec 横移执行指纹

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

同主机 7045 30 秒内出现 4624 LogonType-3 就是教科书 PsExec 签名。

## Splunk 样例 —— 异常服务安装器

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## ATT&CK 对应

- **T1543.003 —— Create or Modify System Process: Windows Service**:头号映射。在攻击者控制二进制下启动的长期服务。
- **T1569.002 —— System Services: Service Execution**:作为远程执行载体的短寿命服务(PsExec、SMBExec、基于 SCM 的横移)。
- **T1078 —— Valid Accounts**:安装主体是凭证被盗的域管理员时。
- **T1036.005 —— Masquerading: Match Legitimate Name or Location**:显示名仿冒真实 Microsoft 服务但二进制在别处的服务。

## 看起来完全像攻击的误报

- **软件安装器**(Chocolatey、MSI 引导程序)常常从暂存目录安装服务,然后再移动二进制。7045 从暂存路径触发,即使最终安装是干净的。
- **EDR / AV 代理**作为安装的一部分安装服务。厂商的 `ImagePath` 会稳定且签名;基线化。
- **某些 Microsoft 更新**安装临时维护服务;它们短寿且来自 `LocalSystem`。
- **容器 / Hyper-V** 工作负载有时按 VM 注册临时服务。

信号是*一次性*安装到用户可写路径的、由*非管理员或非标准*安装器触发。`C:\Program Files\` 下签名安装器服务不是攻击。
