---
title: "Event ID 4688 详解:面向 DFIR 的 Windows 进程创建审计"
description: "4688 是基础 OS 的进程创建记录 —— 前提是命令行审计已开启。这里讲它包含什么、与 Sysmon 1 的区别,以及真正用得上的分诊模式。"
date: "2026-05-24"
---

Event ID **4688** ——「创建了新进程」—— 每当一个进程被启动时,就会写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。它是基础 OS 最接近 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create) 所提供遥测的记录 —— 在未部署 Sysmon 的主机上,它是你能拿到的唯一 `CommandLine` 来源。在配置正确的资产里,每一次进程创建都是这样一条记录。读得好,无需打开 EDR 也能回答「跑了什么」。

## 打开它(因为默认是半盲的)

默认情况下,4688 是开启的,但 `CommandLine` **不会**被记录。没有 `CommandLine`,记录只告诉你一个二进制路径、一个 PID、一个父 PID —— 关于参数一无所知。对分诊几乎没用:`powershell.exe` 没问题;`powershell.exe -enc SQBFAFgA…` 就不一样了。

修复方式是组策略:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

或者等价的注册表项:`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`。一旦设置,每条 4688 都会带完整的 `CommandLine` 字段。代价是日志量;收益是二进制名之下的整个调查面。开启它。

你还需要底层审计策略也开启:`auditpol /set /subcategory:"Process Creation" /success:enable`。很多主机策略开了但命令行没开 —— 两者都要验证。

## 记录里有什么

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

驱动每次调查的字段:

- **`CommandLine`** —— 完整 argv(当 GPO 开启时)。
- **`NewProcessName`** —— 二进制路径。和 `CommandLine` 一起就是完整执行内容。
- **`ParentProcessName`** —— 调用进程。Office → cmd、浏览器 → powershell、services → 未签名 .exe 都是教科书链条。
- **`SubjectUserName` / `SubjectLogonId`** —— 谁在哪个会话下启动的。`SubjectLogonId` 透视回创建该会话的 [4624](/zh/blog/understanding-event-id-4624) 以及同会话其他记录。
- **`TokenElevationType`** —— `%%1936` Default(未提升)、`%%1937` Full(UAC 同意通过)、`%%1938` Limited(过滤后)。非管理员会话里出现 `1937` 是值得细看的权限跃迁。
- **`MandatoryLabel`** —— 完整性级别 SID。`S-1-16-12288` 是 High(提升)、`8192` 是 Medium、`16384` 是 System。

## 4688 vs. Sysmon 1

它们重叠,但不相同。

| 字段 | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | 是(GPO 开启时) | 是 |
| Image / NewProcessName | 是 | 是 |
| 父镜像 | 是(路径) | 是(路径 + CommandLine) |
| ParentCommandLine | 否 | 是 |
| ImageHash(SHA/MD5/IMPHASH) | 否 | 是 |
| ProcessGuid(跨主机稳定) | 否(只有 PID,会复用) | 是 |
| 用户 SID + 名字 | 是 | 是 |
| Logon ID | 是 | 是 |
| CurrentDirectory | 否 | 是 |
| 完整性级别 | 是 | 是 |
| 无需安装即可用 | 是 | 需要 Sysmon |

两者都在时,[Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 是更丰富的记录 —— `ParentCommandLine`、镜像哈希、稳定的 ProcessGuid 父子链。只有 4688 时,你用 PID 构建链(而 Windows 会复用 PID),所以长时间线里可能出现错误匹配;务必按时间戳交叉校验父子关系。

## 分诊模式

在 4688 语料库中,这些模式最有用:

1. **Office → shell**:`ParentProcessName` 以 `winword.exe`、`excel.exe`、`outlook.exe`、`powerpnt.exe` 或 `mshta.exe` 结尾,`NewProcessName` 是 `cmd.exe`、`powershell.exe`、`pwsh.exe`、`wscript.exe`、`cscript.exe`、`rundll32.exe` 或 `regsvr32.exe`。文档类应用拉起 shell 是经典的宏 / 钓鱼链。
2. **编码的 PowerShell**:`NewProcessName` 以 `powershell.exe` 结尾,`CommandLine` 匹配 `-enc`、`-encodedcommand`、`-e `(单字母)、`frombase64string`、`iex ` 或 `invoke-expression`。解码载荷;交叉检查同会话的 [4104 脚本块记录](/zh/blog/powershell-4104-scriptblock)。
3. **从用户可写路径运行的 LOLBin**:签名的 Microsoft 二进制(`certutil`、`regsvr32`、`mshta`、`installutil`、`bitsadmin`、`msbuild`、`csc`)从 `C:\Users\`、`%TEMP%` 或 `C:\ProgramData\` 启动。这些位置上的合法使用极少。
4. **Service host 孤儿**:`svchost.exe` 的 `ParentProcessName` ≠ `services.exe`(或 `wininit.exe` 在极早期启动时)。真正的 `svchost` 总由 `services.exe` 拉起;冒名的会显眼。
5. **改名的二进制**:`NewProcessName` 以中性名字(`update.exe`、`svc.exe`、`data.exe`)结尾,且位于非标准路径。如果有 Sysmon 1 的 `OriginalFileName` 字段,配对使用 —— 那是抓重命名 PsExec、Mimikatz 等的关键字段。

## Sigma 规则样例(office → shell)

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL / Splunk 样例

KQL(经 `SecurityEvent` 接入 Defender XDR / Sentinel):

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK 对应

4688 检测的主体覆盖落在 **T1059 —— Command and Scripting Interpreter** 及其子技术(`.001` PowerShell、`.003` Windows Command Shell、`.005` Visual Basic、`.007` JavaScript)。LOLBin 模式对应 **T1218 —— System Binary Proxy Execution**(`.005` Mshta、`.010` Regsvr32、`.011` Rundll32)。Office → shell 链对应 **T1566.001 —— Phishing: Spearphishing Attachment** 加 T1059。改名二进制检测落在 **T1036.003 —— Masquerading: Rename System Utilities**。

## 误报(告警前先读这段)

- **软件更新代理**合法地拉起 shell:Chocolatey、WinGet、厂商 MSI 包装器。按 `SubjectUserSid`(LocalSystem)加稳定的 `ParentProcessName` 模式加白,而不是按用户账号。
- **漏洞扫描器和 EDR 产品**产生的进程树看起来和攻击者侦察一模一样:net.exe、whoami.exe、systeminfo.exe。给扫描器 IP / 主机打标签并排除。
- **Citrix / RDS 多会话主机**会出现跨域访问的合法 `runas /netonly` 链。调查用户,而不是模式本身。
- **登录脚本**(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)每次登录都触发,呈现为重复链。识别并基线化后再告警。

## 4688 不会告诉你的东西

没有文件哈希。没有 `ParentCommandLine`。没有 `ImageLoaded`(DLL 注入不是进程创建)。没有网络行为。这些都需要 [Sysmon event 1](/zh/blog/sysmon-event-id-1-process-create)(更丰富的 4688)、Sysmon 7(镜像加载)、Sysmon 3/22(网络/DNS),以及在有的地方,EDR 的行为数据。4688 是进程可见性的下限 —— 每台 Windows 主机都该有的最小值。它不是关键主机上正经 EDR + Sysmon 的替代品。

## 4688 在时间线中的位置

在一台没有 Sysmon 的主机上典型的后渗透链,你的时间线会是这样:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— 初始登录,LogonType 3,来自外部 IP。
2. **4624** —— 同一 `SubjectLogonId` 下第二次登录,LogonType 9(`runas /netonly`)—— 凭证横移。
3. **4688** —— 该会话下的 `powershell.exe -enc ...`。
4. [**4104**](/zh/blog/powershell-4104-scriptblock) —— 解码后的脚本体,拉取第二阶段载荷。
5. **4688** —— 从 `%TEMP%` 运行的第二阶段二进制。
6. [**7045**](/zh/blog/service-creation-event-id-7045) —— 为持久化安装的服务。

六条记录讲完整个故事。(3) 和 (5) 的 PID 通过 4688 的 `ProcessId`/`NewProcessId` 关联 —— 但要按时间戳验证,因为 Windows 会回收 PID。有 Sysmon 时,`ProcessGuid` 链替代了这种脆弱的匹配。
