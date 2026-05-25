---
title: "Event ID 4663 详解:用 SACL 做文件与注册表访问审计"
description: "4663 是每次对象访问的审计记录。在合适的文件和键上配好 SACL,你就能获得每次访问的细粒度日志 —— 对勒索软件、外泄和凭证库窃取都非常有用。"
date: "2026-05-24"
---

Event ID **4663** ——「尝试访问对象」—— 每当一个被审计的文件、注册表键或内核对象以匹配其系统访问控制列表(SACL)的方式被访问时,就会写入 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。与大多数 Security 记录不同,4663 本身不会自动产生 —— 你必须先在关心的对象上*配置* SACL,4663 记录才会存在。这让它默认成本极低,一旦调好却毁灭性地有效。

如果你只用 4663 审计一件事,那就审计对凭证库和高价值数据共享的访问。它的信噪比在整个审计目录里数一数二。

## 它在哪里触发

总是在拥有该对象的主机上 —— 文件 SACL 在文件服务器,本地注册表 SACL 在工作站,AD 对象 SACL 在 DC。没有集中记录;要想对整个资产中的某个敏感共享有可见性,就必须从托管它的文件服务器转发 `Security`。

## 记录里有什么

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

字段含义:

- **`ObjectType`** —— `File`、`Key`(注册表)、`Process`、`Token`、`Directory`、`Section`,或任何支持 SACL 的对象类。
- **`ObjectName`** —— 全路径。文件是 Windows 路径;注册表键是 `\REGISTRY\MACHINE\…` 下的完整路径(注意:不是你在 regedit 里看到的 `HKLM\…` 形式)。
- **`AccessList`** —— 尝试了什么,一组解码后的访问权限名(每个 `%%NNNN` 令牌一个)。常见的解码值:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** —— 实际请求的 `STANDARD_RIGHTS_*` 和对象特定权限的原始位图。
- **`ProcessName`** + **`ProcessId`** —— 打开句柄的进程。透视到 [4688](/zh/blog/event-id-4688-process-creation) / [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 获取完整进程上下文。
- **`SubjectLogonId`** —— 透视到 [4624](/zh/blog/understanding-event-id-4624) 拿到原始会话、网络登录时的源 IP,以及用户。

## 配置 4663 —— 真正需要做功夫的部分

有三层配置;少一层就一条记录都拿不到。

1. **审计策略**:启用 *Object Access → Audit File System* 和/或 *Audit Registry* 的成功和/或失败。通过 GPO 或 `auditpol /set /subcategory:"File System" /success:enable /failure:enable`。
2. **对象上的 SACL**:右键 → 属性 → 安全 → 高级 → 审核标签(Windows GUI),或者通过 `Set-Acl` / `icacls /audit`。你要指定*哪个主体*(通常是 `Everyone` 或 `Authenticated Users`)、*哪些权限*、*审核成功、失败,还是两者*。
3. **注册表**:同样的流程,通过 `regedit` → 键 → 权限 → 高级 → 审核访问。

没有 (1) 记录永远写不出来;没有 (2) Windows 不知道你要审计什么;没有 (3) 你只审计了文件。

每台服务器都该配的 SACL:

- **`C:\Windows\System32\config\SAM`**、**`SECURITY`**、**`SYSTEM`** —— 本地凭证库。审核 `Everyone : ReadData : Success`。任何不是 `LocalSystem` 在读它们的进程都是凭证转储企图。
- **`%TEMP%\lsass.dmp`** 以及 `C:\Windows\Temp` 中任何 `*.dmp` —— 进程小型转储。审核 `Everyone : WriteData : Success`。某个进程在这里写 `.dmp` 要么是崩溃转储(Windows 自己),要么是 Mimikatz 操作手(所有其他人)。
- **`C:\ProgramData\Microsoft\Crypto\RSA`** 和 **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** —— DPAPI 主密钥目录。审核 `ReadData : Success`。从用户自己会话以外读这些的人都在偷受保护的秘密。
- **`HKLM\SECURITY`** 和 **`HKLM\SAM`** —— 注册表等价物。审核 `ReadData : Success`。
- **敏感文件共享** —— 财务、法务、薪资。审核 `WriteData + DELETE : Success`,以捕获勒索软件加密扫荡和批量删除。

## 分诊模式

### 1. SAM / SYSTEM hive 被读取

任何 `ObjectName` 以 `\config\SAM`、`\config\SECURITY` 或 `\config\SYSTEM` 结尾的 4663,且 `ProcessName` 不是 `services.exe` / `lsass.exe` / `wininit.exe`,且 `SubjectUserSid` 不是 `S-1-5-18`。这就是 `reg save HKLM\SAM`、`esentutl /y`、`vssadmin create shadow + copy`,或任何在文件级访问 hive 的凭证转储工具。

### 2. LSASS dump 文件被写入

`WriteData` 4663,目标是 `C:\Windows\Temp\`、`C:\ProgramData\` 或 `%TEMP%` 下的 `.dmp` 文件,`ProcessName` 是 `rundll32.exe`、`procdump*.exe`、与 `comsvcs.dll` 相关的调用方,或一个改名后的二进制。这是 LSASS-minidump 模式。交叉对照 [4688](/zh/blog/event-id-4688-process-creation) 看 `CommandLine` —— `comsvcs.dll MiniDump` 是最常见的编码。

### 3. 勒索软件加密扫荡

短时间内大量 4663,`AccessMask` 包含 `WriteData + DELETE`,目标是敏感共享内的文件,全部来自同一个 `SubjectLogonId` 和 `ProcessName`。真实的备份进程触碰文件的节奏是可测、有节流的;勒索软件会以磁盘允许的最快速度扫荡整棵目录树。

### 4. DPAPI 主密钥被盗

对 `\AppData\Roaming\Microsoft\Protect\<sid>\` 下文件的 `ReadData` 4663,来自用户自身会话以外的任何进程。经典模式是 `SubjectUserSid` 与路径中 SID *不一致*。

### 5. 组策略首选项的密码文件被读取

对匹配 `\SYSVOL\<domain>\Policies\*\Groups.xml`(或 `Services.xml`、`Drives.xml`)的文件的 `ReadData` 4663。这是 `Get-GPPPassword` 攻击 —— 老旧,但 SYSVOL 文件在历史悠久的域中常常还存在。

## Sigma 规则样例 —— SAM hive 被读取

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## KQL 样例 —— 勒索软件加密扫荡

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

同一登录会话下每分钟有 100 个不同文件被写入或删除,这就是扫荡 —— 没得辩。

## Splunk 样例 —— DPAPI 主密钥访问

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK 对应

- **T1003.002 —— OS Credential Dumping: Security Account Manager**:SAM hive 读取。
- **T1003.004 —— OS Credential Dumping: LSA Secrets**:SECURITY hive 读取。
- **T1003.001 —— OS Credential Dumping: LSASS Memory**:`.dmp` 写入(结合进程上下文)。
- **T1555.004 —— Credentials from Password Stores: Windows Credential Manager**:访问 `\AppData\Local\Microsoft\Credentials\`。
- **T1552.006 —— Unsecured Credentials: Group Policy Preferences**:SYSVOL `Groups.xml` 读取。
- **T1486 —— Data Encrypted for Impact**:批量 WriteData + DELETE 模式(勒索软件)。
- **T1565.001 —— Stored Data Manipulation**:对受监控数据共享的任意文件写入。

## 容量管理 —— SACL 陷阱

简单粗暴地在一个繁忙目录上设 `Everyone : All access : Success+Failure`,每分钟会产出数十万条 4663,把收集端淹没。SACL 是精密工具。审核应当:

- **只针对你关心的访问类型**(凭证库的 `ReadData`;数据共享的 `WriteData + DELETE`;两者都要的情况很少)。
- **只审核成功** —— 失败更稀少,通常也不有趣。
- **特定文件**,而不是整个磁盘。是 SAM 文件,不是整个 `C:\Windows\System32\config\`。是 HR 共享,不是整个 `D:\`。
- **特定主体**(只要可能):对 SAM 类对象用 `Everyone` 无妨,因为合法访问反正都是 `LocalSystem`;对共享数据,只审核实际接触数据的主体。

在五个高价值对象上调优良好的 SACL,每台主机每天产生 50-200 条记录 —— 完全可控。

## 看起来完全像攻击的误报

- **Volume Shadow Copy(VSS)** 备份在备份窗口期间产生密集的 4663 流量。给备份编排器的 `ProcessName` 打标签。
- **杀软按需扫描**会打开目标目录里每个文件;AV 产品服务账号会主导任何粗放的 4663 规则。按 SID 加白名单。
- **索引服务**(Windows Search、类 Spotlight)通过 `ReadAttributes` 触发元数据 —— 通常按 `AccessList` 可过滤掉。
- **备份分阶段恢复**看起来像勒索软件写入(很多文件、单一进程、在某个目录里),但进程是你的备份代理。
- **Defender 实时扫描**会读所有东西;审计范围太广时,它会成为主要噪声源。

## 4663 不会告诉你的东西

- **访问的内容**:你看到文件被读/写,但看不到读/写了什么。后者需要 EDR 或 FIM(文件完整性监控)产品。
- **访问发生的原因**:只是系统调用的结果。要关联到用户意图,需配对 [4688](/zh/blog/event-id-4688-process-creation) / [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 获取调用进程的完整上下文。
- **句柄关闭事件**:4663 触发于句柄*打开*。关闭事件是 4658,极少用于攻击检测。
- **透明的网络路径**:对共享的 SMB 访问触发的 4663 在*服务器*侧;客户端啥都看不到。需要服务器侧采集。
- **默认下的失败访问**:很多组织只审计 `Success`;只有当你真的关心被拒绝的访问尝试时,才配置 `Failure`。

## 4663 在时间线中的位置

经典 LSASS 凭证转储链:

1. [**4624**](/zh/blog/understanding-event-id-4624) —— admin 登录(LogonType 3 或 10)。
2. [**4672**](/zh/blog/event-id-4672-special-privileges) —— 该会话被授予 SeDebugPrivilege。
3. [**4688**](/zh/blog/event-id-4688-process-creation) —— `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`。
4. **4663** —— `rundll32.exe` 对 `C:\Windows\Temp\lsass.dmp` 的 `WriteData`。**取证金矿 —— 外泄暂存的直接证据。**
5. [**4688**](/zh/blog/event-id-4688-process-creation) —— 文件移动 / 打包(操作手提取转储)。
6. [**1102**](/zh/blog/event-id-1102-cleared-log) —— Security 日志被清空(部分操作手这么做;很多人忘了)。

第 4 步的 4663 是整条链里最便宜、最特定的信号 —— 它在磁盘上直接按名字识别出凭证窃取的产物,并附带调用进程。SAM hive 读、DPAPI 主密钥访问、SYSVOL Groups.xml 读,工作原理都一样。
