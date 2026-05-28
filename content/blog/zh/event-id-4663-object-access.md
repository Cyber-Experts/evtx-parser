---
title: "Event ID 4663 解读：基于 SACL 的文件与注册表访问审计"
description: '4663 是按访问触发的对象审计记录。在恰当的文件和键上配置 SACL，即可获得字节级的对象访问日志。对勒索软件、外泄与凭据库窃取尤其有用。'
date: "2026-05-24"
---

Event ID **4663**「尝试访问对象」在被审计的文件、注册表键或内核对象以与其系统访问控制列表（SACL）相符的方式被触及时触发于 [`Security` 通道](/zh/blog/what-is-an-evtx-file)。与多数 Security 记录不同，4663 默认什么都不产生。你必须先在对象上*配置* SACL。这就是为什么大多数环境没有它。这也是为什么有它的环境，在少数几种技术上拥有几乎不公平的检测优势。

如果你只在恰好五样东西上启用 4663，其他都不管，你就能比任何 EDR 都便宜地抓住凭据转储铺垫、勒索软件扫荡，以及 DPAPI 窃取。

## 在哪里触发

在拥有该对象的主机上。文件 SACL 在文件服务器上触发。本地注册表 SACL 在工作站上触发。AD 对象 SACL 在 DC 上触发。没有集中记录。要在敏感共享上获得全网可见性，你需要从托管它的文件服务器转发 Security。这一点经常被忽略。

## 记录字段

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

要看的字段：

- `ObjectType`。`File`、`Key`（注册表）、`Process`、`Token`、`Directory`、`Section`。任何支持 SACL 的对象类。
- `ObjectName`。完整路径。文件是 Windows 路径。注册表键是 `\REGISTRY\MACHINE\...` 下的完整路径（不是你在 regedit 里输入的 `HKLM\...`）。
- `AccessList`。尝试了什么，作为解码后的访问权令牌。常见的：
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA、`%%4420` = WriteEA
  - `%%4423` = ReadAttributes、`%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`。实际请求的 `STANDARD_RIGHTS_*` 与对象特定权利的原始位掩码。
- `ProcessName` 与 `ProcessId`。打开句柄的进程。要拿到完整进程上下文，跳到 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create)。
- `SubjectLogonId`。跳到 [4624](/zh/blog/understanding-event-id-4624) 拿到发起会话、网络登录时的源 IP，以及用户。

## 打开 4663 是三步，常有人漏掉一步

1. **审计策略**。启用 *Object Access* 的 File System 和/或 Registry 子策略，启用成功和/或失败。通过组策略或 `auditpol /set /subcategory:"File System" /success:enable /failure:enable`。
2. **对象上的 SACL**。GUI 中：属性、Security 选项卡、Advanced、Auditing 选项卡。或者 `Set-Acl`、`icacls /audit`。指定哪个主体、哪些权利，以及审计成功、失败还是两者。
3. **对于注册表**，在 regedit 中通过键的权限、Advanced、Auditing 走同样的流程。

没有 (1)，记录永远不会写。没有 (2)，Windows 不知道你想审计什么。没有 (3)，你只在审计文件。最常被跳过的是 (2)，因为 (1) 给人"应该够了吧"的错觉。不够。

每台服务器上物有所值的 SACL：

- `C:\Windows\System32\config\SAM`、`SECURITY`、`SYSTEM`。审计 `Everyone : ReadData : Success`。除 `LocalSystem` 之外的任何东西读取这些都是凭据转储。
- `C:\Windows\Temp` 与 `%TEMP%` 中的 `*.dmp` 文件。审计 `Everyone : WriteData : Success`。在这里写 `.dmp` 的进程不是崩溃后的 Windows，就是 Mimikatz 操作者。
- `C:\ProgramData\Microsoft\Crypto\RSA` 与 `C:\Users\*\AppData\Roaming\Microsoft\Protect`。DPAPI 主密钥目录。审计 `ReadData : Success`。在用户自身会话之外读取这些的，是在偷秘密。
- `HKLM\SECURITY` 与 `HKLM\SAM`。注册表等价物。同样审计。
- 敏感文件共享：财务、法务、薪资。审计 `WriteData + DELETE : Success`，抓勒索扫荡和批量删除。

## 你真正会抓到的模式

### SAM 或 SYSTEM 蜂巢读取

任何 `ObjectName` 以 `\config\SAM`、`\config\SECURITY` 或 `\config\SYSTEM` 结尾，且 `ProcessName` 不是 `services.exe`、`lsass.exe`、`wininit.exe`，且 `SubjectUserSid` 不是 `S-1-5-18` 的 4663。这要么是 `reg save HKLM\SAM`、对卷影副本的 `esentutl /y`，要么是具有蜂巢文件级访问的凭据转储工具。交叉检查 [registry](https://www.registryparser.com) 看是否留下了备份蜂巢文件。

### LSASS 小型转储写入

向 `C:\Windows\Temp\`、`C:\ProgramData\` 或 `%TEMP%` 中的 `.dmp` 文件写入的 4663 `WriteData`，且 `ProcessName` 为 `rundll32.exe`、`procdump*.exe`，或任何调用 `comsvcs.dll` 的进程。教科书做法是 `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`。交叉参考 [4688](/zh/blog/event-id-4688-process-creation) 拿 `CommandLine`。即便 EDR 在打瞌睡，4663 也能抓到。

### 勒索软件加密扫荡

针对敏感共享中的文件、秒级时间窗内、来自同一 `SubjectLogonId` 与 `ProcessName`、`AccessMask` 含 `WriteData + DELETE` 的大量 4663。真实的备份进程会以受限速率、可测量的模式碰文件。勒索软件会以磁盘允许的最大速度扫荡目录树。形态会暴露它。

### DPAPI 主密钥窃取

除该用户自身会话以外的任何进程，对 `\AppData\Roaming\Microsoft\Protect\<sid>\` 下文件的 4663 `ReadData`。最确凿的迹象是 `SubjectUserSid` 与路径中嵌入的 SID *不同*。

### Group Policy Preferences 密码文件读取

匹配 `\SYSVOL\<domain>\Policies\*\Groups.xml`、`Services.xml`、`Drives.xml`、`ScheduledTasks.xml` 的文件的 4663 `ReadData`。这就是 `Get-GPPPassword`。技术很老。SYSVOL 文件在遗留域中依旧普遍存在，而从 MSDN 上挑一个被混淆的 AES 密钥、然后拿走域凭据的人，比你想的多。

## Sigma：SAM 蜂巢读取

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

## KQL：勒索软件加密扫荡

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

一个登录会话下每分钟有 100 个不同文件被写入或删除，就是扫荡。就这么简单。

## Splunk：DPAPI 主密钥访问

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK 对应

- T1003.002 OS Credential Dumping: Security Account Manager。SAM 蜂巢读取。
- T1003.004 LSA Secrets。SECURITY 蜂巢读取。
- T1003.001 LSASS Memory。`.dmp` 写入（与进程上下文结合）。
- T1555.004 Credentials from Password Stores: Windows Credential Manager。对 `\AppData\Local\Microsoft\Credentials\` 的访问。
- T1552.006 Unsecured Credentials: Group Policy Preferences。SYSVOL 中 `Groups.xml` 的读取。
- T1486 Data Encrypted for Impact。大量 `WriteData + DELETE` 模式。
- T1565.001 Stored Data Manipulation。对受监控数据共享的任意写入。

## SACL 体量陷阱

在一个繁忙的目录上设置 `Everyone : All access : Success+Failure`，会每分钟产生几十万条 4663，把收集端淹没。SACL 是精密仪器。请审计：

- 仅你关心的访问类型。凭据库用 ReadData。数据共享用 WriteData + DELETE。两者同时审计的情况很少。
- 仅成功。失败更少见，且在这一语料里很少有趣。
- 具体文件，而不是整盘。SAM 文件，不是整个 `C:\Windows\System32\config\`。HR 共享，不是整盘 `D:\`。
- 在条件允许时，限定具体主体。对 SAM 类对象，`Everyone` 没问题，因为合法访问反正都来自 `LocalSystem`。对共享数据，仅审计实际接触数据的主体。

针对五个高价值对象调好的 SACL，每台主机每天产生 50 到 200 条记录。完全可处理。

## 看起来与攻击一模一样的误报

- 卷影副本备份在备份窗口期产生密集的 4663 流量。给备份编排器的 `ProcessName` 打标签。
- 反病毒的访问触发扫描会打开目标目录下的每个文件。AV 产品的服务账号会主导任何朴素的 4663 规则。按 SID 加白名单。
- 索引服务（Windows Search）通过 `ReadAttributes` 访问元数据。通常可按 `AccessList` 过滤。
- 备份分级还原看起来像勒索写入（许多文件、一个进程、一个目录）。进程会告诉你区别。
- Defender 的实时扫描会读取一切。如果审计太宽，它会主导噪声。

## 4663 没告诉你的事

- 访问的内容。你看到一个文件被读或被写，但看不到读到/写下了什么。要这个就上 EDR 或 FIM。
- 访问为什么发生。要把它关联到用户意图，请配合 [4688](/zh/blog/event-id-4688-process-creation) 或 [Sysmon 1](/zh/blog/sysmon-event-id-1-process-create) 拿到调用进程的完整上下文。
- 关闭的句柄。4663 在句柄 *open* 时触发。关闭事件是 4658，在攻击检测中很少有用。
- 网络路径不会透明记录。对共享的 SMB 访问在*服务器*上触发 4663，客户端什么都看不到。需要服务器侧的收集。
- 默认下的失败访问。许多公司只审计 Success。仅在你真的关心被阻挡的尝试时再配置 Failure。

## 4663 在时间线中的位置

典型的 LSASS 凭据转储链：

1. [4624](/zh/blog/understanding-event-id-4624)。管理员登录，LogonType 3 或 10。
2. [4672](/zh/blog/event-id-4672-special-privileges)。会话被授予 SeDebugPrivilege。
3. [4688](/zh/blog/event-id-4688-process-creation)。`rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`。
4. **4663**。`rundll32.exe` 向 `C:\Windows\Temp\lsass.dmp` 的 `WriteData`。取证金矿。铺垫外泄的证据。
5. [4688](/zh/blog/event-id-4688-process-creation)。文件移动或打包（操作者提取转储）。
6. [1102](/zh/blog/event-id-1102-cleared-log)。Security 日志被清。一些操作者会做。许多人忘记。

第 4 步是这条链中最便宜、最具体的信号。它在磁盘上以名字直接锁定凭据窃取产物，并附带调用进程。SAM 蜂巢读取、DPAPI 主密钥访问、SYSVOL Groups.xml 读取，遵循同样的逻辑。

## 延伸阅读

- [4663 的 Microsoft 文档](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
