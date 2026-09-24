---
title: "“找不到事件 ID 的描述”错误:原因与解决方法"
description: "为什么事件查看器找不到某个事件 ID 的描述、%%1833 这类代码代表什么，以及如何在离线状态下照样读懂事件内容。"
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "“The description for Event ID X from source Y cannot be found”是什么意思？"
    answer: "记录本身没有问题。.evtx 记录只保存事件 ID、提供程序名称和插入字符串(EventData / UserData)。你平时在事件查看器里读到的那句话，是存放在查看日志那台机器上、提供程序消息 DLL 里的模板。如果你的机器上没有注册该提供程序，事件查看器就拼不出这句话，只能显示这条错误以及原始插入字符串。"
  - question: "事件数据是否已经丢失或损坏？"
    answer: "没有。所有字段都还在记录里。打开事件查看器的“详细信息”选项卡(XML 视图)，或用 Get-WinEvent、wevtutil 或解析器读取 EventData 字段即可。缺的只是包裹这些值的可读文字。"
  - question: "事件里的 %%1833 是什么意思？"
    answer: "%%1833 是对参数消息的引用，由安全审核提供程序的参数消息文件 msobjs.dll 解析。%%1833 表示 Impersonation(4624 的 ImpersonationLevel 字段)。其他常见的有:%%1842 Yes、%%1843 No、%%2313 Unknown user name or bad password、%%1936/%%1937/%%1938 令牌提升类型 1/2/3。"
  - question: "如何导出 .evtx，使其在另一台电脑上也能显示描述？"
    answer: "在源机器的事件查看器中选择“将所有事件另存为”，保存为 .evtx，并勾选要包含显示信息的语言。事件查看器会在 .evtx 旁边写入一个包含 .MTA 文件的 LocaleMetaData 文件夹。两者需要一起复制。命令行下 wevtutil archive-log(wevtutil al)可以达到同样效果。"
  - question: "不安装提供程序能读懂事件吗？"
    answer: "可以。做 DFIR 时很少真正需要渲染后的消息:消息要显示的每个值都在 EventData 字段里。evtxparser.com 的浏览器解析器还会为常见 DFIR 事件显示一行描述，并在离线状态下解码 %% 代码、NTSTATUS 代码和 Kerberos 加密类型，文件无需上传。"
---

你从一台可疑主机上复制了 `Security.evtx`,在分析工作站上打开，每条记录都显示:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

在中文版 Windows 上，同一条消息以“找不到来源 Microsoft-Windows-Security-Auditing 中的事件 ID 4625 的描述。”开头。后面跟着一串原始值:`%%2313`、`0xC000006A`、`0x17`。没有任何东西损坏，也没有丢失。这是*渲染*失败，而不是数据失败。本文说明描述文字究竟存放在哪里、为什么会缺失、需要时如何修复，以及为什么在分诊时通常根本不需要它。(如果你只想马上看到可读的事件:[浏览器解析器](/zh)会离线渲染描述并解码这些代码。)

## 这个错误到底是什么意思

`.evtx` 记录并不保存你在事件查看器中读到的那句话。它保存的是 `<System>` 块(提供程序、事件 ID、时间、计算机)以及 `<EventData>` 或 `<UserData>` 中的**插入字符串**([记录里有什么](/zh/blog/what-is-an-evtx-file))。那句话(英文版 Windows 上是 “An account failed to log on. Subject: … Failure Reason: …”)是一个带有 `%1`、`%2` 占位符的模板，存放在事件提供程序所属 DLL 或 EXE 的**消息表资源**中。

Windows 去哪里找这个文件，取决于提供程序的类型:

- **经典(旧式)事件源**注册在 `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` 下，路径写在 `EventMessageFile` 值中(另外还可能有 `ParameterMessageFile` 和 `CategoryMessageFile`)。
- **基于清单的提供程序**(Vista 及以后，`Microsoft-Windows-*` 系列)注册在 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}` 下。`MessageFileName`、`ResourceFileName` 和 `ParameterFileName` 这几个值指向携带已编译清单(`WEVT_TEMPLATE` 资源)和消息表的二进制文件。

关键在于:**事件查看器是在你查看日志的那台机器上渲染消息的**,使用的是那台机器的注册表和 DLL。写入事件的那台机器在显示时毫无作用。如果本地没有注册该提供程序，就没有模板，于是你看到的就是这条错误加上原始插入字符串。

## 常见原因

- **日志来自另一台主机。** 这是最典型的 DFIR 场景。源主机上的第三方代理、EDR、SQL Server 实例或业务应用，在你的分析工作站上都没有对应的提供程序。在 macOS、Linux 或干净的虚拟机上打开文件效果一样:根本没有任何 Windows 提供程序。
- **软件已被卸载。** 卸载程序删除了 DLL,但旧事件仍然引用该事件源。
- **DLL 缺失、损坏或被移动。** 注册表指向一个已不存在的路径，或者 `EventMessageFile` 被存成了 `REG_SZ` 而不是 `REG_EXPAND_SZ`,导致 `%SystemRoot%` 永远不会被展开。
- **32/64 位不匹配。** 32 位安装程序把 DLL 写进了它以为的 `System32`(由于文件系统重定向，实际是 `SysWOW64`),而 64 位事件日志组件读取注册路径时看到的是真正的 `System32`。
- **语言。** 提供程序的消息表存在，但没有显示语言对应的版本;或者你打开的“带显示信息”导出文件所用语言与查看器语言不同。

## %% 代码：参数消息

即使主描述能正常渲染，有些字段显示的仍是 `%%1833` 或 `%%2313` 而不是文字。这些是对**参数消息**的引用：值是第二张消息表中的 ID,即提供程序的 `ParameterMessageFile` / `ParameterFileName`。对于安全审核提供程序，这个文件是 `msobjs.dll`。离线时，这些引用无法解析。值得牢记的常见代码如下(标签为英文版 Windows 中的写法):

| 代码 | 含义 | 出现位置 |
|------|------|----------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`、`ElevatedToken` |
| `%%1936` | 类型 1,完整令牌(UAC 关闭或内置管理员) | 4688 `TokenElevationType` |
| `%%1937` | 类型 2,提升后的令牌 | 4688 `TokenElevationType` |
| `%%1938` | 类型 3,受限令牌 | 4688 `TokenElevationType` |
| `%%2307` | Account locked out(账户已锁定) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled(账户已禁用) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

`%%2080 %%2082 %%2084` 这个三元组是 [4720](/zh/blog/event-id-4720-account-created) 中新建账户的正常特征。[4688](/zh/blog/event-id-4688-process-creation) 中出现 `%%1937`,表示进程是在 UAC 提示之后以完整管理员令牌启动的。

十六进制值不是 `%%` 代码。[4625](/zh/blog/detecting-4625-brute-force) 的 `Status` / `SubStatus` 字段是 NTSTATUS 代码:`0xC000006A` 表示有效账户的密码错误,`0xC0000064` 表示用户名不存在,`0xC0000234` 表示账户被锁定。[4769](/zh/blog/event-id-4769-kerberoasting) 中的 `TicketEncryptionType` 是 Kerberos etype:`0x17` 是 RC4-HMAC,`0x12` 是 AES256。即使提供程序存在，这两类值也都以原始十六进制显示。

## 解决方法 1:带显示信息导出

如果你还能访问源主机，就把日志连同消息一起导出。在事件查看器中：右键单击日志，选择 **“将所有事件另存为…”**,选 `.evtx`,在接下来的对话框中选择要包含显示信息的语言(英文版 Windows 中为 **Display information for these languages**)。事件查看器会在文件旁边写入一个 `LocaleMetaData` 文件夹，每种语言一个 `.MTA` 文件。复制时请把该文件夹和 `.evtx` 放在一起;分析机上的事件查看器会使用它。

命令行方式:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al`(archive-log)为已导出的文件添加区域设置元数据。大规模采集请参阅[从运行中的系统采集 EVTX](/zh/blog/collecting-evtx-from-live-system)。

## 解决方法 2:安装或修复提供程序

在你自己管理的机器上，如果自家软件的事件无法渲染:

- 重新安装或修复拥有该事件源的应用程序。
- 检查 `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` 下的 `EventMessageFile`:路径必须存在;如果包含 `%SystemRoot%`,值类型应为 `REG_EXPAND_SZ`。
- 对于基于清单的提供程序，检查 `Get-WinEvent -ListProvider <Name>`;如果报错或列不出任何消息，说明清单注册已损坏(在二进制文件就位的情况下，`wevtutil im <manifest>.man` 可以重新注册)。

## 解决方法 3:在源主机上渲染

只有当提供程序存在于本地时，`Get-WinEvent` 才会填充 `Message` 属性。在源主机(或安装了相同软件的机器)上，下面的命令可以正常工作:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

在你的工作站上，同一条命令返回的 `Message` 为空，但 `.Properties` 和 `.ToXml()` 依然能拿到每一个值。更多过滤技巧见[用 Get-WinEvent 查询 EVTX](/en/blog/query-evtx-powershell-get-winevent)(英文)。

## 解决方法 4:通常你并不需要这条消息

在 DFIR 中，渲染后的句子只是一种便利。它要显示的每个值都在 `<EventData>` 里:`TargetUserName`、`LogonType`、`IpAddress`、`Status`、`SubStatus`。即使“常规”选项卡显示错误，事件查看器的 **“详细信息”** 选项卡(XML 视图)依然会显示这些字段。大规模分析的人员本来就直接读字段，[4624](/zh/blog/understanding-event-id-4624) 以及整个[登录事件家族](/en/blog/windows-logon-events-explained)都应这样处理：字段名在不同 Windows 版本和语言之间保持稳定，而渲染出来的文字不是。

## 在浏览器中离线读取事件

[EVTX 解析器](/zh)现在会为约 60 个常见 DFIR 事件显示一行可读描述：登录及 4625 失败、账户和组变更、Kerberos 4768/4769/4771、NTLM 4776、服务 7045/4697、计划任务、Sysmon、PowerShell 4104 和 RDP。它还会直接解码 `%%` 代码、NTSTATUS 代码(`0xC000006A` 密码错误、`0xC0000064` 未知用户)以及 Kerberos 票据加密类型(`0x17` RC4)。不需要任何提供程序 DLL,也不需要 Windows;文件在浏览器中解析，从不上传。打开文件的其他方式，请参阅[如何打开 EVTX 文件](/zh/blog/how-to-open-an-evtx-file)。

## 检查清单

- 这个错误表示**进行显示的机器**缺少提供程序，而不是记录已损坏。
- 通过“详细信息”选项卡、`Get-WinEvent` 的 `.Properties` 或解析器读取 `<EventData>`。
- 用上表解码 `%%` 引用;把 `Status` / `SubStatus` 当作 NTSTATUS 解码。
- 报告里需要渲染后的文字?在源主机上带显示信息(`LocaleMetaData`)重新导出，或使用 `wevtutil al`。
- 对于自家软件，修正 `EventMessageFile` 或重新注册清单。
