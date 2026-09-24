---
title: "\"The description for Event ID cannot be found\": fix it"
description: "Why Event Viewer says the description for an Event ID cannot be found, what %%1833-style codes mean, and how to read the event anyway, offline."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "What does \"The description for Event ID X from source Y cannot be found\" mean?"
    answer: "The event record itself is fine. An .evtx record stores only the event ID, the provider name and the insertion strings (EventData / UserData). The sentence you normally read in Event Viewer is a template stored in the provider's message DLL on the machine doing the viewing. If that provider is not registered on your machine, Event Viewer cannot build the sentence and shows this error followed by the raw insertion strings."
  - question: "Is the event data lost or corrupted?"
    answer: "No. Every field is still in the record. Open the Details tab (XML View) in Event Viewer, or read the EventData fields with Get-WinEvent, wevtutil or a parser. Only the human-readable wrapper text is missing."
  - question: "What does %%1833 mean in an event?"
    answer: "%%1833 is a parameter message reference resolved from msobjs.dll, the Security auditing provider's parameter message file. %%1833 means Impersonation (the ImpersonationLevel field on 4624). Other common ones: %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 token elevation type 1/2/3."
  - question: "How do I export an .evtx so it opens with descriptions on another computer?"
    answer: "On the source machine, in Event Viewer use Save All Events As, choose .evtx, and select Display information for these languages. Event Viewer writes a LocaleMetaData folder with .MTA files next to the .evtx. Copy both together. wevtutil archive-log (wevtutil al) does the same from the command line."
  - question: "Can I read the event without installing the provider?"
    answer: "Yes. For DFIR you rarely need the rendered message: the EventData fields hold every value the message would show. The browser-based parser on evtxparser.com also shows a one-line description for common DFIR events and decodes %% codes, NTSTATUS codes and Kerberos encryption types offline, without uploading the file."
---

You copy a `Security.evtx` off a suspect host, open it on your analysis workstation, and every record reads:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

Then a block of raw values: `%%2313`, `0xC000006A`, `0x17`. Nothing is broken and nothing is lost. The message is a *rendering* failure, not a data failure. This post explains where the description text actually lives, why it goes missing, how to fix it when you need to, and why, for triage, you usually don't. (If you just want the events readable now: [the browser parser](/en) renders descriptions and decodes those codes offline.)

## What the error actually means

An `.evtx` record does not store the sentence you read in Event Viewer. It stores the `<System>` block (provider, Event ID, time, computer) and the **insertion strings** in `<EventData>` or `<UserData>` ([what is inside a record](/en/blog/what-is-an-evtx-file)). The sentence, "An account failed to log on. Subject: … Failure Reason: …", is a template with `%1`, `%2` placeholders stored in a **message table resource** inside a DLL or EXE belonging to the event provider.

Where Windows looks for that file depends on the provider type:

- **Classic (legacy) event sources** register under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, with the path in the `EventMessageFile` value (plus optional `ParameterMessageFile` and `CategoryMessageFile`).
- **Manifest-based providers** (Vista and later, the `Microsoft-Windows-*` family) register under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. The `MessageFileName`, `ResourceFileName` and `ParameterFileName` values point to binaries that carry the compiled manifest (`WEVT_TEMPLATE` resource) and the message table.

The key point: **Event Viewer renders the message on the machine where you view the log**, using that machine's registry and DLLs. The machine that wrote the event is irrelevant at display time. If the provider is not registered locally, there is no template, and you get the error followed by the raw insertion strings.

## Common causes

- **The log came from another host.** The classic DFIR case. A third-party agent, an EDR, a SQL Server instance or a line-of-business app on the source host has no provider on your analysis workstation. Opening the file on macOS, Linux or a clean VM has the same effect: no Windows provider at all.
- **Software was uninstalled.** The uninstaller removed the DLL, but old events still reference the source.
- **Missing, corrupted or moved DLL.** The registry points to a path that no longer exists, or `EventMessageFile` is stored as `REG_SZ` instead of `REG_EXPAND_SZ` so `%SystemRoot%` never expands.
- **32/64-bit mismatch.** A 32-bit installer wrote its DLL to what it thought was `System32` (really `SysWOW64` through file-system redirection), while the registered path is read by the 64-bit Event Log stack as the real `System32`.
- **Locale.** The provider's message table exists but not in the display language, or you opened an export saved "with display information" for a different language than the one your viewer uses.

## The %% codes: parameter messages

Even when the main description renders, some fields show `%%1833` or `%%2313` instead of words. These are **parameter message** references: the value is an ID into a second message table, the provider's `ParameterMessageFile` / `ParameterFileName`. For the Security auditing provider that file is `msobjs.dll`. Offline, those references stay unresolved. The common ones worth knowing by heart:

| Code | Meaning | Where you see it |
|------|---------|------------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Type 1, full token (UAC off or built-in admin) | 4688 `TokenElevationType` |
| `%%1937` | Type 2, elevated token | 4688 `TokenElevationType` |
| `%%1938` | Type 3, limited token | 4688 `TokenElevationType` |
| `%%2307` | Account locked out | 4625 `FailureReason` |
| `%%2310` | Account currently disabled | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

The `%%2080 %%2082 %%2084` triplet is the normal signature of a freshly created account in [4720](/en/blog/event-id-4720-account-created). `%%1937` on a [4688](/en/blog/event-id-4688-process-creation) is a process started with a full admin token after a UAC prompt.

Hex values are not `%%` codes. The `Status` / `SubStatus` fields of [4625](/en/blog/detecting-4625-brute-force) are NTSTATUS codes: `0xC000006A` is a wrong password for a valid account, `0xC0000064` a user name that does not exist, `0xC0000234` a locked-out account. `TicketEncryptionType` on [4769](/en/blog/event-id-4769-kerberoasting) is a Kerberos etype: `0x17` is RC4-HMAC, `0x12` AES256. Both render as raw hex even when the provider is present.

## Fix 1: export with display information

If you still have access to the source host, export the log so it travels with its messages. In Event Viewer: right-click the log, **Save All Events As…**, choose `.evtx`, and in the next dialog select **Display information for these languages**. Event Viewer writes a `LocaleMetaData` folder next to the file containing one `.MTA` file per language. Keep the folder beside the `.evtx` when you copy it; Event Viewer on the analysis machine picks it up.

From the command line:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) adds the locale metadata for an exported file. For collection at scale, see [collecting EVTX from a live system](/en/blog/collecting-evtx-from-live-system).

## Fix 2: install or repair the provider

On a machine you administer, where events from your own software don't render:

- Reinstall or repair the application that owns the source.
- Check `EventMessageFile` under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`: the path must exist, and the value type should be `REG_EXPAND_SZ` if it contains `%SystemRoot%`.
- For manifest providers, check `Get-WinEvent -ListProvider <Name>`; if it errors or lists no messages, the manifest registration is broken (`wevtutil im <manifest>.man` re-registers it, with the binaries in place).

## Fix 3: render on the source host

`Get-WinEvent` renders the `Message` property only when the provider is present locally. On the source host (or a machine with the same software installed), this works:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

On your workstation the same command returns an empty `Message`, but `.Properties` and `.ToXml()` still expose every value. More filtering recipes in [querying EVTX with Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent).

## Fix 4: you usually don't need the message

For DFIR, the rendered sentence is a convenience. Every value it would display is in `<EventData>`: `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. Event Viewer's **Details** tab (XML View) shows them even when the General tab shows the error. Analysts working at scale read the fields directly anyway, which is how you should approach [4624](/en/blog/understanding-event-id-4624) and the rest of the [logon event family](/en/blog/windows-logon-events-explained): the field names are stable across Windows versions and languages, while the rendered text is not.

## Reading events offline in the browser

[EVTX parser](/en) now shows a readable one-line description for about 60 common DFIR events: logons and 4625 failures, account and group changes, Kerberos 4768/4769/4771, NTLM 4776, services 7045/4697, scheduled tasks, Sysmon, PowerShell 4104 and RDP. It also decodes `%%` codes, NTSTATUS codes (`0xC000006A` wrong password, `0xC0000064` unknown user) and Kerberos ticket encryption types (`0x17` RC4) inline. It needs no provider DLLs and no Windows; the file is parsed in your browser and never uploaded. For other ways to open the file, see [how to open an EVTX file](/en/blog/how-to-open-an-evtx-file).

## Checklist

- The error means **the viewing machine** lacks the provider, not that the record is damaged.
- Read `<EventData>` in the Details tab, `Get-WinEvent` `.Properties`, or a parser.
- Decode `%%` references against the table above; decode `Status` / `SubStatus` as NTSTATUS.
- Need the rendered text for a report? Re-export on the source host with display information (`LocaleMetaData`) or `wevtutil al`.
- For your own software, fix `EventMessageFile` or re-register the manifest.
