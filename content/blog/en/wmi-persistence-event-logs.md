---
title: "WMI event-subscription persistence in the event logs"
description: "How attackers persist with permanent WMI event subscriptions (__EventFilter + __EventConsumer + __FilterToConsumerBinding) and what the WMI-Activity Operational log records — Event ID 5861 and friends."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - persistence
  - wmi
  - threat-hunting
author: "Florian Amette"
---

[WMI event-subscription persistence](https://www.reverseengineering.app/en/techniques/wmi-event-subscription) is a favourite of more capable intruders because it is fileless, runs as `SYSTEM`, and survives reboots without a registry Run key or a scheduled task to find. It is also less understood than [scheduled tasks](/en/blog/scheduled-task-persistence-4698) or [services](/en/blog/service-creation-event-id-7045) — so it gets missed. The good news: modern Windows logs the registration. This post is about finding it.

## How the persistence works

A permanent WMI event subscription has three parts, all stored in the WMI repository (`OBJECTS.DATA`):

1. **`__EventFilter`** — *when* to fire: a WQL query, e.g. "every time the clock hits a certain interval" or "when a process named X starts."
2. **`__EventConsumer`** — *what* to run. The dangerous ones are `CommandLineEventConsumer` (runs a command) and `ActiveScriptEventConsumer` (runs VBScript/JScript).
3. **`__FilterToConsumerBinding`** — the glue that ties a filter to a consumer and activates the whole thing.

When the filter's condition is met, the consumer's payload runs — typically as `SYSTEM`. No file on disk, no obvious autorun.

## What the logs record

The relevant log is `Microsoft-Windows-WMI-Activity/Operational`, which is on by default:

| Event ID | Meaning |
|---------:|---------|
| **5861** | a **permanent event consumer** was registered (the binding) — the headline persistence event |
| 5859 | event-subscription / ESS activity |
| 5860 | a **temporary** event consumer was registered |
| 5858 | a WMI operation failed (error, with the client process/user) |
| 5857 | a WMI provider was loaded |

**5861** is the one to hunt. It is logged when a `__FilterToConsumerBinding` is registered, and on modern Windows it includes details of the consumer and the query — often enough to see the malicious command directly in the event. A 5861 referencing a `CommandLineEventConsumer` or `ActiveScriptEventConsumer` with a script-host or encoded payload is persistence until proven otherwise.

## Reading a 5861

Look in the event text for:

- The **consumer type** — `CommandLineEventConsumer` and `ActiveScriptEventConsumer` are the script-capable ones attackers use; `NTEventLogEventConsumer` is benign-ish.
- The **command / script** carried by the consumer — frequently `powershell -enc …`, `mshta`, a dropped script path, or inline VBScript.
- The **filter query (WQL)** — the trigger. Common attacker triggers watch for a time interval (`__InstanceModificationEvent` on `Win32_LocalTime`/`Win32_PerfFormattedData…`) so the payload fires periodically, or for user logon.

## Why it gets missed (and how not to)

- **It's not where people look.** Analysts check Run keys, services, and tasks; WMI is a step beyond. Add 5861 to your persistence sweep by default.
- **Logging gaps.** Older Windows logged far less WMI detail; if 5861 is sparse, corroborate from the WMI repository itself (`OBJECTS.DATA`) offline.
- **5858 as a breadcrumb.** Frequent 5858 errors record the **client process and user** doing WMI operations — useful for spotting WMI used for [lateral movement](/en/blog/detect-lateral-movement-evtx) (remote process creation via `Win32_Process.Create`), not just persistence.

## Correlate to the actor

WMI persistence is usually planted from an interactive or remote session. Chain:

```
4624 (+4672)   the actor's privileged logon
5861           __FilterToConsumerBinding registered (read the consumer + WQL)
… later …
4688           the SYSTEM process the consumer spawned (command line)
```

The spawned [4688](/en/blog/event-id-4688-process-creation) with a `SYSTEM` parent and a script-host command line, recurring on the filter's schedule, is the persistence firing.

## Hunt checklist

- Pull `…WMI-Activity%4Operational.evtx`; filter to **5861** (and 5860/5859/5858).
- For each 5861, read the **consumer type**, the **command/script**, and the **WQL trigger**.
- Flag `CommandLineEventConsumer` / `ActiveScriptEventConsumer` with script-host or encoded payloads.
- Use **5858** to surface WMI-driven remote execution (client process/user).
- Correlate to the planting [logon](/en/blog/windows-logon-events-explained) and to recurring `SYSTEM` [4688](/en/blog/event-id-4688-process-creation) executions.

WMI persistence is fileless but not invisible — 5861 is the thread to pull. Load the WMI-Activity log in the [browser parser](/en/blog/how-to-open-an-evtx-file) and filter to it; for the record format underneath, see the [EVTX reference](/en/blog/evtx-file-format-reference).
