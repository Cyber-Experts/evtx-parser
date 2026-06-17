---
title: "Scheduled task persistence: Event ID 4698 and the Task Scheduler log"
description: "How attackers use scheduled tasks for persistence and what it leaves in the event logs — Security 4698/4699/4700/4701/4702 with the full task XML, and the Task Scheduler Operational log 106/140/141/200."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - persistence
  - scheduled-tasks
  - threat-hunting
author: "Florian Amette"
---

Scheduled tasks are one of the most common persistence mechanisms in Windows, precisely because they are mundane — every host has dozens of legitimate ones. The job in DFIR is separating the attacker's task from the noise, and the event logs give you two independent records to do it with. This sits in the [persistence theme](/en/blog/service-creation-event-id-7045) alongside service creation.

## Two logs, two views

| Log | Event IDs | What it gives you |
|-----|-----------|-------------------|
| `Security` | 4698 / 4699 / 4700 / 4701 / 4702 | task **created / deleted / enabled / disabled / updated**, with the full task XML |
| `…TaskScheduler/Operational` | 106 / 140 / 141 / 200 / 201 | task **registered / updated / deleted / action launched / action completed** |

The Security events require **Audit Other Object Access Events** to be enabled (it often is not by default), so on many hosts the Task Scheduler Operational log is your primary source — and it is on by default.

## 4698: the high-value event

Event ID **4698** ("A scheduled task was created") is the one to love, because its `TaskContent` field carries the **entire task definition as XML**. That means a single event tells you:

- **What runs** — the `<Command>` and `<Arguments>` (the payload: a binary, a script, `powershell -enc …`).
- **As whom** — the `<Principal>` `<UserId>` and `<RunLevel>`. A task created to run as `SYSTEM` / `HighestAvailable` is a privilege flag.
- **When/why it fires** — the `<Triggers>`: at logon, at boot, on a schedule, on an event. Logon and boot triggers are classic persistence.
- **Whether it hides** — `<Settings>` such as `<Hidden>true</Hidden>`.

Read the `TaskContent` XML and you usually have the whole persistence mechanism in one record. Pair `SubjectUserName` (who created it) with the [logon timeline](/en/blog/windows-logon-events-explained) to place the actor.

## The Task Scheduler Operational log

When 4698 is unavailable, lean on `Microsoft-Windows-TaskScheduler/Operational`:

- **106** — "Task registered." The creation event; carries the task name and the user that registered it.
- **140** — "Task updated"; **141** — "Task deleted." Useful for catching an attacker who creates, uses, and deletes a task to clean up.
- **200 / 201** — "Action started / completed." These tell you the task actually **ran**, and when — the difference between a dormant persistence task and one that has been executing.
- **129** — "Created Task Process" — names the spawned process.

A 106 followed by repeated 200/201 on a logon or boot trigger is persistence that is actively firing.

## What attacker tasks look like

Signals worth hunting:

- **Suspicious commands** — `powershell`/`cmd`/`mshta`/`rundll32`/`regsvr32` with encoded or remote arguments in the 4698 `TaskContent`.
- **Run as SYSTEM** with `HighestAvailable` — most user tasks don't.
- **Logon/boot triggers** on a task created during the incident window.
- **Hidden tasks** (`<Hidden>true</Hidden>`) — legitimate software rarely hides.
- **Odd names** mimicking Microsoft tasks (e.g. `\Microsoft\Windows\…` clones placed in the root), or random strings.
- **Create-then-delete** (106/4698 → 141/4699) within minutes around execution — run-and-clean.
- **Task created shortly after** a fresh [RDP session](/en/blog/did-someone-rdp-into-this-host) or remote logon.

## Correlate to confirm execution

A created task is intent; a fired task is action. Chain:

```
4698 / 106        task created (read the command + trigger + principal)
4624              the actor's logon, same SubjectUserName/time
200 / 201         the task's action ran
4688              the process the task spawned (with command line)
```

The Security **4688** process-creation event for the spawned process closes the loop, showing the actual command line that executed — see [4688 process creation](/en/blog/event-id-4688-process-creation).

## Hunt checklist

- Pull `Security.evtx` and `…TaskScheduler%4Operational.evtx`; load both in the [browser parser](/en/blog/how-to-open-an-evtx-file).
- Filter to **4698/4699/4700/4701/4702** and **106/140/141/200/201**.
- For every 4698 in the incident window, read the `TaskContent` XML: command, principal, trigger, hidden flag.
- Flag SYSTEM/HighestAvailable, logon/boot triggers, hidden tasks, and script-host commands.
- Confirm execution via 200/201 and the spawned 4688.
- Check for create-then-delete cleanup.

Tasks tie persistence to a specific account and a specific command in one place, which is why they are often the fastest way to answer "how did they keep coming back." For the underlying record format, see the [EVTX reference](/en/blog/evtx-file-format-reference); for who created the task, the [logon analysis](/en/blog/windows-logon-events-explained).
