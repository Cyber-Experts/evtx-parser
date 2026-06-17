---
title: "Account lockouts and password resets: 4740, 4724 and 4767"
description: "Reading account-lockout and password-change events in the Security log — 4740 (locked out) and its caller computer, 4767 (unlocked), 4723/4724 (password change vs admin reset), and what each pattern means for an investigation."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - account-management
  - threat-hunting
author: "Florian Amette"
---

Lockouts and password changes are where two very different stories meet: a user who forgot their password, and an attacker brute-forcing or taking over an account. The Security log lets you tell them apart — if you read the right fields. This rounds out the [persistence / account-management theme](/en/blog/privileged-group-changes-4732).

## The events

| Event ID | Meaning | Logged where |
|---------:|---------|--------------|
| **4740** | account **locked out** | on the DC (and the authenticating server) |
| **4767** | account **unlocked** | DC |
| **4723** | user **changed their own** password | DC / host |
| **4724** | an **admin reset** another account's password | DC / host |
| **4738** | user account **changed** (attributes) | DC / host |

These are part of **Audit User Account Management** / **Audit Account Lockout** and are on by default on domain controllers.

## 4740: who, and from where

Event ID **4740** ("A user account was locked out") is more useful than it looks because it records the **`CallerComputerName`** — the machine whose failed logons tripped the lockout. That field is the lead: a lockout sourced from a server the user has never touched, or from many machines at once, is not a forgotten password.

Read together:

- **`TargetUserName`** — the account that locked.
- **`CallerComputerName`** — the source of the bad attempts.
- Timing — a single lockout at 9 a.m. Monday is mundane; a burst across many accounts is an attack.

## Lockout + 4625: the brute-force fingerprint

A lockout is the *consequence*; the [4625 failures](/en/blog/detecting-4625-brute-force) are the *cause*. Correlate on the DC and the target host:

```
4625 ×N    sub-status 0xC000006A (bad password) from one IP/host
4740       account locked out, CallerComputerName = that host
```

- **Many 4625 against one account → 4740** = classic brute force.
- **4625 `0xC0000064` (no such user) across many accounts** = enumeration/spraying (may not lock anything).
- **A 4624 success *between* the failures and the lockout** = guessed-then-succeeded; treat the success time as the compromise.

The 4625 sub-status `0xC0000234` itself means "account locked," so seeing it is the failures hitting the lockout wall.

## Password changes vs resets: 4723 vs 4724

This distinction matters in account-takeover cases:

- **4723** — the user **changed their own** password (they knew the old one).
- **4724** — an **administrator reset** the password (no knowledge of the old one needed).

A **4724 where `SubjectUserName` ≠ `TargetUserName`** means someone reset *another* account's password. For a privileged target (a service account, an admin), an unexpected 4724 is a strong takeover signal — especially when followed by a [logon](/en/blog/windows-logon-events-explained) of that account from a new source, or by [adding it to a privileged group](/en/blog/privileged-group-changes-4732).

## Patterns worth flagging

- **4724 on a service or admin account** by a non-admin or unexpected actor.
- **4740 with a `CallerComputerName`** the user has no relationship with.
- **Repeated lockouts of one account** from a single host — either a brute force, or stale cached credentials on that host (a service running as the user with an old password). The `CallerComputerName` plus the source's [logon/process events](/en/blog/event-id-4688-process-creation) disambiguate.
- **4724 → 4624 (new source) → 4728/4732** — reset, log in, escalate: an account-takeover chain.

## Don't over-read the benign case

Lockouts are noisy in normal operations: phones with saved Wi-Fi/Exchange passwords, scheduled tasks and services running as a user whose password changed, mapped drives with stale creds. The `CallerComputerName` almost always tells you which it is — a user's own devices and known servers point to benign stale credentials; an unfamiliar host points to an attack. Always read it before escalating.

## Hunt checklist

- On DCs: filter Security to **4740 / 4767 / 4723 / 4724 / 4738**.
- For each 4740, read **`CallerComputerName`** and correlate to the [4625 failures](/en/blog/detecting-4625-brute-force) that caused it.
- For each 4724, check whether `SubjectUserName` ≠ `TargetUserName` and whether the target is privileged.
- Hunt the takeover chain: 4724 → 4624 (new source) → privileged group add.
- Separate brute force (one account, many 4625) from spraying (many accounts, `0xC0000064`).

Load the DC `Security.evtx` in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to the account-management IDs, and the lockout's cause and the reset's actor both fall out of the `CallerComputerName` and `SubjectUserName` fields.
