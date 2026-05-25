---
title: "LogonId"
description: "A 64-bit identifier Windows assigns to each logon session."
date: "2026-01-01"
---

A 64-bit identifier Windows assigns to each logon session. Lets you link records across channels (4624 / 4634 / 4647 / Sysmon 1) to the same session even when SIDs are too generic to disambiguate. SubjectLogonId on 1102 pivots to the 4624 that created the privileged session.
