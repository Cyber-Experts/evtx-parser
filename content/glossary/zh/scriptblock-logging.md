---
title: "ScriptBlock logging"
description: "PowerShell feature that records the full text of every script that runs — interactive commands, scripts from disk, and bodies reflected into memory by Invoke-Expression."
date: "2026-01-01"
---

PowerShell feature that records the full text of every script that runs — interactive commands, scripts from disk, and bodies reflected into memory by Invoke-Expression. The records land under event 4104 on the PowerShell/Operational channel and capture content after decoding/reflection, surviving most obfuscation.
