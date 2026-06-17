---
title: "Querying EVTX with PowerShell: Get-WinEvent, FilterHashtable and XPath"
description: "A practical guide to reading .evtx files with PowerShell — Get-WinEvent vs Get-EventLog, the fast FilterHashtable path, XPath filters for EventData fields, FilterXml, and the limitations that trip people up."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - powershell
  - how-to
author: "Florian Amette"
---

PowerShell is on every Windows box, which makes `Get-WinEvent` the parser you always have. Used well it queries a saved `.evtx` in milliseconds; used badly it loads a million objects into memory and crawls. This is the practical version: the patterns that are fast and the gotchas that aren't. For a no-install, in-browser alternative, there is also the [parser on this site](/en/blog/how-to-open-an-evtx-file).

## Get-WinEvent, not Get-EventLog

`Get-EventLog` is the legacy cmdlet — it only reads the classic logs (Application/System/Security) and is slow. `Get-WinEvent` reads **any channel and any saved `.evtx` file**, understands the modern schema, and supports server-side filtering. Use it.

Read a saved file:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 50
```

Read a live channel:

```powershell
Get-WinEvent -LogName Security -MaxEvents 50
```

## The cardinal rule: filter at the source

The single biggest mistake is filtering with `Where-Object` *after* retrieval:

```powershell
# SLOW — deserialises every event, then filters
Get-WinEvent -Path .\Security.evtx | Where-Object { $_.Id -eq 4624 }
```

`Get-WinEvent` can filter **before** materialising objects, via `-FilterHashtable` (or XPath). That is orders of magnitude faster on big logs:

```powershell
# FAST — filtering pushed down to the log reader
Get-WinEvent -FilterHashtable @{
  Path      = '.\Security.evtx'
  Id        = 4624
  StartTime = (Get-Date).AddDays(-1)
}
```

`-FilterHashtable` keys you'll use most: `Path` or `LogName`, `Id`, `ProviderName`, `Level`, `StartTime`, `EndTime`, and `Data` (matches values, though it's positional and blunt). Combine keys with implicit AND.

## Getting at EventData fields

The hashtable can't target a *named* EventData field like `TargetUserName`. Two ways to do it.

**Property access after a cheap ID filter** — readable, fine for moderate volumes:

```powershell
Get-WinEvent -FilterHashtable @{Path='.\Security.evtx'; Id=4624} |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    [pscustomobject]@{
      Time = $_.TimeCreated
      User = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
      Type = ($x.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
      Src  = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
    }
  }
```

**XPath, pushed down to the reader** — fastest, but with caveats below:

```powershell
# All 4624s
Get-WinEvent -Path .\Security.evtx `
  -FilterXPath "*[System[EventID=4624]]"

# 4624 where TargetUserName = 'alice'
Get-WinEvent -Path .\Security.evtx -FilterXPath @"
*[System[EventID=4624]] and *[EventData[Data[@Name='TargetUserName']='alice']]
"@
```

This is the same XPath dialect Event Viewer's custom views use — the queries transfer both ways.

## XPath limitations that bite

Windows implements a *limited* XPath 1.0. The trap people hit: **string functions are not supported** in the event-log filter. So this **errors**:

```powershell
# FAILS — contains() / starts-with() are not allowed here
Get-WinEvent -Path .\Security.evtx `
  -FilterXPath "*[EventData[Data[contains(.,'admin')]]]"
```

You get exact-match (`=`), `and`/`or`, and positional/attribute predicates — not `contains`, `starts-with`, or other string functions. For substring/regex matching, filter to the ID with XPath/hashtable first, then match in PowerShell on the materialised text, or use the [in-browser parser's](/en/blog/how-to-open-an-evtx-file) text filter.

## FilterXml for complex queries

For multi-clause queries it's cleaner to build the XML once (export it from a Event Viewer custom view, even) and pass it via `-FilterXml`:

```powershell
$q = @"
<QueryList>
  <Query Id="0" Path="file://./Security.evtx">
    <Select Path="file://./Security.evtx">
      *[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]
    </Select>
  </Query>
</QueryList>
"@
Get-WinEvent -FilterXml ([xml]$q)
```

## A few recipes

```powershell
# Failed logons grouped by source IP
Get-WinEvent -FilterHashtable @{Path='.\Security.evtx'; Id=4625} |
  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object Name -eq 'IpAddress' | Select-Object -Exp '#text' } |
  Group-Object | Sort-Object Count -Descending

# Scheduled tasks created (4698) with their command
Get-WinEvent -FilterHashtable @{Path='.\Security.evtx'; Id=4698} |
  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object Name -eq 'TaskContent' | Select-Object -Exp '#text' }
```

(The fields these pull are explained in the [logon](/en/blog/windows-logon-events-explained) and [scheduled-task](/en/blog/scheduled-task-persistence-4698) posts.)

## Gotchas worth knowing

- **`-Oldest`.** For Analytic/Debug and some `.evtx` files you must add `-Oldest` or `Get-WinEvent` errors.
- **No-match is a terminating error.** A filter that matches nothing throws "No events were found"; wrap in `try/catch` or `-ErrorAction SilentlyContinue` in scripts.
- **Time zone.** `TimeCreated` is rendered in local time by PowerShell, but the underlying value is [UTC FILETIME](/en/blog/evtx-file-format-reference) — be explicit when correlating across machines.
- **Speed.** Always filter with `-FilterHashtable`/XPath; reserve `Where-Object` for the small set that survives.

When the query outgrows ad-hoc PowerShell — detection rules across many files — that's the job for [Sigma with Chainsaw or Hayabusa](/en/blog/sigma-rules-evtx-chainsaw-hayabusa).
