---
title: "Event ID 4625 explained: detecting brute force, sprays and enumeration"
description: "4625 is the failed-logon record. Read it right and you spot password sprays, credential stuffing, and Kerberos abuse before they turn into a success."
date: "2026-05-17"
---

Event ID 4625, "An account failed to log on", fires on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time an authentication attempt is rejected. It is the single most useful record for catching credential attacks in flight. It is also the record analysts most often misread, because the headline message is generic and the answer lives two fields deeper.

## The fields that decide the call

A typical record:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` and `SubStatus` together tell you why the logon failed. The pair you actually care about is `SubStatus`. The codes worth memorising:

- `0xC0000064`: account does not exist. Username enumeration.
- `0xC000006A`: bad password. The classic.
- `0xC0000234`: account locked out.
- `0xC0000072`: account disabled.
- `0xC0000071`: password expired.
- `0xC0000133`: clock skew on Kerberos. Common during AS-REP roasting attempts where the attacker spoofed a time.
- `0xC000018B`: wrong SID, the workstation thinks it is in a domain it is not. Rare and interesting.

A burst of `0xC0000064` across mixed valid and invalid usernames is reconnaissance. A burst of `0xC000006A` against one account is brute force. A burst of `0xC000006A` against many accounts using the *same* password is a spray. Same event ID, three different incidents.

## The triage queries that earn their keep

1. Spray detection. Group 4625 by `IpAddress` (or `WorkstationName` if the IP field is empty), count distinct `TargetUserName` over 10 minutes. More than five accounts per source in that window is suspicious almost everywhere.
2. Brute force. Group by `TargetUserName`, count failures per minute. More than ten per minute against one account is almost always automated.
3. Lockout root cause. Pair 4740 (account locked) with the preceding 4625s. The `WorkstationName` field will tell you which device triggered the lockout. Most of the time it is a domain-joined server with a stale cached credential, not an attacker. The triage matters because the helpdesk treats both the same way and the SOC has to pick which one to escalate.

## The "after" decides the response

A 4625 burst followed by a [4624](/en/blog/understanding-event-id-4624) from the same `IpAddress` is the actionable case. The attacker found a working credential. The progression in the timeline is unmistakable: dense failures, sudden silence, single success.

## Sigma: password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL: brute force against one account

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: enumeration leading into brute

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

The signal is the *progression*: enumeration to find valid usernames first, then targeted password attempts. A real operator with a fresh user list will produce both shapes within minutes.

## ATT&CK mapping

- T1110.001 Brute Force: Password Guessing. Single account, many `0xC000006A` failures.
- T1110.003 Brute Force: Password Spraying. Many accounts, one source, few failures each.
- T1110.004 Credential Stuffing. Many accounts, one source, mixed `0xC0000064` (account does not exist, leaked-list miss) and `0xC000006A` (hit).
- T1078 Valid Accounts. 4625 burst followed by [4624](/en/blog/understanding-event-id-4624) success from the same source. Compromise.
- T1556 Modify Authentication Process. Anomalous `LogonProcessName` (anything other than `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) suggests tampering.

## False positives that wear the costume

- Stored credentials going stale after a password change. The user's mapped drives, scheduled tasks, or service configs retry the old password. The shape is one `TargetUserName`, one `IpAddress`, steady `0xC000006A` cadence. Find the host with the stale credential and fix it before alerting.
- Misconfigured automation. A script with the wrong password retrying in a loop. Same shape as brute force. Talk to the owner first.
- Vulnerability scanners during authenticated scans produce dense 4625 traffic. Tag scanner IPs.
- Lockout-policy churn. Helpdesk procedures that unlock aggressively create repeating 4625 to 4740 to 4624 cycles. Annoying. Not malicious.

## What 4625 hides

Kerberos and NTLMv2 failures coming through a DC do not always carry a useful `IpAddress`. The field can be empty or `-`. For those, you pivot to the DC's records: [4768](/en/blog/event-id-4768-kerberos-tgt) and 4771 for Kerberos pre-auth failures. "No source IP, no investigation" is the wrong instinct. Look at the DC log instead.

The `LogonProcessName` and `AuthenticationPackageName` fields tell you which auth stack handled the attempt. Useful values: `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (picks one of the two), `User32` (local console), `Schannel` (TLS-backed). Anything else, look harder.

## Further reading

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
