---
title: "Event ID 4624 explained: Windows successful logon & LogonType reference"
description: "What a 4624 record actually contains, why the LogonType field matters more than the event itself, and how to read them at scale."
date: "2026-05-17"
---

Event ID 4624 — "An account was successfully logged on" — is logged on the `Security` channel every time Windows authenticates an identity. It is the single highest-traffic record on most workstations and the spine of almost every IR investigation. Knowing how to read one is non-negotiable.

## What's inside a 4624 record

The interesting parts live in `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

The `Subject*` fields are the security context that *requested* the logon (often `S-1-5-18` for SYSTEM during service starts). The `Target*` fields are the identity that ended up authenticated. Confusing these costs analysts hours.

## LogonType is the field that matters

Windows ships ten logon types; in practice only a handful drive triage:

- **2 — Interactive**: physical or console logon.
- **3 — Network**: SMB, RPC, WinRM, anything across the wire. The vast majority of normal traffic.
- **4 — Batch**: scheduled tasks running as a user.
- **5 — Service**: a service started under a specific account.
- **7 — Unlock**: workstation unlocked after a screen lock.
- **8 — NetworkCleartext**: rare, suspicious — credentials sent in cleartext (Basic auth on IIS, some old printers).
- **9 — NewCredentials**: `runas /netonly`, often used by attackers carrying domain creds onto a machine they only have local rights on.
- **10 — RemoteInteractive**: RDP. Pairs with `IpAddress` for source attribution.
- **11 — CachedInteractive**: domain account logged on with cached credentials (no DC reachable).

A 4624 with LogonType **10** from an external IP at 03:00 on a Sunday tells a different story than 50 LogonType **3** events from a backup server at 02:00.

## What to chain it with

A successful 4624 alone is rarely a finding. It becomes one when paired with:

- [**4625**](/en/blog/detecting-4625-brute-force) preceding it from the same source — a successful logon after a burst of failures is the textbook brute-force-then-success signature.
- [**4672**](/en/blog/event-id-4672-special-privileges) (special privileges assigned) — flags logons that granted privileges like `SeDebugPrivilege`, useful for finding privileged-account use.
- **4648** (logon with explicit credentials) — captures `runas` and other credential-passing patterns.
- [**7045**](/en/blog/service-creation-event-id-7045) following it with LogonType 3 — service install after a network logon is the PsExec lateral-execution signature.

## The triage patterns

The five patterns that actually fire alerts in a real SOC, in rough order of how often they earn their keep:

1. **Brute-force-then-success**: a burst of [4625](/en/blog/detecting-4625-brute-force) from one source IP followed within minutes by a 4624 from the same IP for the same `TargetUserName`. The attacker found a working credential. Cheapest catch in the audit catalog.
2. **Off-hours RDP**: 4624 with `LogonType=10` from an external IP outside business hours. Tag known admin VPN egress IPs; everything else is a real lead.
3. **`runas /netonly`**: 4624 with `LogonType=9`. Legitimate use is rare (admin tools running with foreign-domain credentials); attacker use is a credential-pivot pattern after capturing creds from one host they don't want to surface on.
4. **NetworkCleartext (LogonType=8)**: cleartext credentials over the wire. Real causes are old Basic-auth IIS apps, ancient printers, or misconfigured LDAP simple binds. Each one is a credential-leak liability.
5. **LogonType drift on service accounts**: a service account that historically only fires LogonType 3 (network) suddenly producing LogonType 10 (RDP) or LogonType 2 (interactive console). Almost always means somebody is using the service account interactively — a strong "stolen creds" signal.

## Sample Sigma rule — successful logon after failure burst

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source — brute-force-then-success.
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: windows
  service: security
detection:
  fail_burst:
    EventID: 4625
  success:
    EventID: 4624
    LogonType:
      - 3
      - 10
  timeframe: 10m
  condition: ( fail_burst | count() by IpAddress,TargetUserName > 10 ) and success
falsepositives:
  - Users repeatedly typing passwords after a recent password change
  - SSO endpoints with retry behavior on first auth
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## Sample KQL — off-hours RDP from external IPs

KQL (Sentinel / Defender XDR via `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and not (IpAddress startswith "172." and toint(split(IpAddress, ".")[1]) between (16 .. 31))
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 7 or Hour > 20
| project TimeGenerated, Account, IpAddress, WorkstationName, Computer
| order by TimeGenerated desc
```

## Sample Splunk — LogonType drift on a service account

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

Service accounts should produce a single, stable `LogonType` (usually 3 or 5). Multiple types under the same account name is the alert.

## ATT&CK mapping

- **T1078 — Valid Accounts** (and sub-techniques `.001` Default, `.002` Domain, `.003` Local): every successful logon by a legitimately compromised credential maps here. 4624 is the *evidence* of the technique.
- **T1110 — Brute Force**: combined with [4625](/en/blog/detecting-4625-brute-force) bursts.
- **T1021 — Remote Services** (and sub-techniques `.001` RDP, `.002` SMB, `.006` WinRM): the bulk of network-side 4624 LogonType=3/10 traffic.
- **T1550 — Use Alternate Authentication Material**: `.002` Pass the Hash (NTLM-package 4624 from unexpected source), `.003` Pass the Ticket (Kerberos-package 4624 with no matching [4769](/en/blog/event-id-4769-kerberoasting) on any DC).

## False positives that look exactly like attacks

- **Vulnerability scanners** (Tenable, Qualys, Rapid7) generate dense 4624 LogonType=3 traffic from a stable set of scanner IPs. Tag and exclude.
- **SCCM / Intune client check-ins** produce recurring 4624 traffic to management endpoints.
- **Backup agents** authenticate to many hosts on a schedule — looks like spread, isn't.
- **Citrix / RDS multi-session boxes** legitimately see LogonType=10 from many internal IPs. Filter by source range.
- **Password change UX**: users who just changed a password and re-typed the old one twice produce 4625 → 4625 → 4624 — that's not brute force, it's muscle memory.

The signal is *unexpected* recurrence or *novel* combinations, not raw volume.

## What 4624 doesn't tell you

- **No process information**: you see the logon, not what ran in the resulting session. Pivot `LogonId` to [4688](/en/blog/event-id-4688-process-creation) / [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) to see process activity.
- **No source process** for the logon itself — you know NTLM or Kerberos was used, but not which client app initiated it.
- **`IpAddress` can be empty or `-`** for NTLM logons from a DC; the field isn't reliable on every record.
- **Cached interactive logons (Type 11)** happen when the DC is unreachable — they confirm a credential worked locally but not that the live account is enabled at the DC.

## Reading them at scale

The parser on this page extracts these fields directly from the record's XML and exposes them in the table. Filter by `LogonType` via the timeline buckets and the text filter (`4624` in the search), pull the filtered set as CSV, and pivot on `SubjectUserSid` + `IpAddress` in your tool of choice. The full XML for each record is one click away.
