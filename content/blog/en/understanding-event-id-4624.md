---
title: "Event ID 4624 explained: Windows successful logon and LogonType reference"
description: "What a 4624 record actually contains, why the LogonType field matters more than the event itself, and how to read them at scale."
date: "2026-05-17"
---

Event ID 4624, "An account was successfully logged on", lands on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time Windows authenticates an identity. It is the single highest-traffic record on most workstations and the spine of almost every IR investigation. Knowing how to read one is not optional.

## What is inside a 4624 record

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

The `Subject*` fields are the security context that *requested* the logon (often `S-1-5-18` for SYSTEM during service starts). The `Target*` fields are the identity that ended up authenticated. Confusing the two costs analysts hours. I have watched a senior analyst escalate on a `Subject` that turned out to be SYSTEM running an internal service. Read both, twice, before you make the call.

## LogonType is the field that decides

Windows ships ten logon types. In practice only a handful drive triage:

- **2 Interactive**. Physical or console logon.
- **3 Network**. SMB, RPC, WinRM, anything across the wire. The vast majority of normal traffic.
- **4 Batch**. Scheduled tasks running as a user.
- **5 Service**. A service started under a specific account.
- **7 Unlock**. Workstation unlocked after a screen lock.
- **8 NetworkCleartext**. Rare and suspicious. Credentials sent in cleartext (Basic auth on IIS, ancient printers, misconfigured LDAP simple bind).
- **9 NewCredentials**. `runas /netonly`. Often used by attackers carrying domain creds onto a machine they only have local rights on.
- **10 RemoteInteractive**. RDP. Pairs with `IpAddress` for source attribution.
- **11 CachedInteractive**. Domain account logged on with cached credentials. No DC reachable.

A 4624 with LogonType **10** from an external IP at 03:00 on a Sunday tells a very different story than 50 LogonType **3** records from a backup server at 02:00.

## What to chain it with

A successful 4624 alone is rarely a finding. It becomes one when paired with:

- [4625](/en/blog/detecting-4625-brute-force) preceding it from the same source. A success after a burst of failures is the textbook brute-force-then-success signature.
- [4672](/en/blog/event-id-4672-special-privileges). Flags logons that granted privileges like `SeDebugPrivilege`.
- 4648 (logon with explicit credentials). Captures `runas` and other credential-passing patterns. Most defenders underuse this.
- [7045](/en/blog/service-creation-event-id-7045) following it with LogonType 3. Service install after a network logon is the PsExec signature.

## The five patterns

The ones that actually fire alerts in a real SOC, in rough order of how often they earn their keep:

1. **Brute-force-then-success.** A burst of [4625](/en/blog/detecting-4625-brute-force) from one source IP followed within minutes by a 4624 from the same IP for the same `TargetUserName`. Attacker found a working credential. Cheapest catch in the audit catalog.
2. **Off-hours RDP.** 4624 with `LogonType=10` from an external IP outside business hours. Tag known admin VPN egress IPs. Everything else is a real lead.
3. **`runas /netonly`.** 4624 with `LogonType=9`. Legitimate use is rare (admin tools using foreign-domain credentials). Attacker use is a credential-pivot pattern after capturing creds from one host they do not want to surface on.
4. **NetworkCleartext (LogonType=8).** Cleartext credentials over the wire. Real causes are old Basic-auth IIS apps, ancient printers, or misconfigured LDAP simple binds. Each is a credential-leak liability.
5. **LogonType drift on service accounts.** A service account that historically only fires LogonType 3 suddenly producing LogonType 10 or LogonType 2. Almost always means somebody is using the service account interactively. Strong stolen-creds signal.

## Sigma: successful logon after failure burst

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source. Brute-force-then-success.
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

## KQL: off-hours RDP from external IPs

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

## Splunk: LogonType drift on a service account

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

Service accounts should produce a single, stable `LogonType` (usually 3 or 5). Multiple types under the same account is the alert.

## ATT&CK mapping

- T1078 Valid Accounts (and sub-techniques `.001` Default, `.002` Domain, `.003` Local). Every successful logon by a compromised credential maps here. 4624 is the *evidence* of the technique.
- T1110 Brute Force. Combined with [4625](/en/blog/detecting-4625-brute-force) bursts.
- T1021 Remote Services (`.001` RDP, `.002` SMB, `.006` WinRM). The bulk of network-side 4624 LogonType=3/10 traffic.
- T1550 Use Alternate Authentication Material. `.002` Pass the Hash (NTLM-package 4624 from unexpected source), `.003` Pass the Ticket (Kerberos-package 4624 with no matching [4769](/en/blog/event-id-4769-kerberoasting) on any DC).

## False positives that look exactly like attacks

- Vulnerability scanners (Tenable, Qualys, Rapid7) generate dense 4624 LogonType=3 traffic from a stable set of scanner IPs. Tag and exclude.
- SCCM and Intune client check-ins produce recurring 4624 traffic to management endpoints.
- Backup agents authenticate to many hosts on a schedule. Looks like spread. Is not.
- Citrix and RDS multi-session boxes legitimately see LogonType=10 from many internal IPs. Filter by source range.
- Password change UX. Users who just changed a password and re-typed the old one twice produce 4625 / 4625 / 4624. That is not brute force, it is muscle memory.

The signal is *unexpected* recurrence or *novel* combinations, not raw volume.

## What 4624 does not tell you

- No process information. You see the logon, not what ran in the resulting session. Pivot `LogonId` to [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) to see process activity.
- No source process for the logon itself. You know NTLM or Kerberos was used, but not which client app initiated it.
- `IpAddress` can be empty or `-` for NTLM logons from a DC. The field is not reliable on every record.
- Cached interactive logons (Type 11) happen when the DC is unreachable. They confirm a credential worked locally, not that the live account is enabled at the DC.

## Reading at scale

The [browser parser on this site](/en/blog/how-to-open-an-evtx-file) extracts these fields directly from the record's XML and exposes them in the table. Filter by `LogonType` via the timeline buckets and the text filter, pull the filtered set as CSV, then pivot on `SubjectUserSid` and `IpAddress` in your tool of choice. The full XML for each record is one click away. Pair it with [RDP cache artifacts](https://www.jumplistparser.com), [recent file](https://www.recentfilecacheparser.com) tracking, and [browser history](https://www.browserforensics.app) when the user account in question is a real user, not a service.

## Further reading

- [Microsoft documentation for 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
