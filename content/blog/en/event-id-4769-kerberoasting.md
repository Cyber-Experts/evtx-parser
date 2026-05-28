---
title: "Event ID 4769 explained: Kerberos service tickets and kerberoasting"
description: "4769 is the DC's record of every service-ticket request. Read it through the encryption type and you spot kerberoasting. Read it with 4768 and you spot pass-the-ticket."
date: "2026-05-24"
---

Event ID **4769**, "A Kerberos service ticket was requested", fires on every Domain Controller every time any account requests a TGS (Ticket Granting Service) ticket for a service. Every SMB connection, every SQL login, every web SSO hit produces one on whichever DC handled the request. It is the highest-volume record in the [Security channel](/en/blog/what-is-an-evtx-file) on a busy DC, and the only place kerberoasting reliably shows up before the credentials are cracked offline.

If you only instrument three Security records from your DCs, this is one of them.

## Where it lives

`4769` is written to the Security channel of the **issuing Domain Controller** only. Not the client, not the target service. To see all 4769 records for a domain, you have to collect from every DC. KAPE's `EventLogs` target on a DC, or forwarding Security via WEF to a collector, both work. WEF is what mature shops use.

## What the record contains

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

The fields that drive triage:

- `TargetUserName`. The requester (the user account, in `user@DOMAIN` form).
- `ServiceName`. The SPN being requested. A user account here (rather than `host/...` or a service class) is suspicious.
- `TicketEncryptionType`. The field that decides whether this record matters. Modern domains run `0x12` (AES-256-CTS-HMAC-SHA1-96) or `0x11` (AES-128). **`0x17` is RC4-HMAC**: legacy, weak, and the *only* encryption type Mimikatz and Rubeus' `kerberoast` mode requests. A 4769 for a service account ticket with `0x17` is a textbook kerberoasting fingerprint.
- `Status`. `0x0` is success. Anything else is denied (codes documented in `[MS-KILE]`).
- `IpAddress`. Requesting host. Pair with [4624](/en/blog/understanding-event-id-4624) on that host to see the logon that produced the session.

## TicketEncryptionType: the field that decides

| Value | Algorithm | Status |
|---|---|---|
| 0x01 | DES-CBC-CRC | Disabled by default since Win7 |
| 0x03 | DES-CBC-MD5 | Disabled by default since Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Modern |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Modern (default for most accounts) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Required for kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | Export-grade RC4, vanishingly rare |

If the domain has been baselined and `msDS-SupportedEncryptionTypes` set to AES-only on service accounts, `0x17` should not appear for those accounts at all. Attackers request `0x17` explicitly because cracking RC4-encrypted service tickets is computationally cheap. AES is not. The cracking tool *has* to request 0x17.

This is the single highest-signal field on the record.

## The kerberoasting pattern

Kerberoasting (T1558.003) works like this:

1. Attacker authenticates with any domain user (no admin rights needed).
2. Attacker enumerates SPNs registered to user accounts (not computer accounts), typically via LDAP `(servicePrincipalName=*)` filtered to user objects.
3. Attacker requests a TGS for each SPN with `etype=23` (RC4) via the standard Kerberos protocol. The 4769 you are looking for.
4. The DC happily issues the ticket, encrypted with the service account's NTLM hash.
5. Attacker pulls the encrypted blob and cracks it offline in Hashcat (`-m 13100`).

The 4769 fingerprint:

- `ServiceName` is `MSSQLSvc/...`, `HTTP/...`, `LDAP/...`, or any SPN pointing at a user account (not `host/...` or `cifs/...`, which are computer accounts).
- `TicketEncryptionType` is `0x17`.
- A burst within a short window, from the same source, for many SPNs.

A related pattern, **AS-REP roasting** (T1558.004), uses [4768](/en/blog/event-id-4768-kerberos-tgt) instead, targeting accounts with `DONT_REQUIRE_PREAUTH`. Different record, same family.

## Pass-the-ticket, golden, silver

4769 also reveals ticket forgery, but the signal is subtler.

- A 4769 *without* a preceding 4768 for the same `LogonGuid` from the same host in a reasonable window: golden ticket suspicion. The attacker presented a forged TGT and walked straight to TGS requests.
- A 4769 *and* the resulting service authentication on the target *without* a 4769 visible on any DC: silver ticket suspicion. The attacker forged the TGS itself. The DC was never asked.
- `LogonGuid` mismatch between 4624 on the target and the 4769 supposedly issuing the ticket: forged ticket.

These are detection-by-absence patterns. They require complete log coverage across all DCs and target services. Gaps in WEF coverage produce identical-looking false positives. Characterise your collection before alerting.

## Triage workflow

1. Filter all 4769 across the DC corpus for `TicketEncryptionType == 0x17`.
2. Group by `IpAddress` and `TargetUserName` over 30-minute windows. Count distinct `ServiceName` per source.
3. More than 3 distinct SPNs requested as 0x17 from one source within 30 minutes is kerberoasting almost everywhere.
4. Pivot the source IP to its [4624](/en/blog/understanding-event-id-4624) to find the credential that initiated the attack.
5. Pivot the requested SPNs to the owning service accounts. Rotate those passwords. Reset cracked hashes within hours, not days.

## Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

`filter_machine` excludes computer-account SPNs (which always end in `$`). Kerberoasting only targets user-account SPNs.

## KQL and Splunk

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK mapping

- T1558.003 Kerberoasting. The headline.
- T1558.001 Golden Ticket. 4769 without 4768 from the same `LogonGuid`.
- T1558.002 Silver Ticket. 4769 absent for an observed service-auth on the target.
- T1078 Valid Accounts. 4769 from an unexpected IP for a known service account.
- T1550.003 Pass the Ticket. 4769 followed by [4624](/en/blog/understanding-event-id-4624) LogonType 3 with `LogonProcessName: Kerberos`.

## False positives you will see

- Legacy applications (some old SQL Server connectors, certain Java/JBoss apps) explicitly request RC4. Steady, daytime 0x17 from a small set of stable hosts. Baseline and exclude.
- Pre-AES domains during a Kerberos hardening transition emit 0x17 broadly until `msDS-SupportedEncryptionTypes` is set on every account. Annoying. Not malicious.
- Vulnerability scanners (Tenable, Qualys, BloodHound enumeration scripts) replicate kerberoasting traffic. Tag scanner hosts.
- Account migration tools during cross-forest moves can request unusual combinations.

The signal is the *burst* pattern, not the individual record. Steady 0x17 from one host is configuration. Bursty 0x17 to many SPNs from one host within minutes is the attack.

## What 4769 does not tell you

The record does not include the encrypted ticket itself. The cracking happens on whatever the attacker exfiltrated, not on the wire from the DC. You cannot, from 4769 alone, distinguish "ticket was issued and never used" from "ticket was cracked, credentials reused". For the second half of the chain you need the resulting [4624](/en/blog/understanding-event-id-4624) on the target service (LogonType 3, AuthenticationPackage Kerberos), and ideally [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) showing what ran after the credential was reused. Treat 4769 as the canary, not the alarm.

## Where 4769 fits in a timeline

Classic post-exploitation kerberoasting chain:

1. [4624](/en/blog/understanding-event-id-4624) on a workstation. Initial access via phished user credentials.
2. **4769** ×N from that workstation to one DC, all `etype=0x17`, all targeting user-SPN service accounts within 5 minutes. Kerberoasting.
3. *(Offline, invisible)*. Attacker cracks the weakest service account's hash in Hashcat.
4. [4768](/en/blog/event-id-4768-kerberos-tgt). TGT request as the compromised service account, from a different host.
5. 4624 LogonType 3 on a high-value server, AuthenticationPackage Kerberos.
6. [7045](/en/blog/service-creation-event-id-7045). Service installed for persistence under the compromised account.

The 4769 burst in step 2 is your earliest, cheapest detection point. Hours or days before the attacker comes back as the service account.

## Further reading

- [Microsoft documentation for 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)
