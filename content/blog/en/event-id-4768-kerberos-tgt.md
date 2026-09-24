---
title: "Event ID 4768: Kerberos TGT requests and AS-REP roasting"
description: "Event ID 4768: A Kerberos authentication ticket (TGT) was requested. How result codes and the pre-auth flag reveal AS-REP roasting, password spraying and delegation abuse."
date: "2026-05-24"
---

Event ID **4768**, "A Kerberos authentication ticket (TGT) was requested", fires on a Domain Controller every time anyone asks for a Ticket Granting Ticket. Every domain logon starts with one of these. Pair it with [4769](/en/blog/event-id-4769-kerberoasting) (service ticket) and you see the entire Kerberos lifecycle of every account in the forest.

On a DC, 4768 is the highest-volume record in the [Security channel](/en/blog/what-is-an-evtx-file) after 4624. Most of it is noise. The high-signal slices live in two specific fields, and one of them is the AS-REP roasting fingerprint.

## Where it fires

Like [4769](/en/blog/event-id-4769-kerberoasting), 4768 lands on the issuing **Domain Controller** only. The client does not see it. The target service does not see it. To detect anything from 4768, you need Security collection from every DC. KAPE-style for one-off engagements, WEF for steady state.

## What the record contains

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

The fields that matter:

- `TargetUserName`. The account requesting a TGT. Always a user or computer account. `ServiceName` is always `krbtgt`.
- `Status`. Kerberos result code. `0x0` is success. The failures are what makes 4768 useful: `0x6` unknown user, `0x12` client locked out, `0x17` password expired, `0x18` bad password.
- `TicketEncryptionType`. Same encoding as 4769: `0x12` and `0x11` AES (modern), **`0x17` RC4** (legacy, also the AS-REP roasting fingerprint).
- `PreAuthType`. `2` is the standard encrypted-timestamp pre-auth. `0` means **no pre-auth was used** (the AS-REP roasting prerequisite). `15`, `16`, `17` are PKINIT certificate-based pre-auth values.
- `IpAddress`. Requesting host. Pair with the client-side [4624](/en/blog/understanding-event-id-4624) for full context.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Populated for PKINIT (smart-card or certificate logon). Empty for password-based logons.

## The two attack patterns 4768 reveals

### AS-REP roasting (T1558.004)

The headline use. Some accounts have `DONT_REQUIRE_PREAUTH` set in `userAccountControl` (UAC bit 22 = `0x400000`). For those accounts, the DC responds to a TGT request **without** requiring the encrypted-timestamp pre-auth. The AS-REP it returns contains material that an attacker can crack offline to recover the account's password hash.

The 4768 fingerprint of an AS-REP roast in progress:

- `PreAuthType = 0` (no pre-auth).
- `TicketEncryptionType = 0x17` (RC4, what the cracking tool needs).
- `Status = 0x0` (the DC happily issued the AS-REP).
- Often clusters. An attacker batches dozens of accounts to test which have pre-auth disabled.

Real accounts with `DONT_REQUIRE_PREAUTH` exist almost exclusively for legacy compatibility: very old Unix Kerberos clients, some ancient appliances. They are tiny in number and predictable in location. A 4768 with `PreAuthType=0` for an account that has no business using pre-auth-less Kerberos is the signal.

### Password brute force or spray

Failed Kerberos pre-auth produces 4768 with `Status=0x18` ("wrong password"). Unlike [4625](/en/blog/detecting-4625-brute-force) (which captures NTLM failures), 4768 is where Kerberos-based password attacks land. Modern toolkits (Rubeus, kerbrute) speak Kerberos directly because the DC silently fails on NTLM attempts faster than it answers Kerberos ones, and many SOCs only watch 4625.

The 4768 brute-force fingerprint:

- Many `Status=0x18` records for the same `TargetUserName` from the same source IP within a short window. Brute force.
- Many `Status=0x18` records across many `TargetUserName` values from one source IP, each hit once or twice. Password spray.
- A burst of `Status=0x6` ("unknown user") preceding `Status=0x18` from the same source. User enumeration confirmed before the brute starts.

## Status codes that drive triage

| Status | Meaning | Field reading |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Success. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Username does not exist. Bursts = enumeration. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Account locked, disabled, or expired. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Password expired. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Wrong password. Bursts = brute force or spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Returned to the client first on a fresh TGT request. Real success follows. Do not alert on these alone. |
| `0x25` | KRB_AP_ERR_SKEW | Clock skew > 5 min. Often AS-REP roasting attempts from a host with a deliberately wrong clock. |

## Triage workflow: AS-REP roasting

1. Filter 4768 across all DCs for `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Group by `IpAddress`. Single account from a known migration host is configuration. Multiple accounts from one source is the attack.
3. Pivot every `TargetUserName` to its `userAccountControl`. Does `DONT_REQUIRE_PREAUTH` actually need to be set? Almost certainly not.
4. Source IP into [4624](/en/blog/understanding-event-id-4624) on that host to find the credential that authenticated to launch the attack.
5. Rotate every cracked account's password. Remove `DONT_REQUIRE_PREAUTH` from accounts that do not need it.

## Triage workflow: Kerberos brute force

1. Filter 4768 for `Status == 0x18`.
2. Group by `IpAddress` over 15-minute windows. Count distinct `TargetUserName`.
3. More than 5 accounts from one source in 15 minutes is spray. More than 10 failures against one account in the same window is brute force.
4. Cross-check against `Status == 0x6` from the same source. Enumeration before the brute is the textbook ordering.

## Sigma: AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: Kerberos password spray

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK mapping

- T1558.004 AS-REP Roasting. Headline detection on `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force and sub-techniques `.001` Password Guessing and `.003` Password Spraying. `Status=0x18` patterns.
- T1558.001 Golden Ticket. A forged TGT bypasses 4768 entirely. Detection here is by *absence*: a [4769](/en/blog/event-id-4769-kerberoasting) without a preceding 4768 from the same source and window is the suspicion.
- T1187 Forced Authentication. Not directly visible in 4768 but the resulting TGT requests will be.

## False positives that look like attacks

- Old Java or Unix Kerberos stacks in legacy app silos sometimes default to RC4 without pre-auth. They show up as steady, daytime 4768 traffic from a stable host. Baseline.
- PKINIT migration during smart-card rollouts. Legitimate `PreAuthType=15/16/17` flips look anomalous if you have not seen them before. Watch the rollout window.
- Kerberos library bugs. Certain clients re-request TGTs aggressively on time skew, generating noise. Cross-check with `Status=0x25`.
- Domain trust traversal. Cross-forest authentication produces 4768 on each side. The `IpAddress` is a DC of the other forest. Tag it.

## What 4768 does not tell you

The record does not include the actual AS-REP material the attacker captured (which is what they crack offline). You see the request was issued. You do not see what data was returned beyond the metadata. You also do not see the client perspective: what application launched the request, which user context it ran in. For that you need the client-side [4624](/en/blog/understanding-event-id-4624), and [4688](/en/blog/event-id-4688-process-creation) if `kerbrute.exe` or Rubeus ran locally.

Note also that 4768 fires only for the initial TGT request and on renewals. Once a client has a valid TGT cached, it does not talk to the KDC again for TGT until renewal. The service tickets it derives generate [4769](/en/blog/event-id-4769-kerberoasting), not 4768. An attacker who steals a long-lived TGT (golden ticket) can issue arbitrary 4769s without ever producing another 4768.

## Where 4768 fits in a timeline

AS-REP roasting start to finish:

1. [4624](/en/blog/understanding-event-id-4624). Initial low-privilege domain logon (phished credential).
2. *(LDAP, sometimes a 4662 if SACL is set)*. Attacker enumerates `userAccountControl` for accounts with `DONT_REQUIRE_PREAUTH`.
3. **4768** burst. `PreAuthType=0`, `etype=0x17`, `Status=0x0` for each candidate account. The detection point.
4. *(Offline, invisible)*. Attacker cracks the recovered AS-REP material in Hashcat (mode 18200).
5. **4768**. New TGT request as the compromised account, this time normally pre-authed.
6. [4769](/en/blog/event-id-4769-kerberoasting). Service tickets for everything the compromised account can reach.
7. [4624](/en/blog/understanding-event-id-4624) LogonType 3 on the target service.

Step 3 is the canary. Step 5 onward is the actual compromise. The window between them, minutes to days, is the only window where a defender can act before the credential is alive in the wild.

## Further reading

- [Microsoft documentation for 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)
