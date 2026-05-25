---
title: "Event ID 4672 spiegato: rilevare i logon privilegiati in Windows"
description: "Il 4672 segnala ogni logon che riceve privilegi sensibili come SeDebugPrivilege o SeTcbPrivilege: è il marcatore «logon admin-equivalent»."
date: "2026-05-24"
---

L'Event ID **4672** — «Special privileges assigned to new logon» — si attiva sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che a una sessione di logon viene concesso uno di un insieme fisso di privilegi Windows sensibili. In pratica significa: ogni logon admin-equivalent riuscito produce un 4672, immediatamente dopo il corrispondente [4624](/it/blog/understanding-event-id-4624). Sulla maggior parte delle workstation il 4672 è raro; sui domain controller e sui jumpbox di amministrazione è costante. Quell'asimmetria è ciò che lo rende utile.

Se filtri i record Security per un solo campo, «dammi tutti i 4672 dell'ultima settimana» è la query «mostrami ogni sessione privilegiata nell'estate» più economica che puoi eseguire.

## Dove si attiva

Sempre sull'host dove il logon è effettivamente avvenuto — come per il [4624](/it/blog/understanding-event-id-4624). Un logon di rete verso `SERVER01` produce il 4624 e (se privilegiato) il 4672 su `SERVER01`, non sulla workstation originante. Per rilevare qualcosa dal 4672 su larga scala serve la collection di Security come minimo da server e DC; dalle workstation di amministrazione e dai jumphost se ti puoi permettere il volume.

## Cosa contiene il record

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

I campi:

- **`SubjectLogonId`** — lo stesso `LogonId` che appare sul [4624](/it/blog/understanding-event-id-4624) corrispondente. Questo è il tuo pivot: ogni 4672 lega esattamente un 4624 (e ogni record successivo in quella sessione) al set di privilegi che quel logon ha ottenuto.
- **`PrivilegeList`** — il vero bag dei privilegi. Windows logga qui solo un insieme fisso di privilegi «sensibili» (definito nell'audit policy); un logon può detenere più privilegi di quanti ne mostri il record. Quelli omessi — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, ecc. — non sono security-relevant e vengono tagliati di proposito.
- **`Subject*`** — a chi appartiene il logon. Quasi sempre identici agli stessi campi del 4624 corrispondente.

Non c'è `IpAddress`, non c'è `LogonType`, non c'è `WorkstationName` nel 4672 stesso. Per ottenerli devi joinare al 4624 via `SubjectLogonId`.

## I privilegi e cosa significano

| Privilegio | Display name | Perché conta |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Leggere/scrivere la memoria di qualsiasi processo — incluso `lsass.exe`. Mimikatz ne ha bisogno. |
| `SeTcbPrivilege` | Act as part of the operating system | Di fatto `LocalSystem`. Dovrebbe apparire solo per LocalSystem stesso. |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | Il privilegio usato dalle famiglie di exploit `SeImpersonatePrivilege` (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Tooling di token impersonation. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | Bypassa le ACL per leggere/scrivere file arbitrari — inclusi gli hive di registry. `reg save HKLM\SAM` funziona con questi. |
| `SeTakeOwnershipPrivilege` | Take ownership of files | Override delle ACL sui file. |
| `SeLoadDriverPrivilege` | Load and unload device drivers | Richiesto per attacchi BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Manage auditing and security log | Leggere/cancellare il Security event log. Richiesto per scatenare il [1102](/it/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkit, tampering EFI. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Comune sulla maggior parte dei logon; non è un segnale di triage. |

Alcuni di questi te li aspetti su ogni logon admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Altri dovrebbero essere più rari (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Il segnale è nel privilegio *inatteso* che compare sull'account *sbagliato*.

## I pattern di triage

### 1. Baseline di chi ottiene 4672

In un'estate sana, i produttori di 4672 sono un set *piccolo e conosciuto*:

- `LocalSystem` (S-1-5-18) — ogni host, sempre, all'avvio dei servizi.
- `NetworkService` (S-1-5-20) — comune su server che eseguono servizi impersonation-capable.
- Una manciata di amministratori, identificati per SID più che per nome.

Chiunque altro generi un 4672 è: un nuovo admin di cui non sapevi, un evento di privilege escalation, o un account mal configurato.

La query di baseline più economica: `SubjectUserSid` distinti dai 4672 negli ultimi 30 giorni, ordinati per frequenza. Qualsiasi cosa fuori dai top N produttori merita un'occhiata.

### 2. SeImpersonatePrivilege su un account non privilegiato

Se un 4672 mostra `SeImpersonatePrivilege` su un account che non è admin e non è un SID `*Service`, è quasi certamente una escalation di famiglia «Potato» (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). Questi exploit danno a un caller `IIS_IUSRS` o con token di servizio il `SYSTEM`. Il 4672 si attiva *mentre il privilegio viene acquisito* — prima di qualsiasi processo visibile spawnato con il nuovo privilegio.

### 3. SeDebugPrivilege senza gruppo admin

`SeDebugPrivilege` viene concesso agli admin locali per policy. Vederlo su un account non admin è un segno che la policy è stata modificata — di solito da un attaccante per abilitare l'accesso a LSASS — o che un attaccante si è iniettato in un processo admin.

### 4. Logon privilegiato fuori dall'orario di lavoro

Un 4672 per un account admin reale alle 03:00 di domenica è il più economico alert «attività admin fuori orario» esistente. Combina col `LogonType` e `IpAddress` del 4624 corrispondente per il contesto.

### 5. Drift di service account

Un service account che storicamente attivava solo `SeImpersonatePrivilege` e `SeAssignPrimaryTokenPrivilege` e improvvisamente produce 4672 con `SeBackupPrivilege` e `SeDebugPrivilege` significa che qualcuno ne ha cambiato le membership di gruppo. Abbina con 4732/4728 per trovare il cambio di membership.

## Esempio di regola Sigma — SeDebugPrivilege su non-admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Tara `filter_known_admins` per ambiente; alcuni negozi usano una lista di SID più che un pattern di nome.

## Esempio KQL — escalation famiglia Potato

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Esempio Splunk — baseline dei logon admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Eseguila settimanalmente; le anomalie appaiono come nuovi account nei top 50.

## Mappatura ATT&CK

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**: SeImpersonatePrivilege su account non privilegiati.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: SeDebugPrivilege è la precondizione.
- **T1068 — Exploitation for Privilege Escalation**: qualsiasi acquisizione inattesa di privilegi.
- **T1078 — Valid Accounts**: 4672 per account admin legittimi da sorgenti inusuali.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: SeSecurityPrivilege è richiesto per chiamare `ClearEventLog`; un 4672 con questo privilegio immediatamente prima del [1102](/it/blog/event-id-1102-cleared-log) è la pista di briciole.

## Falsi positivi che sembrano esattamente attacchi

- **Software di backup** (Veeam, Commvault) attiva di routine 4672 con `SeBackupPrivilege` + `SeRestorePrivilege` da service account. Baseline per SID di service account.
- **Agenti di monitoring** (SCOM, collector WMI custom) che leggono dati security-relevant scatenano ampi 4672. Tagga l'host dell'agente.
- **Alcuni runner di logon script** sotto contesti privilegiati producono catene di 4672 al logon time.
- **Host Hyper-V / VMM / container** generano traffico 4672 denso da `LocalSystem` e managed service account.

Il segnale è nel produttore *nuovo*, non in quello *ricorrente*. Un produttore di 4672 che si attiva quotidianamente da un anno è configurazione; uno che è appena comparso questa settimana è il lead.

## Cosa il 4672 non ti dice

- **Nessuna informazione di processo**: vedi la concessione del privilegio, non cosa ha fatto il processo privilegiato. Per seguirlo in avanti, pivota `SubjectLogonId` ai record [4688](/it/blog/event-id-4688-process-creation) / [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) nella stessa sessione.
- **Nessun IP sorgente** direttamente: devi joinare al [4624](/it/blog/understanding-event-id-4624) via `SubjectLogonId` per ottenerlo.
- **Non ogni azione privilegiata**: viene registrata solo la *concessione al logon*. Usi successivi (es. `RtlAdjustPrivilege` che toggla `SeDebugPrivilege` on/off) producono record 4673/4674, non un altro 4672.
- **Saltato se l'audit Special Logon è off**: la subcategory di audit è *Audit Special Logon*, che deve essere abilitata per gli eventi success. È on di default nei Windows moderni ma vale la pena verificarlo.

## Dove il 4672 si colloca in una timeline

La catena da manuale escalation-e-cleanup:

1. [**4624**](/it/blog/understanding-event-id-4624) — LogonType 3 da un IP controllato dall'attaccante, utente low-priv.
2. *(silente)* — escalation basata su `SeImpersonatePrivilege` (PrintSpoofer o simili).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` concessi a una nuova sessione di logon che gira come `LocalSystem`. **Escalation visibile qui.**
4. [**4688**](/it/blog/event-id-4688-process-creation) — `cmd.exe` o `powershell.exe` in esecuzione come SYSTEM tramite il token impersonato.
5. [**4104**](/it/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` o `comsvcs.dll MiniDump` contro LSASS — è SeDebugPrivilege a farlo funzionare.
6. [**1102**](/it/blog/event-id-1102-cleared-log) — Security log cancellato. SeSecurityPrivilege dal passo 3 lo ha abilitato.
7. **4672** — seconda sessione privilegiata come domain admin estratto dalla memoria di LSASS.

I 4672 nei passi 3 e 7 sono i punti di detection più economici della catena. Senza di loro stai ricostruendo l'impersonation solo da eventi di processo — più lento e più facile da perdere.
