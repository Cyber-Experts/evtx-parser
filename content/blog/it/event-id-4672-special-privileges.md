---
title: "Event ID 4672 spiegato: rilevare logon privilegiati in Windows"
description: "4672 scatta quando a un logon vengono concessi privilegi sensibili come SeDebugPrivilege o SeTcbPrivilege. Leggilo come il segnale 'questo logon è admin-equivalent' e il resto della policy di audit va al suo posto."
date: "2026-05-24"
---

L'Event ID **4672**, „Privilegi speciali assegnati al nuovo logon", scatta sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che a una sessione di logon viene concesso uno di un insieme fisso di privilegi sensibili di Windows. In pratica, ogni logon riuscito equivalente ad amministratore produce un 4672, scritto subito dopo il corrispondente [4624](/it/blog/understanding-event-id-4624). Sulla maggior parte delle workstation 4672 è raro. Su domain controller e jumpbox admin è costante. Quell'asimmetria è ciò che lo rende utile.

Se questa settimana filtri Security per un campo solo, esegui „tutti i 4672 degli ultimi sette giorni". È la query „mostrami ogni sessione privilegiata nel parco" più economica che tu possa scrivere.

## Dove scatta

Sull'host dove il logon è effettivamente avvenuto, come [4624](/it/blog/understanding-event-id-4624). Un logon di rete a `SERVER01` produce il 4624 e il 4672 su `SERVER01`, non sulla workstation originante. Per rilevare qualcosa da 4672 su scala ti serve come minimo la raccolta di Security da server e DC. Workstation admin e jumphost se puoi permetterti il volume.

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

- `SubjectLogonId`. La stessa `LogonId` del [4624](/it/blog/understanding-event-id-4624) corrispondente. Questo è il tuo pivot. Ogni 4672 lega esattamente un 4624 (e ogni record successivo in quella sessione) all'insieme di privilegi che il logon ha ottenuto.
- `PrivilegeList`. La borsa di privilegi reale. Windows logga solo i privilegi „sensibili" definiti nella policy di audit. Un logon può detenere più privilegi di quanto il record mostri. Quelli omessi (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, ecc.) non sono rilevanti per la sicurezza e vengono potati da questo record di proposito.
- `Subject*`. A chi appartiene il logon. Quasi sempre identico al 4624 corrispondente.

Non c'è `IpAddress`, non c'è `LogonType`, non c'è `WorkstationName` sul 4672 stesso. Per averli, fai join al 4624 tramite `SubjectLogonId`. Gli analisti che cercano di allertare solo su 4672 spesso si perdono questo e finiscono con record che non possono arricchire.

## I privilegi e cosa significano

| Privilegio | Nome visualizzato | Perché conta |
|---|---|---|
| `SeDebugPrivilege` | Eseguire il debug dei programmi | Leggere/scrivere la memoria di qualsiasi processo, incluso `lsass.exe`. Mimikatz ne ha bisogno. |
| `SeTcbPrivilege` | Agire come parte dell'OS | Effettivamente `LocalSystem`. Dovrebbe apparire solo per LocalSystem. |
| `SeImpersonatePrivilege` | Impersonare un client dopo auth | Il privilegio usato dalla famiglia Potato (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). |
| `SeAssignPrimaryTokenPrivilege` | Sostituire un token di processo | Tooling di impersonificazione di token. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | Bypassare le ACL per leggere/scrivere file arbitrari inclusi hive di registro. `reg save HKLM\SAM` funziona con questi. |
| `SeTakeOwnershipPrivilege` | Assumere la proprietà | Sovrascrivere le ACL dei file. |
| `SeLoadDriverPrivilege` | Caricare driver | Necessario per BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Gestire il log di audit | Leggere o svuotare Security. Necessario per far scattare [1102](/it/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modificare il firmware | Bootkit, manomissione EFI. |
| `SeChangeNotifyPrivilege` | Bypassare il traverse check | Comune sulla maggior parte dei logon. Non un segnale di triage. |

Alcuni te li aspetti su ogni logon admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Altri dovrebbero essere più rari (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Il segnale è il privilegio *inatteso* sull'account *sbagliato*.

## I pattern

### Baseline di chi ottiene 4672

In un parco sano, i produttori di 4672 sono un insieme piccolo e noto:

- `LocalSystem` (S-1-5-18). Ogni host, tutto il tempo, all'avvio dei servizi.
- `NetworkService` (S-1-5-20). Comune su server che eseguono servizi capaci di impersonificazione.
- Una manciata di amministratori, identificati per SID anziché per nome.

Chiunque altro è un nuovo admin di cui non sapevi, un evento di escalation di privilegi o un account mal configurato.

La query di baseline più economica: `SubjectUserSid` distinti da 4672 negli ultimi 30 giorni, ordinati per frequenza. Qualsiasi cosa fuori dal top N merita un'occhiata.

### SeImpersonatePrivilege su un account non privilegiato

Se un 4672 mostra `SeImpersonatePrivilege` su un account che non è admin e non è un SID `*Service`, è quasi certamente un'escalation Potato. Questi exploit danno a un chiamante con `IIS_IUSRS` o token di servizio `SYSTEM`. Il 4672 scatta *all'acquisizione del privilegio*. È prima di qualsiasi processo visibile generato col nuovo privilegio.

### SeDebugPrivilege senza gruppo admin

`SeDebugPrivilege` è concesso agli admin locali per policy. Su un account non admin, o la policy è stata modificata (di solito da un attaccante per abilitare l'accesso a LSASS) o un attaccante si è iniettato in un processo admin.

### Logon privilegiato fuori orario lavorativo

Un 4672 per un account admin reale alle 03:00 di una domenica è l'allerta after-hours più economica che esista. Combina col `LogonType` e `IpAddress` del 4624 corrispondente per il contesto.

### Drift del service account

Un account di servizio che storicamente scatta solo `SeImpersonatePrivilege` e `SeAssignPrimaryTokenPrivilege` che improvvisamente produce 4672 con `SeBackupPrivilege` e `SeDebugPrivilege` significa che qualcuno ha cambiato le sue appartenenze a gruppi. Abbina con 4732 o 4728 per trovare il cambio di membership.

## Sigma: SeDebugPrivilege su un non-admin

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
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Sintonizza `filter_known_admins` per ambiente. Alcuni shop usano una lista di SID invece di un pattern di nomi.

## KQL: escalation famiglia Potato

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

## Splunk: baseline dei logon admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Eseguilo settimanalmente. Le anomalie emergono come nuovi account nel top 50.

## Mapping ATT&CK

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege su account non privilegiati.
- T1003.001 LSASS Memory. SeDebugPrivilege è la precondizione.
- T1068 Exploitation for Privilege Escalation. Ogni guadagno inatteso di privilegio.
- T1078 Valid Accounts. 4672 per account admin legittimi da sorgenti inusuali.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege è richiesto per chiamare `ClearEventLog`. Un 4672 che porta questo privilegio subito prima di [1102](/it/blog/event-id-1102-cleared-log) è la scia di briciole.

## Falsi positivi che sembrano attacchi

- I software di backup (Veeam, Commvault) scattano abitualmente 4672 con `SeBackupPrivilege` + `SeRestorePrivilege` da account di servizio. Baseline per SID di service account.
- Agenti di monitoring (SCOM, collettori WMI custom) innescano 4672 ampiamente. Tagga l'host dell'agente.
- Alcuni runner di script di logon sotto contesti privilegiati producono catene di 4672 al momento del logon.
- Hyper-V, VMM, host di container generano 4672 densi da `LocalSystem` e managed service account.

Il segnale è il produttore *nuovo*, non quello *ricorrente*. Un produttore di 4672 che ha scattato quotidianamente nell'ultimo anno è configurazione. Uno appena apparso questa settimana è la pista.

## Cosa 4672 non ti dice

- Nessuna informazione di processo. Vedi la concessione del privilegio, non cosa ha fatto il processo privilegiato. Per seguirlo in avanti, pivota `SubjectLogonId` ai record [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) nella stessa sessione.
- Nessun IP sorgente direttamente. Fai join a [4624](/it/blog/understanding-event-id-4624) tramite `SubjectLogonId`.
- Non ogni azione privilegiata. Solo la *concessione al logon* è registrata. Usi successivi (per esempio `RtlAdjustPrivilege` che accende e spegne `SeDebugPrivilege`) producono record 4673/4674, non un altro 4672.
- Perso se l'auditing Special Logon è spento. La sub-policy di audit è *Audit Special Logon*. Attiva per default in Windows moderno, ma vale la pena verificarla.

## Dove si inserisce 4672 in una timeline

La catena classica di escalation-e-pulizia:

1. [4624](/it/blog/understanding-event-id-4624). LogonType 3 da un IP controllato dall'attaccante, utente a basso privilegio.
2. *(silenzioso)*. Escalation basata su SeImpersonatePrivilege (PrintSpoofer o simili).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege concessi a una nuova sessione di logon che gira come LocalSystem. Escalation visibile qui.
4. [4688](/it/blog/event-id-4688-process-creation). `cmd.exe` o `powershell.exe` come SYSTEM tramite il token impersonato.
5. [4104](/it/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` o `comsvcs.dll MiniDump` contro LSASS. SeDebugPrivilege è ciò che lo rende possibile.
6. [1102](/it/blog/event-id-1102-cleared-log). Log Security svuotato. SeSecurityPrivilege del passo 3 l'ha abilitato.
7. **4672**. Seconda sessione privilegiata come domain admin estratta dalla memoria di LSASS.

I 4672 nei passi 3 e 7 sono i punti di detection più economici. Senza di essi stai ricostruendo l'impersonificazione da soli eventi di processo. Più lento, più facile da perdere.

## Per approfondire

- [Documentazione Microsoft per 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
