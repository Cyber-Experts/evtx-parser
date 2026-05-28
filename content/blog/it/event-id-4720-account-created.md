---
title: "Event ID 4720 spiegato: rilevare la creazione di account malevoli in AD"
description: "4720 scatta ogni volta che viene creato un account utente, locale o di dominio. Leggilo con 4722, 4724 e 4732 e catturi gli account di persistenza e movimento laterale in pochi minuti."
date: "2026-05-24"
---

L'Event ID **4720**, „Un account utente è stato creato", atterra sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un nuovo utente viene provisionato. Su un domain controller scatta per ogni nuovo utente AD. Su una workstation o server membro scatta per ogni nuovo account locale. In uno shop maturo, il traffico 4720 è schiacciantemente guidato dall'HR e prevedibile. Quella prevedibilità è ciò che lo rende utile. Un attaccante che crea un account backdoor spicca proprio perché il traffico legittimo è così regolare.

Questo è uno dei record di rilevamento di persistenza più economici che la piattaforma produca. Ho chiuso casi solo con questo.

## Dove scatta

- Account di dominio: 4720 atterra sul DC che ha gestito la creazione. Raccogli da tutti i DC.
- Account locali: 4720 atterra sull'host dove l'account è stato creato. Catturarlo dalle workstation membro richiede WEF o raccolta per-host. Molti shop saltano il forwarding di Security dalle workstation e perdono completamente questo segnale.

Se l'attaccante crea un account *locale* su un server già compromesso (spesso come credenziale di backup), il 4720 sarà solo su quel server. La copertura conta più delle regole.

## Cosa c'è nel record

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

I campi che guidano le indagini:

- `TargetUserName`. Il nuovo account. Il nome letterale è il primo segnale di triage: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, look-alike di account legittimi (`administrator`, `administr0r`) e stringhe casuali brevi meritano tutti uno sguardo più attento.
- `SubjectUserName` e `SubjectLogonId`. Chi l'ha creato. Pivota al [4624](/it/blog/understanding-event-id-4624) che ha creato quella sessione. Un 4720 da `LocalSystem` su una workstation fuori orario non è un vero workflow di provisioning.
- `UserAccountControl`. L'insieme *iniziale* di flag UAC. `0x10` (nell'esempio) è `NORMAL_ACCOUNT`. I flag pericolosi appaiono nei record 4738 successivi.
- `PrimaryGroupId`. 513 (Domain Users) è normale. 512 (Domain Admins) su un account nuovo è urlato e non dovrebbe mai accadere in un vero workflow di provisioning.
- `SidHistory`. Non vuoto su un account appena creato è o uno strumento di migrazione o, nel contesto sbagliato, un artefatto di autenticazione forgiato.

## 4720 non viene mai da solo

La creazione di account non è quasi mai un singolo evento. La sequenza minima:

| Evento | Significato | Perché ti interessa |
|---|---|---|
| **4720** | Account utente creato | Il titolo. |
| **4722** | Account utente abilitato | L'account è impostato per consentire il logon. Se manca 4722, l'account esiste ma non può ancora fare logon. |
| **4724** | Reset password (guidato da admin) | Qualcuno, possibilmente non il creatore, ha impostato o resettato la password. |
| **4738** | Account utente modificato | Flag UAC, scadenza, gruppo, modifiche di attributi. |
| **4732** | Membro aggiunto a un gruppo locale abilitato per la sicurezza | Se il gruppo locale è `Administrators`, questa è la concessione di privilegio. |
| **4728** | Membro aggiunto a un gruppo globale abilitato per la sicurezza | Se il gruppo globale è `Domain Admins` o `Enterprise Admins`, escalation. |
| **4756** | Membro aggiunto a un gruppo universale abilitato per la sicurezza | `Schema Admins`, `Enterprise Admins`, delegazioni custom. |

Un account backdoor raramente viene creato e lasciato a privilegio di default. La catena completa (4720, 4722, 4724, 4738, 4732/4728) si completa in pochi secondi ed è il vero evento di persistenza.

## Pattern di triage

1. **Nuovo account in gruppo admin entro pochi minuti**. 4720 seguito da 4732 o 4728 a un gruppo privilegiato entro un'ora, dove l'aggiunta al gruppo privilegiato non era preceduta da un ticket. Abbina `TargetSid` dal 4720 con `MemberSid` su 4732/4728.
2. **Creazione fuori orario**. 4720 fuori orario lavorativo da un `SubjectUserName` che non è un service account che esegue provisioning automatizzato.
3. **Nome look-alike**. `Levenshtein(TargetUserName, real_admin_name) <= 2` contro la tabella utenti esistente. `administrato`, `administr0r`, `helpd3sk`. Tutti reali.
4. **Creato da un account recentemente compromesso**. 4720 dove `SubjectLogonId` traccia indietro a un 4624 da un IP inusuale, o un 4624 LogonType 3 da una workstation che il soggetto non usa normalmente.
5. **Creato da LocalSystem su una workstation**. 4720 con `SubjectUserSid = S-1-5-18` su qualcosa diverso da un domain controller o server di provisioning noto. Quasi sempre malevolo.
6. **PrimaryGroupId == 512**. Non accade mai nel provisioning normale. Alert duro.

## Sigma

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

Una variante ad alta confidenza combina 4720 con un 4732 o 4728 in un gruppo privilegiato entro 1 ora, scopato per `TargetSid`.

## KQL: 4720 più concessione di privilegio

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Splunk

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## Mapping ATT&CK

- T1136.001 Create Account: Local Account. Account locali di workstation e server.
- T1136.002 Create Account: Domain Account. Creazioni registrate al DC.
- T1136.003 Create Account: Cloud Account. *Non* scatta 4720. Le creazioni cloud vivono nei log di audit di Entra ID / unified audit log.
- T1098 Account Manipulation. Quando 4720 è seguito da escalation di gruppo o modifiche di attributi.

## Falsi positivi che sembrano attacchi

- Gli strumenti di migrazione di massa (ADMT, Quest Migration Manager) creano account a velocità con `SidHistory` impostato. La forma è identica a un attaccante veloce. Baseline le finestre di migrazione note.
- Le pipeline di joiner nei workflow di provisioning guidati da HR scattano 4720 a orari prevedibili. Allertare su ogni 4720 fuori orario ti seppellirà sotto i run HR che sforano oltre mezzanotte.
- Gli strumenti di gestione stile SCCM, Intune e Jamf creano account locali per il provisioning OS. `SubjectUserSid` è `S-1-5-18` sugli host di build noti. Tagga quelli.
- Gli installer di servizi per alcuni prodotti legacy creano un service account locale al primo avvio. Baseline l'installer.

Le detection solide di 4720 combinano sempre la creazione con un segnale successivo (aggiunta a gruppo, cambio password verso un pattern debole noto, login immediato da un host inusuale). La sola creazione è troppo rumorosa.

## Cosa 4720 non ti dice

Il record non include la password del nuovo account (Windows non la logga mai, da nessuna parte). Non include neanche il SID del dominio target esplicitamente. Leggi il dominio da `TargetDomainName` o lo derivi dalla porzione di dominio di `TargetSid`.

Le creazioni di account locali sulle workstation membro sono invisibili al DC. Se non stai raccogliendo Security dalle workstation (la maggior parte degli shop non lo fa), perdi ogni account backdoor locale. Sysmon e un EDR reale colmano parte del divario (pattern di creazione file e modifica registro quando il SAM locale viene toccato), ma il forwarding di 4720 è il controllo più economico. Lo snapshot dell'hive del [registro](https://www.registryparser.com) è la conferma quando il log forwarding era spento.

## Dove si inserisce 4720 in una timeline

La catena di persistenza da manuale:

1. [4624](/it/blog/understanding-event-id-4624). Logon iniziale di dominio da un utente phishato.
2. Raffica di [4769](/it/blog/event-id-4769-kerberoasting). Kerberoasting contro service account di dominio.
3. 4624 come un service account compromesso su un server membro.
4. [4688](/it/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (o `New-ADUser` via PowerShell).
5. **4720**. Account creato sul DC.
6. 4724. Password impostata.
7. 4722. Account abilitato.
8. 4728. Aggiunto a Domain Admins.
9. [7045](/it/blog/service-creation-event-id-7045). Servizio installato su un server, in esecuzione sotto il nuovo account.

Strumenta solo 4720 e cogli la persistenza al passo 5, prima che i passi da 6 a 9 facciano alcun danno. È quello il valore.

## Per approfondire

- [Documentazione Microsoft per 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
