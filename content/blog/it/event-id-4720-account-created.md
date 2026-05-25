---
title: "Event ID 4720 spiegato: rilevare la creazione di account rogue in AD"
description: "Il 4720 si attiva ogni volta che viene creato un account utente — localmente o in AD. Leggilo insieme a 4722/4724/4732 e individui account di persistenza e movimento laterale in pochi minuti."
date: "2026-05-24"
---

L'Event ID **4720** — «A user account was created» — viene scritto sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un nuovo account utente viene provisioned. Su un domain controller si attiva per ogni nuovo utente AD; su una workstation o member server si attiva per ogni nuovo account locale. In un negozio maturo il traffico 4720 è prevalentemente HR-driven e prevedibile. Quella prevedibilità è ciò che lo rende utile: un attaccante che crea un account backdoor spicca proprio perché il traffico legittimo è così regolare.

Questo è uno dei record di detection di persistenza più economici che la piattaforma produce.

## Dove si attiva

- **Account di dominio**: il 4720 atterra sul DC che ha gestito la create. Raccogli su tutti i DC.
- **Account locali**: il 4720 atterra sull'host dove l'account è stato creato. Intercettarlo dalle workstation member richiede WEF o collection per-host — molti negozi saltano il forwarding di Security delle workstation e perdono completamente questo segnale.

Se l'attaccante crea un account *locale* su un server già compromesso (spesso come credenziale di backup), il 4720 sarà solo su quel server. La copertura conta.

## Cosa contiene il record

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

- **`TargetUserName`** — il nuovo account. Il nome letterale è il primo segnale di triage: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, lookalike di account legittimi (`administrator`, `administr0r`) e stringhe corte random meritano tutti uno sguardo più attento.
- **`SubjectUserName` / `SubjectLogonId`** — *chi* l'ha creato. Pivota al [4624](/it/blog/understanding-event-id-4624) che ha creato quella sessione. Un 4720 da `LocalSystem` su una workstation fuori orario non è un workflow di provisioning reale.
- **`UserAccountControl`** — il set *iniziale* di flag UAC. `0x10` (l'esempio) è `NORMAL_ACCOUNT`; i flag pericolosi appaiono in record 4738 (account changed) successivi. La bitmap UAC completa è in MS-SAMR.
- **`PrimaryGroupId`** — 513 (Domain Users) è normale; 512 (Domain Admins) su un nuovo account è un'anomalia da urlo che non dovrebbe mai succedere in un workflow di provisioning reale.
- **`SidHistory`** — un `SidHistory` non vuoto su un account *appena creato* è un segno forte di un tool di migrazione — o, nel contesto sbagliato, di un artefatto di autenticazione forgiato.

## I record di cui il 4720 non è solo

La creazione di account è quasi mai un singolo evento. La sequenza minima:

| Evento | Significato | Perché ti interessa |
|---|---|---|
| **4720** | Account utente creato | L'headline. |
| **4722** | Account utente abilitato | L'account è impostato per consentire il logon. Se manca il 4722, l'account esiste ma non può ancora loggarsi. |
| **4724** | Password reset (admin-driven) | Qualcuno — possibilmente non il creatore — ha impostato o resettato la password. |
| **4738** | Account utente cambiato | Cambi di flag UAC, scadenza, gruppo, attributi. |
| **4732** | Membro aggiunto a un gruppo locale security-enabled | Se il gruppo locale è `Administrators`, questa è la concessione di privilegio. |
| **4728** | Membro aggiunto a un gruppo globale security-enabled | Se il gruppo globale è `Domain Admins` o `Enterprise Admins`, escalation. |
| **4756** | Membro aggiunto a un gruppo universale security-enabled | `Schema Admins`, `Enterprise Admins`, delegations custom. |

Un account backdoor è raramente creato e lasciato al privilegio di default. La catena completa — `4720 → 4722 → 4724 → 4738 (flag UAC) → 4732/4728 (group add)` — si completa in secondi ed è l'evento di persistenza vero.

## Pattern di triage

1. **Nuovo account → gruppo admin in pochi minuti**: 4720 seguito da 4732/4728 verso un gruppo privilegiato entro un'ora, dove l'aggiunta al gruppo privilegiato *non* è stata preceduta da un ticket nel sistema di change-management. Abbina il `TargetSid` dal 4720 con `MemberSid` su 4732/4728.
2. **Creazione fuori orario**: 4720 fuori dall'orario di lavoro da uno `SubjectUserName` che non è un service account che fa provisioning automatizzato.
3. **Nome lookalike**: `Levenshtein(TargetUserName, nome_admin_reale) <= 2` contro la tabella utenti esistente. `administrato`, `administr0r`, `helpd3sk` — tutti casi reali.
4. **Creato da un account recentemente compromesso**: 4720 dove `SubjectLogonId` riconduce a un 4624 da un IP inusuale, o un 4624 LogonType 3 da una workstation che il subject non usa normalmente.
5. **Creato da `LocalSystem` su una workstation**: 4720 con `SubjectUserSid = S-1-5-18` su qualsiasi cosa diversa da un domain controller o un server di provisioning noto. Quasi sempre malizioso.
6. **`PrimaryGroupId == 512`**: non succede mai nel provisioning normale. Alert hard.

## Esempio di regola Sigma

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

Una variante ad alta confidenza: combina il 4720 con un 4732/4728 verso un gruppo privilegiato entro 1 ora, scoped per `TargetSid`.

## Esempio KQL — 4720 + concessione di privilegio

KQL (Sentinel) — il pivot «nuovo account → gruppo admin»:

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

## Esempio Splunk

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

## Mappatura ATT&CK

- **T1136.001 — Create Account: Local Account** per account locali workstation/server.
- **T1136.002 — Create Account: Domain Account** per le creazioni registrate sul DC.
- **T1136.003 — Create Account: Cloud Account** — *non* attiva il 4720 (le create di account cloud sono nei log di Azure AD audit / unified audit log, non in Windows Security).
- **T1098 — Account Manipulation** quando il 4720 è seguito da escalation di gruppo o cambi di attributi.

## Falsi positivi che sembrano esattamente attacchi

- **Tool di migrazione bulk** (ADMT, Quest Migration Manager) creano account a velocità con `SidHistory` impostato. La forma del traffico è identica a un attaccante veloce; fai baseline delle finestre di migrazione note.
- **Pipeline di joiner** nei workflow di provisioning HR-driven attivano il 4720 a orari prevedibili. Se lanci alert su ogni 4720 fuori orario ti seppellirai sotto le run del sistema HR che sforano la mezzanotte.
- **Tool di management stile SCCM / Intune / Jamf** creano account locali per il provisioning del SO. Il `SubjectUserSid` sarà `S-1-5-18` (LocalSystem) su host di build noti; tagga quegli host.
- **Installer di servizio** per alcuni prodotti legacy creano un service account locale al primo run. Fai baseline dell'installer.

Le detection 4720 solide combinano sempre la create con un segnale di follow-up (aggiunta a gruppo, cambio password verso un pattern debole noto, login immediato da un host inusuale). La create standalone è troppo rumorosa.

## Cosa il 4720 non ti dice

Il record non include la *password* del nuovo account (Windows non la logga mai, da nessuna parte). Non include nemmeno esplicitamente il SID del *dominio target*; il dominio lo leggi da `TargetDomainName` o lo derivi dalla porzione di dominio del `TargetSid`.

Le create di account locali sulle workstation member sono invisibili al DC. Se non collezioni Security dalle workstation (la maggior parte dei negozi non lo fa), perderai ogni account backdoor locale. Sysmon e un EDR vero coprono parte del gap (pattern di file create / cambi di registry quando il SAM locale viene toccato), ma il forwarding del 4720 è la via più economica.

## Dove il 4720 si colloca in una timeline

La catena da manuale di persistenza:

1. [**4624**](/it/blog/understanding-event-id-4624) — logon di dominio iniziale di un utente phishato.
2. [**4769**](/it/blog/event-id-4769-kerberoasting) burst — kerberoasting contro service account di dominio.
3. **4624** come service account compromesso su un member server.
4. [**4688**](/it/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain` (o lo stesso via PowerShell `New-ADUser`).
5. **4720** — account creato sul DC.
6. **4724** — password impostata.
7. **4722** — account abilitato.
8. **4728** — aggiunto a Domain Admins.
9. [**7045**](/it/blog/service-creation-event-id-7045) — servizio installato su un server, in esecuzione sotto il nuovo account.

Se strumenti solo il 4720, becchi la persistenza al passo 5 — prima che i passi 6-9 facciano qualsiasi danno. Quello è il valore.
