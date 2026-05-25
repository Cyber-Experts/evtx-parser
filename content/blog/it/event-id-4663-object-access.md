---
title: "Event ID 4663 spiegato: auditing degli accessi a file e registry con le SACL"
description: "Il 4663 è l'audit per-accesso sugli oggetti. Le giuste SACL danno un log di chi tocca cosa — utile per ransomware, exfil e furto di credential store."
date: "2026-05-24"
---

L'Event ID **4663** — «An attempt was made to access an object» — si attiva sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un file, una chiave di registry o un oggetto kernel auditato viene acceduto in un modo che corrisponde alla sua System Access Control List (SACL). A differenza della maggior parte dei record Security, il 4663 non produce nulla da solo — devi *configurare* la SACL sull'oggetto che ti interessa prima che esistano record 4663. Questo lo rende a costo zero di default e devastantemente efficace una volta tarato.

Se devi auditare una sola cosa col 4663, audita l'accesso ai credential store e agli share di dati ad alto valore. Il rapporto segnale-rumore è tra i migliori dell'intero catalogo di audit.

## Dove si attiva

Sempre sull'host proprietario dell'oggetto — il file server per una SACL su file, la workstation per una SACL locale di registry, il DC per una SACL su un oggetto AD. Non c'è un record centrale; se vuoi visibilità a livello di estate su uno share sensibile, devi forwardare il `Security` dal file server che lo ospita.

## Cosa contiene il record

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

I campi:

- **`ObjectType`** — `File`, `Key` (registry), `Process`, `Token`, `Directory`, `Section`, o qualsiasi classe di oggetto che supporti SACL.
- **`ObjectName`** — il path completo. Per i file è un path Windows; per le chiavi di registry, il path completo sotto `\REGISTRY\MACHINE\…` (nota: non la notazione `HKLM\…` che digiteresti in regedit).
- **`AccessList`** — cosa è stato tentato, come lista di nomi di access-right decodificati (uno per token `%%NNNN`). I valori decodificati comuni:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — la bitmask grezza di `STANDARD_RIGHTS_*` e di diritti object-specific effettivamente richiesti.
- **`ProcessName`** + **`ProcessId`** — il processo che ha aperto l'handle. Il pivot verso [4688](/it/blog/event-id-4688-process-creation) / [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) per il contesto di processo completo.
- **`SubjectLogonId`** — pivot al [4624](/it/blog/understanding-event-id-4624) per la sessione originante, l'IP sorgente se logon di rete, e l'utente.

## Configurare il 4663 — la parte che richiede lavoro vero

Ci sono tre layer di configurazione; se ne manca uno, niente record.

1. **Audit policy**: abilita *Object Access → Audit File System* e/o *Audit Registry* per success e/o failure. Tramite Group Policy o `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL sull'oggetto**: click destro → Properties → Security → Advanced → tab Auditing (GUI Windows), o tramite `Set-Acl` / `icacls /audit`. Specifichi *quale principal* (spesso `Everyone` o `Authenticated Users`), *quali diritti* e *se auditare success, failure o entrambi*.
3. **Per il registry**: stesso flusso, accessibile via `regedit` → chiave → Permissions → Advanced → Auditing.

Senza (1) i record non vengono mai scritti. Senza (2) Windows non ha idea che tu volessi auditare qualcosa. Senza (3) stai auditando solo i file.

Le SACL da impostare su ogni server:

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — credential store locali. Audit `Everyone : ReadData : Success`. Qualsiasi cosa legga questi diversa da `LocalSystem` è un tentativo di credential dumping.
- **`%TEMP%\lsass.dmp`** e qualsiasi `*.dmp` in `C:\Windows\Temp` — minidump di processo. Audit `Everyone : WriteData : Success`. Un processo che scrive un `.dmp` qui è o un crash dump (Windows) o un operatore Mimikatz (tutti gli altri).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** e **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — directory delle DPAPI master-key. Audit `ReadData : Success`. Chiunque legga questi dall'esterno della propria sessione utente sta rubando segreti protetti.
- **`HKLM\SECURITY`** e **`HKLM\SAM`** — equivalenti di registry. Audit `ReadData : Success`.
- **Share di file sensibili** — finance, legal, payroll. Audit `WriteData + DELETE : Success` per intercettare gli sweep di cifratura ransomware e le cancellazioni di massa.

## I pattern di triage

### 1. Lettura degli hive SAM / SYSTEM

Qualsiasi 4663 con `ObjectName` che termina in `\config\SAM`, `\config\SECURITY` o `\config\SYSTEM`, dove `ProcessName` non è `services.exe` / `lsass.exe` / `wininit.exe` e `SubjectUserSid` non è `S-1-5-18`. Questo è `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy`, o qualsiasi tool di credential dumping con accesso a livello file all'hive.

### 2. File di dump LSASS scritto

Un 4663 `WriteData` per un file `.dmp` in `C:\Windows\Temp\`, `C:\ProgramData\` o `%TEMP%`, con `ProcessName` di `rundll32.exe`, `procdump*.exe`, caller correlati a `comsvcs.dll`, o un binario rinominato. Questo è il pattern del minidump di LSASS. Cross-reference con [4688](/it/blog/event-id-4688-process-creation) per la `CommandLine` — `comsvcs.dll MiniDump` è l'encoding più comune.

### 3. Sweep di cifratura ransomware

Molti 4663 con `AccessMask` che include `WriteData + DELETE` contro file in uno share sensibile in pochi secondi, tutti dallo stesso `SubjectLogonId` e `ProcessName`. Un processo di backup reale tocca i file in un pattern misurabile e throttlato; il ransomware percorre un albero di directory alla velocità che il disco consente.

### 4. Furto di DPAPI master-key

4663 `ReadData` su file sotto `\AppData\Roaming\Microsoft\Protect\<sid>\` da qualsiasi processo diverso dalla sessione dell'utente stesso. Il pattern classico è `SubjectUserSid` che è un SID *diverso* da quello nel path.

### 5. Lettura del file password delle Group Policy preference

4663 `ReadData` su file che matchano `\SYSVOL\<domain>\Policies\*\Groups.xml` (o `Services.xml`, `Drives.xml`). Questo è l'attacco `Get-GPPPassword` — vecchio, ma i file SYSVOL spesso esistono ancora nei domini legacy.

## Esempio di regola Sigma — lettura dell'hive SAM

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## Esempio KQL — sweep di cifratura ransomware

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

100 file distinti scritti-o-cancellati al minuto sotto una sola sessione di logon è uno sweep, senza eccezioni.

## Esempio Splunk — accesso a DPAPI master-key

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mappatura ATT&CK

- **T1003.002 — OS Credential Dumping: Security Account Manager**: letture dell'hive SAM.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: letture dell'hive SECURITY.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: scritture di `.dmp` (combinate con il contesto di processo).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**: accesso a `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**: letture di SYSVOL `Groups.xml`.
- **T1486 — Data Encrypted for Impact**: pattern di WriteData + DELETE bulk (ransomware).
- **T1565.001 — Stored Data Manipulation**: scritture arbitrarie su share di dati monitorati.

## Gestione del volume — la trappola delle SACL

Impostare ingenuamente `Everyone : All access : Success+Failure` su una directory occupata produrrà centinaia di migliaia di record 4663 al minuto e seppellirà la tua collection. Le SACL sono strumenti di precisione. Audita:

- **Solo i tipi di accesso che ti interessano** (`ReadData` per i credential store; `WriteData + DELETE` per gli share di dati; raramente entrambi).
- **Solo success** — i failure sono più rari e raramente interessanti.
- **File specifici**, non interi drive. Il file SAM, non tutto `C:\Windows\System32\config\`. Lo share HR, non tutto `D:\`.
- **Principal specifici** quando puoi — per oggetti SAM-class `Everyone` va bene perché l'accesso legittimo è comunque tramite `LocalSystem`; per dati condivisi, audita solo i principal che toccano davvero i dati.

Una SACL ben tarata su cinque oggetti ad alto valore produce 50-200 record al giorno per host — totalmente gestibile.

## Falsi positivi che sembrano esattamente attacchi

- **Volume Shadow Copy** (VSS) durante una finestra di backup genera traffico 4663 denso. Tagga il `ProcessName` dell'orchestratore di backup.
- **Le scansioni on-access degli antivirus** aprono ogni file in una directory target; i service account del prodotto AV domineranno qualsiasi regola 4663 ingenua. Whitelist per SID.
- **Servizi di indexing** (Windows Search, stile Spotlight) toccano i metadati via `ReadAttributes` — di solito filtrabili da `AccessList`.
- **Restore staged da backup** sembrano scritture ransomware (molti file, un processo, in una directory) ma il processo è il tuo backup agent.
- **Lo scan real-time di Defender** legge tutto; se audi troppo ampiamente, è la fonte di rumore dominante.

## Cosa il 4663 non ti dice

- **Contenuto dell'accesso**: vedi che un file è stato letto/scritto, non *cosa* è stato letto/scritto. Per questo serve un prodotto EDR o FIM (File Integrity Monitoring).
- **Perché l'accesso è avvenuto**: solo l'esito della syscall. Per correlare all'intento utente, abbina a [4688](/it/blog/event-id-4688-process-creation) / [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) per il contesto completo del processo chiamante.
- **Handle chiusi**: il 4663 si attiva sull'*apertura* dell'handle. Gli eventi di chiusura sono 4658, raramente utili per la detection.
- **Path di rete in modo trasparente**: l'accesso SMB a uno share attiva il 4663 sul *server*; il client non vede nulla. Serve collection lato server.
- **Accesso fallito per default**: molti negozi auditano solo `Success`; configura `Failure` solo se ti interessano genuinamente i tentativi di accesso sventati.

## Dove il 4663 si colloca in una timeline

Catena classica di dump credenziali LSASS:

1. [**4624**](/it/blog/understanding-event-id-4624) — logon admin (LogonType 3 o 10).
2. [**4672**](/it/blog/event-id-4672-special-privileges) — SeDebugPrivilege concesso alla sessione.
3. [**4688**](/it/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` su `C:\Windows\Temp\lsass.dmp` da `rundll32.exe`. **Oro forense — prova dello staging per l'exfil.**
5. [**4688**](/it/blog/event-id-4688-process-creation) — file move / archiviazione (l'operatore che estrae il dump).
6. [**1102**](/it/blog/event-id-1102-cleared-log) — Security log cancellato (alcuni operatori lo fanno; molti se lo dimenticano).

Il 4663 al passo 4 è il segnale più economico e specifico della catena — identifica direttamente l'artefatto di furto credenziali per nome, su disco, con il processo chiamante allegato. Letture dell'hive SAM, accesso a DPAPI master-key e letture di SYSVOL Groups.xml funzionano allo stesso modo.
