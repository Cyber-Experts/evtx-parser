---
title: "Event ID 4663 spiegato: audit di accesso a file e registro con SACL"
description: "4663 è il record di audit dell'oggetto per ogni accesso. Configura le SACL sui file e sulle chiavi giuste e ottieni un log byte per byte di chi ha toccato cosa. Utile per ransomware, exfil e furto di credential store."
date: "2026-05-24"
---

L'Event ID **4663**, „È stato tentato un accesso a un oggetto", scatta sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un file, una chiave di registro o un oggetto kernel auditati vengono toccati in un modo che corrisponde alla loro System Access Control List. A differenza della maggior parte dei record Security, 4663 non produce nulla per default. Devi prima *configurare* la SACL sull'oggetto. Per questo la maggior parte degli ambienti non lo ha. Per questo anche quelli che lo hanno hanno un vantaggio di detection quasi sleale su un piccolo insieme di tecniche.

Se strumenti 4663 su esattamente cinque cose e ignori il resto, prenderai lo staging del credential dump, gli sweep di ransomware e il furto DPAPI a un costo inferiore a qualsiasi EDR.

## Dove scatta

Sull'host che possiede l'oggetto. Le SACL su file scattano sul file server. Le SACL del registro locale scattano sulla workstation. Le SACL su oggetti AD scattano sul DC. Non esiste un record centrale. Per avere visibilità su tutto il parco verso uno share sensibile, devi inoltrare Security dal file server che lo ospita. Questo fa inciampare la gente di continuo.

## I campi del record

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

Quelli che contano:

- `ObjectType`. `File`, `Key` (registro), `Process`, `Token`, `Directory`, `Section`. Qualsiasi classe di oggetto che supporta SACL.
- `ObjectName`. Path completo. Per i file, un path Windows. Per le chiavi di registro, il path completo sotto `\REGISTRY\MACHINE\...` (non `HKLM\...` come scriveresti in regedit).
- `AccessList`. Cosa è stato tentato, come token di diritto di accesso decodificati. I comuni:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Bitmask grezza di `STANDARD_RIGHTS_*` e dei diritti specifici dell'oggetto effettivamente richiesti.
- `ProcessName` e `ProcessId`. Il processo che ha aperto l'handle. Pivota a [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) per il contesto completo del processo.
- `SubjectLogonId`. Pivota a [4624](/it/blog/understanding-event-id-4624) per la sessione originante, l'IP sorgente se logon di rete, e l'utente.

## Accendere 4663 sono tre passi e la gente ne salta uno

1. **Audit policy**. Abilita le sub-policy *Object Access* per File System e/o Registry, success e/o failure. Group Policy o `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL sull'oggetto**. Proprietà, scheda Sicurezza, Avanzate, scheda Controllo nella GUI. O `Set-Acl`, `icacls /audit`. Specifichi quale principal, quali diritti e se auditare success, failure o entrambi.
3. **Per il registro**, stesso flusso tramite Autorizzazioni della chiave di regedit, Avanzate, Controllo.

Senza (1) i record non vengono mai scritti. Senza (2) Windows non ha idea che tu volessi auditare niente. Senza (3) stai auditando solo file. La gente più spesso salta (2) perché il passo (1) sembra dover bastare. Non basta.

Le SACL che si guadagnano lo stipendio su ogni server:

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Audita `Everyone : ReadData : Success`. Qualsiasi cosa legga questi diversa da `LocalSystem` è credential dumping.
- File `*.dmp` in `C:\Windows\Temp` e `%TEMP%`. Audita `Everyone : WriteData : Success`. Un processo che scrive un `.dmp` qui è o Windows dopo un crash, o un operatore Mimikatz.
- `C:\ProgramData\Microsoft\Crypto\RSA` e `C:\Users\*\AppData\Roaming\Microsoft\Protect`. Directory di master-key DPAPI. Audita `ReadData : Success`. Qualsiasi cosa li legga al di fuori della sessione dell'utente stesso sta rubando segreti.
- `HKLM\SECURITY` e `HKLM\SAM`. Equivalenti su registro. Stesso audit.
- Share di file sensibili: finanza, legale, payroll. Audita `WriteData + DELETE : Success` per cogliere sweep ransomware e cancellazioni di massa.

## I pattern che davvero coglierai

### Lettura dell'hive SAM o SYSTEM

Ogni 4663 con `ObjectName` che termina in `\config\SAM`, `\config\SECURITY` o `\config\SYSTEM`, dove `ProcessName` non sia `services.exe`, `lsass.exe` o `wininit.exe`, e `SubjectUserSid` non sia `S-1-5-18`. Questo è `reg save HKLM\SAM`, `esentutl /y` contro una shadow copy, o qualsiasi strumento di credential dumping con accesso a hive a livello file. Incrocia col [registro](https://www.registryparser.com) per eventuali file di hive di backup lasciati dietro.

### Minidump di LSASS scritto

Un 4663 `WriteData` per un file `.dmp` in `C:\Windows\Temp\`, `C:\ProgramData\` o `%TEMP%`, con `ProcessName` di `rundll32.exe`, `procdump*.exe` o qualsiasi cosa che chiami `comsvcs.dll`. Il caso da manuale è `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Incrocia con [4688](/it/blog/event-id-4688-process-creation) per la `CommandLine`. Il 4663 lo coglie anche quando l'EDR dormiva.

### Sweep di cifratura ransomware

Molti 4663 con `AccessMask` che include `WriteData + DELETE` contro file in uno share sensibile entro secondi, tutti dallo stesso `SubjectLogonId` e `ProcessName`. Un vero processo di backup tocca file in un pattern misurato e throttled. Il ransomware sweepa un albero di directory veloce quanto il disco permette. La forma lo tradisce.

### Furto di master-key DPAPI

4663 `ReadData` su file sotto `\AppData\Roaming\Microsoft\Protect\<sid>\` da qualsiasi processo diverso dalla sessione propria dell'utente. Il segno inequivocabile è che `SubjectUserSid` sia un SID *diverso* da quello incorporato nel path.

### Lettura del file di password Group Policy Preferences

4663 `ReadData` su file che combaciano con `\SYSVOL\<domain>\Policies\*\Groups.xml`, o `Services.xml`, `Drives.xml`, `ScheduledTasks.xml`. Questo è `Get-GPPPassword`. La tecnica è vecchia. I file SYSVOL spesso esistono ancora su domini legacy, e ti sorprenderesti di quante volte qualcuno prenda la chiave AES offuscata da MSDN e se ne vada con una credenziale di dominio.

## Sigma: lettura hive SAM

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

## KQL: sweep di cifratura ransomware

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

100 file distinti scritti-o-cancellati al minuto sotto una singola sessione di logon è uno sweep. Punto.

## Splunk: accesso master-key DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapping ATT&CK

- T1003.002 OS Credential Dumping: Security Account Manager. Letture di hive SAM.
- T1003.004 LSA Secrets. Letture di hive SECURITY.
- T1003.001 LSASS Memory. Scritture `.dmp` (combinato col contesto di processo).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Accesso a `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. Letture di SYSVOL `Groups.xml`.
- T1486 Data Encrypted for Impact. Pattern di massa `WriteData + DELETE`.
- T1565.001 Stored Data Manipulation. Scritture arbitrarie su share di dati monitorati.

## La trappola del volume delle SACL

Impostare `Everyone : Tutto l'accesso : Success+Failure` su una directory affollata produce centinaia di migliaia di 4663 al minuto e seppellisce la raccolta. Le SACL sono strumenti di precisione. Audita:

- Solo i tipi di accesso che ti interessano. ReadData per i credential store. WriteData + DELETE per gli share di dati. Raramente entrambi insieme.
- Solo success. I failure sono più rari e raramente interessanti in questo corpus.
- File specifici, non interi dischi. Il file SAM, non tutto `C:\Windows\System32\config\`. Lo share HR, non tutto `D:\`.
- Principal specifici quando puoi. Per oggetti di classe SAM, `Everyone` va bene perché l'accesso legittimo è comunque tramite `LocalSystem`. Per dati condivisi, audita solo i principal che davvero toccano i dati.

Una SACL ben sintonizzata su cinque oggetti ad alto valore produce 50-200 record al giorno per host. Del tutto trattabile.

## Falsi positivi che sembrano identici agli attacchi

- I backup Volume Shadow Copy generano traffico 4663 denso durante una finestra di backup. Tagga il `ProcessName` dell'orchestratore di backup.
- Le scansioni antivirus on-access aprono ogni file in una directory target. Gli account di servizio del prodotto AV domineranno qualunque regola 4663 ingenua. Whitelist per SID.
- I servizi di indicizzazione (Windows Search) toccano i metadati tramite `ReadAttributes`. Solitamente filtrabili per `AccessList`.
- I restore in staging di backup sembrano scritture ransomware (molti file, un processo, in una directory). Il processo ti dice la differenza.
- La scansione real-time di Defender legge tutto. Se auditi troppo larghi, domina il rumore.

## Cosa 4663 non ti dice

- Il contenuto dell'accesso. Vedi che un file è stato letto o scritto, non cosa è stato letto o scritto. Per quello, EDR o FIM.
- Perché l'accesso è avvenuto. Per correlare all'intenzione utente, abbina a [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) per il contesto completo del processo chiamante.
- Handle chiusi. 4663 scatta all'*apertura* dell'handle. Gli eventi di chiusura sono 4658, raramente utili per il rilevamento di attacchi.
- Path di rete in modo trasparente. L'accesso SMB a uno share scatta 4663 sul *server*. Il client non vede niente. Hai bisogno della raccolta lato server.
- Accesso fallito per default. Molti shop auditano solo Success. Configura Failure solo se ti interessano davvero i tentativi sventati.

## Dove si inserisce 4663 in una timeline

Catena classica di credential dump LSASS:

1. [4624](/it/blog/understanding-event-id-4624). Logon admin, LogonType 3 o 10.
2. [4672](/it/blog/event-id-4672-special-privileges). SeDebugPrivilege concesso con la sessione.
3. [4688](/it/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` verso `C:\Windows\Temp\lsass.dmp` da `rundll32.exe`. Oro forense. Prova di exfil in staging.
5. [4688](/it/blog/event-id-4688-process-creation). Spostamento file o archiviazione (operatore che estrae il dump).
6. [1102](/it/blog/event-id-1102-cleared-log). Log Security svuotato. Alcuni operatori lo fanno. Molti dimenticano.

Il passo 4 è il segnale più economico e più specifico nella catena. Identifica direttamente l'artefatto di furto di credenziali per nome, su disco, col processo chiamante allegato. Le letture di hive SAM, l'accesso alle master-key DPAPI e le letture di Groups.xml in SYSVOL funzionano allo stesso modo.

## Per approfondire

- [Documentazione Microsoft per 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
