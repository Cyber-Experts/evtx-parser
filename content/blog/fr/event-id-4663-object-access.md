---
title: "Event ID 4663 expliqué : audit d'accès aux fichiers et au registre avec SACL"
description: "4663 est l'enregistrement d'audit d'objet par accès. Configurez des SACL sur les bons fichiers et clés et vous obtenez un journal au byte près de qui a touché à quoi. Utile pour le rançongiciel, l'exfil et le vol de credential store."
date: "2026-05-24"
---

L'Event ID **4663**, « Une tentative d'accès à un objet a eu lieu », se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un fichier audité, une clé de registre ou un objet noyau est touché d'une manière qui correspond à sa System Access Control List. Contrairement à la plupart des enregistrements Security, 4663 ne produit rien par défaut. Vous devez d'abord *configurer* la SACL sur l'objet. C'est pour cela que la plupart des environnements ne l'ont pas. C'est aussi pour cela que ceux qui l'ont disposent d'un avantage de détection presque injuste sur un petit ensemble de techniques.

Si vous instrumentez 4663 sur exactement cinq choses et ignorez le reste, vous attraperez le staging de credential dump, les balayages de rançongiciel et le vol DPAPI moins cher que n'importe quel EDR ne peut le faire.

## Où il se déclenche

Sur l'hôte qui possède l'objet. Les SACL sur fichiers se déclenchent sur le serveur de fichiers. Les SACL de registre local se déclenchent sur le poste. Les SACL d'objets AD se déclenchent sur le DC. Il n'y a pas d'enregistrement central. Pour avoir une visibilité à l'échelle du parc sur un partage sensible, il vous faut transférer Security depuis le serveur de fichiers qui l'héberge. Cela piège les gens en permanence.

## Les champs de l'enregistrement

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

Ceux qui comptent :

- `ObjectType`. `File`, `Key` (registre), `Process`, `Token`, `Directory`, `Section`. Toute classe d'objet qui supporte les SACL.
- `ObjectName`. Chemin complet. Pour les fichiers, un chemin Windows. Pour les clés de registre, le chemin complet sous `\REGISTRY\MACHINE\...` (et non le `HKLM\...` que vous taperiez dans regedit).
- `AccessList`. Ce qui a été tenté, sous forme de tokens de droit d'accès décodés. Les courants :
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Bitmask brut de `STANDARD_RIGHTS_*` et de droits spécifiques à l'objet réellement demandés.
- `ProcessName` et `ProcessId`. Le processus qui a ouvert le handle. Pivotez vers [4688](/fr/blog/event-id-4688-process-creation) ou [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) pour le contexte complet du processus.
- `SubjectLogonId`. Pivotez vers [4624](/fr/blog/understanding-event-id-4624) pour la session originelle, l'IP source en cas de logon réseau, et l'utilisateur.

## Activer 4663, c'est trois étapes et les gens en sautent une

1. **Stratégie d'audit**. Activez les sous-stratégies *Object Access* pour File System et/ou Registry, success et/ou failure. Stratégie de groupe ou `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL sur l'objet**. Propriétés, onglet Sécurité, Avancé, onglet Audit dans l'interface graphique. Ou `Set-Acl`, `icacls /audit`. Vous spécifiez quel principal, quels droits et s'il faut auditer success, failure ou les deux.
3. **Pour le registre**, même flux via les Permissions de la clé dans regedit, Avancé, Audit.

Sans (1) les enregistrements ne s'écrivent jamais. Sans (2) Windows n'a aucune idée que vous vouliez auditer quoi que ce soit. Sans (3) vous n'auditez que les fichiers. Les gens sautent le plus souvent (2) parce que l'étape (1) semble devoir suffire. Elle ne suffit pas.

Les SACL qui gagnent leur place sur tout serveur :

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Auditez `Everyone : ReadData : Success`. Tout ce qui lit ces fichiers autre que `LocalSystem` est du credential dumping.
- Fichiers `*.dmp` dans `C:\Windows\Temp` et `%TEMP%`. Auditez `Everyone : WriteData : Success`. Un processus qui écrit un `.dmp` ici, c'est soit Windows après un crash, soit un opérateur Mimikatz.
- `C:\ProgramData\Microsoft\Crypto\RSA` et `C:\Users\*\AppData\Roaming\Microsoft\Protect`. Répertoires de master-keys DPAPI. Auditez `ReadData : Success`. Tout ce qui les lit hors de la session propre de l'utilisateur vole des secrets.
- `HKLM\SECURITY` et `HKLM\SAM`. Équivalents registre. Même audit.
- Partages de fichiers sensibles : finance, juridique, paie. Auditez `WriteData + DELETE : Success` pour attraper les balayages de rançongiciel et les suppressions en masse.

## Les motifs que vous attraperez vraiment

### Lecture du hive SAM ou SYSTEM

Tout 4663 avec `ObjectName` finissant par `\config\SAM`, `\config\SECURITY` ou `\config\SYSTEM`, où `ProcessName` n'est pas `services.exe`, `lsass.exe` ou `wininit.exe`, et `SubjectUserSid` n'est pas `S-1-5-18`. C'est `reg save HKLM\SAM`, `esentutl /y` contre une shadow copy, ou tout outil de credential dumping avec accès au hive niveau fichier. Recoupez avec le [registre](https://www.registryparser.com) pour tout fichier de hive de sauvegarde laissé derrière.

### Minidump LSASS écrit

Un 4663 `WriteData` pour un fichier `.dmp` dans `C:\Windows\Temp\`, `C:\ProgramData\` ou `%TEMP%`, avec `ProcessName` de `rundll32.exe`, `procdump*.exe` ou tout ce qui appelle `comsvcs.dll`. Le cas d'école est `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Recoupez avec [4688](/fr/blog/event-id-4688-process-creation) pour la `CommandLine`. Le 4663 attrape ça même quand l'EDR dormait.

### Balayage de chiffrement par rançongiciel

Beaucoup de 4663 avec `AccessMask` incluant `WriteData + DELETE` contre des fichiers d'un partage sensible en quelques secondes, tous depuis le même `SubjectLogonId` et `ProcessName`. Un vrai processus de sauvegarde touche des fichiers selon un motif mesuré et étranglé. Le rançongiciel balaye un arbre de répertoires aussi vite que le disque le permet. La forme le trahit.

### Vol de master-key DPAPI

4663 `ReadData` sur des fichiers sous `\AppData\Roaming\Microsoft\Protect\<sid>\` par tout processus autre que la session propre de l'utilisateur. Le signe imparable est que `SubjectUserSid` soit un SID *différent* de celui encodé dans le chemin.

### Lecture de fichier de mots de passe Group Policy Preferences

4663 `ReadData` sur des fichiers correspondant à `\SYSVOL\<domain>\Policies\*\Groups.xml`, ou `Services.xml`, `Drives.xml`, `ScheduledTasks.xml`. C'est `Get-GPPPassword`. La technique est ancienne. Les fichiers SYSVOL existent souvent encore sur des domaines legacy, et vous seriez surpris de voir combien de fois quelqu'un attrape la clé AES obfusquée sur MSDN et repart avec un identifiant de domaine.

## Sigma : lecture du hive SAM

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

## KQL : balayage de chiffrement par rançongiciel

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

100 fichiers distincts écrits ou supprimés par minute sous une seule session de logon, c'est un balayage. Point.

## Splunk : accès aux master-keys DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapping ATT&CK

- T1003.002 OS Credential Dumping: Security Account Manager. Lectures de hive SAM.
- T1003.004 LSA Secrets. Lectures de hive SECURITY.
- T1003.001 LSASS Memory. Écritures `.dmp` (combinées au contexte de processus).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Accès à `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. Lectures de SYSVOL `Groups.xml`.
- T1486 Data Encrypted for Impact. Motifs de masse `WriteData + DELETE`.
- T1565.001 Stored Data Manipulation. Écritures arbitraires sur des partages de données monitorés.

## Le piège du volume de SACL

Mettre `Everyone : Tous accès : Success+Failure` sur un répertoire chargé produit des centaines de milliers de 4663 par minute et enterre la collecte. Les SACL sont des instruments de précision. Auditez :

- Seulement les types d'accès qui vous intéressent. ReadData pour les credential stores. WriteData + DELETE pour les partages de données. Rarement les deux à la fois.
- Seulement success. Les failures sont plus rares et rarement intéressants dans ce corpus.
- Des fichiers spécifiques, pas des lecteurs entiers. Le fichier SAM, pas tout `C:\Windows\System32\config\`. Le partage RH, pas tout `D:\`.
- Des principals spécifiques quand vous le pouvez. Pour les objets de classe SAM, `Everyone` convient parce que l'accès légitime se fait par `LocalSystem` de toute façon. Pour les données partagées, auditez seulement les principals qui touchent vraiment les données.

Une SACL bien réglée sur cinq objets à haute valeur produit 50 à 200 enregistrements par jour par hôte. Tout à fait gérable.

## Faux positifs qui ressemblent identiquement à des attaques

- Les sauvegardes Volume Shadow Copy génèrent un trafic 4663 dense pendant une fenêtre de sauvegarde. Étiquetez le `ProcessName` de l'orchestrateur de sauvegarde.
- Les scans antivirus on-access ouvrent chaque fichier dans un répertoire cible. Les comptes de service du produit AV vont dominer toute règle 4663 naïve. Whitelistez par SID.
- Les services d'indexation (Windows Search) frappent les métadonnées via `ReadAttributes`. Habituellement filtrable par `AccessList`.
- Les restaurations en staging de sauvegarde ressemblent à des écritures de rançongiciel (beaucoup de fichiers, un processus, dans un répertoire). Le processus vous dit la différence.
- Le scanning en temps réel de Defender lit tout. Si vous auditez trop largement, il domine le bruit.

## Ce que 4663 ne vous dit pas

- Le contenu de l'accès. Vous voyez qu'un fichier a été lu ou écrit, pas quoi a été lu ou écrit. Pour ça, EDR ou FIM.
- Pourquoi l'accès a eu lieu. Pour corréler à l'intention utilisateur, associez à [4688](/fr/blog/event-id-4688-process-creation) ou à [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) pour le contexte complet du processus appelant.
- Les handles fermés. 4663 se déclenche à l'*ouverture* du handle. Les événements de fermeture sont 4658, rarement utiles pour la détection d'attaques.
- Les chemins réseau de façon transparente. L'accès SMB à un partage déclenche 4663 sur le *serveur*. Le client ne voit rien. Vous avez besoin de la collecte côté serveur.
- L'accès échoué par défaut. Beaucoup de boutiques n'auditent que Success. Configurez Failure seulement si vous vous souciez vraiment des tentatives déjouées.

## Où 4663 s'insère dans une timeline

Chaîne classique de credential dump LSASS :

1. [4624](/fr/blog/understanding-event-id-4624). Logon admin, LogonType 3 ou 10.
2. [4672](/fr/blog/event-id-4672-special-privileges). SeDebugPrivilege accordé avec la session.
3. [4688](/fr/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` vers `C:\Windows\Temp\lsass.dmp` par `rundll32.exe`. De l'or forensique. Preuve d'exfiltration en staging.
5. [4688](/fr/blog/event-id-4688-process-creation). Déplacement ou archive de fichier (opérateur extrayant le dump).
6. [1102](/fr/blog/event-id-1102-cleared-log). Journal Security effacé. Certains opérateurs le font. Beaucoup oublient.

L'étape 4 est le signal le moins cher et le plus spécifique de la chaîne. Elle identifie directement l'artefact de vol d'identifiants par son nom, sur disque, avec le processus appelant attaché. Les lectures de hive SAM, l'accès aux master-keys DPAPI et les lectures de Groups.xml dans SYSVOL fonctionnent de la même manière.

## Pour aller plus loin

- [Documentation Microsoft pour 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps : SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
