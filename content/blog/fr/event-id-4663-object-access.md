---
title: "Event ID 4663 expliqué : audit d'accès aux fichiers et au registre via SACL"
description: "4663 est l'enregistrement d'audit objet par accès. Configurez les SACL sur les bons fichiers et clés pour un log de qui a touché quoi."
date: "2026-05-24"
---

L'Event ID **4663** — « Une tentative d'accès à un objet a été faite » — se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un fichier, une clé de registre ou un objet noyau audité est accédé d'une manière qui correspond à sa System Access Control List (SACL). Contrairement à la plupart des enregistrements Security, 4663 ne produit rien par défaut — vous devez *configurer* la SACL sur l'objet qui vous intéresse avant qu'aucun 4663 n'existe. C'est ce qui le rend peu coûteux par défaut et redoutablement efficace une fois ajusté.

Si vous n'auditez qu'une seule chose avec 4663, auditez l'accès aux credential stores et aux partages de données à forte valeur. Le ratio signal/bruit est parmi les meilleurs de tout le catalogue d'audit.

## Où il se déclenche

Toujours sur l'hôte qui possède l'objet — le serveur de fichiers pour une SACL fichier, le poste pour une SACL registre locale, le DC pour une SACL d'objet AD. Il n'y a pas d'enregistrement central ; pour une visibilité d'entreprise sur un partage sensible, vous devez transférer `Security` depuis le serveur de fichiers qui l'héberge.

## Ce que contient l'enregistrement

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

Les champs :

- **`ObjectType`** — `File`, `Key` (registre), `Process`, `Token`, `Directory`, `Section` ou toute classe d'objet qui supporte les SACL.
- **`ObjectName`** — le chemin complet. Pour les fichiers c'est un chemin Windows ; pour les clés de registre, le chemin complet sous `\REGISTRY\MACHINE\…` (note : pas la notation `HKLM\…` que vous taperiez dans regedit).
- **`AccessList`** — ce qui a été tenté, sous forme d'une liste de noms de droits décodés (un par token `%%NNNN`). Les valeurs décodées courantes :
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — le bitmask brut des `STANDARD_RIGHTS_*` et des droits spécifiques à l'objet réellement demandés.
- **`ProcessName`** + **`ProcessId`** — le processus qui a ouvert le handle. Le pivot vers [4688](/fr/blog/event-id-4688-process-creation) / [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) pour le contexte complet du processus.
- **`SubjectLogonId`** — pivot vers [4624](/fr/blog/understanding-event-id-4624) pour la session d'origine, l'IP source si connexion réseau, et l'utilisateur.

## Configurer 4663 — la partie qui demande du travail

Il y a trois couches de configuration ; en manquer une signifie aucun enregistrement.

1. **Politique d'audit** : activer *Object Access → Audit File System* et/ou *Audit Registry* pour les succès et/ou échecs. Via Group Policy ou `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL sur l'objet** : clic droit → Propriétés → Sécurité → Avancé → onglet Audit (GUI Windows), ou via `Set-Acl` / `icacls /audit`. Vous spécifiez *quel principal* (souvent `Everyone` ou `Authenticated Users`), *quels droits*, et *si auditer succès, échec ou les deux*.
3. **Pour le registre** : même flux, via `regedit` → clé → Autorisations → Avancé → Audit.

Sans (1), les enregistrements ne s'écrivent jamais. Sans (2), Windows ne sait pas que vous vouliez auditer quoi que ce soit. Sans (3), vous n'auditez que les fichiers.

Les SACL à poser sur chaque serveur :

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — credential stores locaux. Auditer `Everyone : ReadData : Success`. Tout ce qui les lit autre que `LocalSystem` est une tentative de credential dumping.
- **`%TEMP%\lsass.dmp`** et tout `*.dmp` dans `C:\Windows\Temp` — minidumps de processus. Auditer `Everyone : WriteData : Success`. Un processus qui écrit un `.dmp` ici est soit un crash dump (Windows), soit un opérateur Mimikatz (tout le monde).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** et **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — répertoires de clés maîtresses DPAPI. Auditer `ReadData : Success`. Quiconque lit ces fichiers depuis l'extérieur de la session propre de l'utilisateur vole des secrets protégés.
- **`HKLM\SECURITY`** et **`HKLM\SAM`** — équivalents registre. Auditer `ReadData : Success`.
- **Partages fichiers sensibles** — finance, juridique, paie. Auditer `WriteData + DELETE : Success` pour attraper les vagues de chiffrement ransomware et les suppressions en masse.

## Les patterns de triage

### 1. Lecture des hives SAM / SYSTEM

Tout 4663 avec `ObjectName` finissant par `\config\SAM`, `\config\SECURITY` ou `\config\SYSTEM`, où `ProcessName` n'est pas `services.exe` / `lsass.exe` / `wininit.exe` et `SubjectUserSid` n'est pas `S-1-5-18`. C'est `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy` ou tout outil de credential dumping ayant un accès fichier aux hives.

### 2. Fichier dump LSASS écrit

Un 4663 `WriteData` pour un fichier `.dmp` dans `C:\Windows\Temp\`, `C:\ProgramData\` ou `%TEMP%`, avec `ProcessName` de `rundll32.exe`, `procdump*.exe`, des appelants liés à `comsvcs.dll` ou un binaire renommé. C'est le pattern minidump LSASS. À croiser avec [4688](/fr/blog/event-id-4688-process-creation) pour la `CommandLine` — `comsvcs.dll MiniDump` est l'encodage le plus fréquent.

### 3. Vague de chiffrement ransomware

Beaucoup de 4663 avec `AccessMask` incluant `WriteData + DELETE` contre des fichiers d'un partage sensible en quelques secondes, tous depuis le même `SubjectLogonId` et `ProcessName`. Un vrai processus de backup touche les fichiers selon un motif mesurable et limité ; un ransomware parcourt l'arborescence aussi vite que le disque le permet.

### 4. Vol de clé maîtresse DPAPI

4663 `ReadData` sur des fichiers sous `\AppData\Roaming\Microsoft\Protect\<sid>\` par un processus autre que la session propre de l'utilisateur. Le pattern classique est `SubjectUserSid` *différent* du SID dans le chemin.

### 5. Lecture de fichier mot de passe Group Policy preference

4663 `ReadData` sur des fichiers correspondant à `\SYSVOL\<domain>\Policies\*\Groups.xml` (ou `Services.xml`, `Drives.xml`). C'est l'attaque `Get-GPPPassword` — ancienne, mais les fichiers SYSVOL existent souvent encore sur d'anciens domaines.

## Exemple de règle Sigma — lecture du hive SAM

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

## Exemple KQL — vague de chiffrement ransomware

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

100 fichiers distincts écrits ou supprimés par minute sous une session de logon est une vague, point final.

## Exemple Splunk — accès à clé maîtresse DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Cartographie ATT&CK

- **T1003.002 — OS Credential Dumping: Security Account Manager** : lectures du hive SAM.
- **T1003.004 — OS Credential Dumping: LSA Secrets** : lectures du hive SECURITY.
- **T1003.001 — OS Credential Dumping: LSASS Memory** : écritures `.dmp` (combinées au contexte de processus).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager** : accès à `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences** : lectures SYSVOL `Groups.xml`.
- **T1486 — Data Encrypted for Impact** : motifs WriteData + DELETE en masse (ransomware).
- **T1565.001 — Stored Data Manipulation** : écritures de fichiers arbitraires sur des partages de données surveillés.

## Gestion du volume — le piège des SACL

Régler naïvement `Everyone : All access : Success+Failure` sur un répertoire occupé va produire des centaines de milliers de 4663 par minute et noyer votre collecte. Les SACL sont des instruments de précision. Auditer :

- **Seulement les types d'accès qui vous intéressent** (`ReadData` pour credential stores ; `WriteData + DELETE` pour partages de données ; rarement les deux).
- **Seulement les succès** — les échecs sont plus rares et rarement intéressants.
- **Des fichiers spécifiques**, pas des disques entiers. Le fichier SAM, pas tout `C:\Windows\System32\config\`. Le partage RH, pas tout `D:\`.
- **Des principals spécifiques** quand vous le pouvez — pour les objets de classe SAM, `Everyone` est correct parce que l'accès légitime se fait par `LocalSystem` de toute façon ; pour les données partagées, n'auditez que les principals qui touchent réellement les données.

Une SACL bien ajustée sur cinq objets à haute valeur produit 50 à 200 enregistrements par jour par hôte — entièrement tractable.

## Faux positifs qui ressemblent exactement à des attaques

- **Backups Volume Shadow Copy** (VSS) génèrent un trafic 4663 dense pendant une fenêtre de backup. Taguez le `ProcessName` de l'orchestrateur de backup.
- **Scans on-access antivirus** ouvrent chaque fichier d'un répertoire ; les comptes de service AV vont dominer toute règle 4663 naïve. Whitelistez par SID.
- **Services d'indexation** (Windows Search, équivalent Spotlight) touchent les métadonnées via `ReadAttributes` — généralement filtrables par `AccessList`.
- **Restaurations depuis backup** ressemblent à des écritures ransomware (beaucoup de fichiers, un processus, dans un répertoire) mais le processus est votre agent de backup.
- **Scan temps réel Defender** lit tout ; si vous auditez trop large, c'est la source dominante de bruit.

## Ce que 4663 ne dit pas

- **Le contenu de l'accès** : vous voyez qu'un fichier a été lu/écrit, pas ce qui a été lu/écrit. Pour ça, il faut un EDR ou un produit FIM (File Integrity Monitoring).
- **Pourquoi l'accès a eu lieu** : seulement le résultat de l'appel système. Pour corréler à l'intention utilisateur, combinez avec [4688](/fr/blog/event-id-4688-process-creation) / [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) pour le contexte complet du processus appelant.
- **Handles fermés** : 4663 se déclenche à l'*ouverture* du handle. Les événements de fermeture sont 4658, rarement utiles pour la détection d'attaque.
- **Chemins réseau de manière transparente** : un accès SMB à un partage déclenche 4663 sur le *serveur* ; le client ne voit rien. Il faut une collecte côté serveur.
- **Accès en échec par défaut** : beaucoup de structures n'auditent que `Success` ; configurez `Failure` uniquement si vous vous souciez vraiment des tentatives d'accès contrecarrées.

## Où 4663 s'inscrit dans une timeline

Chaîne classique de dump de credentials LSASS :

1. [**4624**](/fr/blog/understanding-event-id-4624) — connexion admin (LogonType 3 ou 10).
2. [**4672**](/fr/blog/event-id-4672-special-privileges) — SeDebugPrivilege accordé à la session.
3. [**4688**](/fr/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` sur `C:\Windows\Temp\lsass.dmp` par `rundll32.exe`. **Or forensique — preuve de staging d'exfiltration.**
5. [**4688**](/fr/blog/event-id-4688-process-creation) — déplacement / archivage du fichier (l'opérateur extrait le dump).
6. [**1102**](/fr/blog/event-id-1102-cleared-log) — log Security effacé (certains opérateurs font cela ; beaucoup oublient).

Le 4663 à l'étape 4 est le signal le moins cher et le plus spécifique de la chaîne — il identifie directement l'artefact de vol de credentials par son nom, sur disque, avec le processus appelant attaché. Les lectures de hive SAM, l'accès aux clés maîtresses DPAPI et les lectures SYSVOL Groups.xml fonctionnent de la même façon.
