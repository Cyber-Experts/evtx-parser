---
title: "Event ID 4720 expliqué : détecter la création de comptes malveillants dans AD"
description: "4720 se déclenche chaque fois qu'un compte utilisateur est créé, local ou de domaine. Lisez-le avec 4722, 4724 et 4732 et vous attrapez les comptes de persistance et de mouvement latéral en quelques minutes."
date: "2026-05-24"
---

L'Event ID **4720**, « Un compte utilisateur a été créé », atterrit sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un nouvel utilisateur est provisionné. Sur un contrôleur de domaine il se déclenche pour chaque nouvel utilisateur AD. Sur un poste ou un serveur membre il se déclenche pour chaque nouveau compte local. Dans une boutique mûre, le trafic 4720 est massivement piloté par les RH et prévisible. Cette prévisibilité est ce qui le rend utile. Un attaquant qui crée un compte backdoor ressort précisément parce que le trafic légitime est si régulier.

C'est l'un des enregistrements de détection de persistance les moins chers que la plateforme produise. J'ai clos des dossiers rien qu'avec lui.

## Où il se déclenche

- Comptes de domaine : 4720 atterrit sur le DC qui a géré la création. Collectez sur tous les DC.
- Comptes locaux : 4720 atterrit sur l'hôte où le compte a été créé. Pour l'attraper depuis les postes membres il faut du WEF ou une collecte par hôte. Beaucoup de boutiques sautent le transfert Security des postes et perdent entièrement ce signal.

Si l'attaquant crée un compte *local* sur un serveur déjà compromis (souvent comme identifiant de secours), le 4720 ne sera que sur ce serveur. La couverture compte plus que les règles.

## Ce qui est dans l'enregistrement

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

Les champs qui pilotent les enquêtes :

- `TargetUserName`. Le nouveau compte. Le nom littéral est le premier signal de triage : `svc_*`, `backup*`, `admin2`, `test`, `guest2`, sosies de comptes légitimes (`administrator`, `administr0r`) et courtes chaînes aléatoires méritent tous un regard plus attentif.
- `SubjectUserName` et `SubjectLogonId`. Qui l'a créé. Pivotez vers le [4624](/fr/blog/understanding-event-id-4624) qui a créé cette session. Un 4720 depuis `LocalSystem` sur un poste hors heures de bureau n'est pas un vrai workflow de provisionnement.
- `UserAccountControl`. L'ensemble *initial* de flags UAC. `0x10` (dans l'exemple) est `NORMAL_ACCOUNT`. Les flags dangereux apparaissent dans des enregistrements 4738 ultérieurs.
- `PrimaryGroupId`. 513 (Domain Users) est normal. 512 (Domain Admins) sur un nouveau compte hurle et ne devrait jamais arriver dans un vrai workflow de provisionnement.
- `SidHistory`. Non vide sur un compte fraîchement créé est soit un outil de migration, soit, dans le mauvais contexte, un artefact d'authentification forgé.

## 4720 ne vient jamais seul

La création de compte n'est presque jamais un événement unique. La séquence minimale :

| Événement | Sens | Pourquoi ça vous importe |
|---|---|---|
| **4720** | Compte utilisateur créé | Le titre. |
| **4722** | Compte utilisateur activé | Le compte est paramétré pour autoriser le logon. Si 4722 manque, le compte existe mais ne peut pas se connecter encore. |
| **4724** | Réinitialisation de mot de passe (pilotée par admin) | Quelqu'un, possiblement pas le créateur, a posé ou réinitialisé le mot de passe. |
| **4738** | Compte utilisateur modifié | Flags UAC, expiration, groupe, modifications d'attribut. |
| **4732** | Membre ajouté à un groupe local activé sécurité | Si le groupe local est `Administrators`, c'est l'octroi de privilège. |
| **4728** | Membre ajouté à un groupe global activé sécurité | Si le groupe global est `Domain Admins` ou `Enterprise Admins`, escalade. |
| **4756** | Membre ajouté à un groupe universel activé sécurité | `Schema Admins`, `Enterprise Admins`, délégations personnalisées. |

Un compte backdoor est rarement créé et laissé au privilège par défaut. La chaîne complète (4720, 4722, 4724, 4738, 4732/4728) se conclut en quelques secondes et est l'événement de persistance réel.

## Motifs de triage

1. **Nouveau compte dans un groupe admin en quelques minutes**. 4720 suivi de 4732 ou 4728 vers un groupe privilégié dans l'heure, où l'ajout au groupe privilégié n'a pas été précédé d'un ticket. Associez `TargetSid` du 4720 avec `MemberSid` sur 4732/4728.
2. **Création hors heures**. 4720 hors heures de bureau par un `SubjectUserName` qui n'est pas un compte de service exécutant un provisionnement automatisé.
3. **Nom sosie**. `Levenshtein(TargetUserName, real_admin_name) <= 2` contre la table d'utilisateurs existante. `administrato`, `administr0r`, `helpd3sk`. Tous réels.
4. **Créé par un compte récemment compromis**. 4720 où `SubjectLogonId` remonte à un 4624 depuis une IP inhabituelle, ou un 4624 LogonType 3 depuis un poste que le sujet n'utilise normalement pas.
5. **Créé par LocalSystem sur un poste**. 4720 avec `SubjectUserSid = S-1-5-18` sur autre chose qu'un contrôleur de domaine ou un serveur de provisionnement connu. Presque toujours malveillant.
6. **PrimaryGroupId == 512**. N'arrive jamais en provisionnement normal. Alerte dure.

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

Une variante haute confiance combine 4720 avec un 4732 ou 4728 dans un groupe privilégié dans l'heure, scopé par `TargetSid`.

## KQL : 4720 plus octroi de privilège

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

- T1136.001 Create Account: Local Account. Comptes locaux de postes et serveurs.
- T1136.002 Create Account: Domain Account. Créations enregistrées au DC.
- T1136.003 Create Account: Cloud Account. Ne déclenche *pas* 4720. Les créations cloud vivent dans les audit logs Entra ID / unified audit log.
- T1098 Account Manipulation. Quand 4720 est suivi d'une escalade de groupe ou de modifications d'attributs.

## Faux positifs qui ressemblent à des attaques

- Les outils de migration en masse (ADMT, Quest Migration Manager) créent des comptes à vitesse avec `SidHistory` posé. La forme est identique à un attaquant rapide. Baseline les fenêtres de migration connues.
- Les pipelines de joiner dans les workflows de provisionnement pilotés par RH déclenchent 4720 à des moments prévisibles. Alerter sur chaque 4720 hors heures vous enterrera sous les runs RH qui débordent après minuit.
- Les outils de gestion style SCCM, Intune et Jamf créent des comptes locaux pour le provisionnement OS. `SubjectUserSid` est `S-1-5-18` sur les hôtes de build connus. Étiquetez-les.
- Les installeurs de services pour certains produits legacy créent un compte de service local au premier lancement. Baseline l'installeur.

Les détections solides de 4720 combinent toujours la création avec un signal de suivi (ajout à un groupe, changement de mot de passe vers un motif faible connu, login immédiat depuis un hôte inhabituel). La création seule est trop bruyante.

## Ce que 4720 ne vous dit pas

L'enregistrement n'inclut pas le mot de passe du nouveau compte (Windows ne le journalise jamais, nulle part). Il n'inclut pas non plus le SID du domaine cible explicitement. Vous lisez le domaine depuis `TargetDomainName` ou le déduisez de la portion domaine de `TargetSid`.

Les créations de comptes locaux sur les postes membres sont invisibles pour le DC. Si vous ne collectez pas Security depuis les postes (la plupart des boutiques ne le font pas), vous ratez chaque compte backdoor local. Sysmon et un vrai EDR comblent une partie du manque (motifs de création de fichier et de modification de registre quand le SAM local est touché), mais le transfert de 4720 est le contrôle le moins cher. Le snapshot de la ruche du [registre](https://www.registryparser.com) est la corroboration quand le log forwarding était éteint.

## Où 4720 s'insère dans une timeline

La chaîne de persistance de manuel :

1. [4624](/fr/blog/understanding-event-id-4624). Logon initial de domaine par un utilisateur phishé.
2. Rafale de [4769](/fr/blog/event-id-4769-kerberoasting). Kerberoasting contre des comptes de service de domaine.
3. 4624 en tant que compte de service compromis sur un serveur membre.
4. [4688](/fr/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (ou `New-ADUser` via PowerShell).
5. **4720**. Compte créé sur le DC.
6. 4724. Mot de passe posé.
7. 4722. Compte activé.
8. 4728. Ajouté à Domain Admins.
9. [7045](/fr/blog/service-creation-event-id-7045). Service installé sur un serveur, tournant sous le nouveau compte.

Instrumentez 4720 seul et vous attrapez la persistance à l'étape 5, avant que les étapes 6 à 9 ne fassent de dégâts. C'est ça la valeur.

## Pour aller plus loin

- [Documentation Microsoft pour 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)
