---
title: "Event ID 4720 expliqué : détecter la création de compte malveillant dans AD"
description: "4720 se déclenche à chaque création de compte utilisateur — local ou AD. Lu avec 4722/4724/4732, il révèle persistance et comptes de mouvement latéral en minutes."
date: "2026-05-24"
---

L'Event ID **4720** — « Un compte utilisateur a été créé » — est écrit sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un nouveau compte utilisateur est provisionné. Sur un contrôleur de domaine, il se déclenche pour chaque nouveau user AD ; sur un poste ou un serveur membre, il se déclenche pour chaque nouveau compte local. Dans une structure mature, le trafic 4720 est massivement piloté par les RH et prévisible. Cette prévisibilité est ce qui le rend utile : un attaquant créant un compte backdoor ressort précisément parce que le trafic légitime est si régulier.

C'est l'un des enregistrements de détection de persistance les moins chers que la plateforme produit.

## Où il se déclenche

- **Comptes domaine** : 4720 atterrit sur le DC qui a traité la création. Collectez depuis tous les DC.
- **Comptes locaux** : 4720 atterrit sur l'hôte où le compte a été créé. Attraper cela depuis les postes membres requiert WEF ou une collecte par hôte — beaucoup de structures sautent le forwarding Security des postes et perdent ce signal entièrement.

Si l'attaquant crée un compte *local* sur un serveur déjà compromis (souvent comme credential de secours), le 4720 ne sera que sur ce serveur. La couverture compte.

## Ce que contient l'enregistrement

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

Les champs qui pilotent les investigations :

- **`TargetUserName`** — le nouveau compte. Le nom littéral est le premier signal de triage : `svc_*`, `backup*`, `admin2`, `test`, `guest2`, des sosies de comptes légitimes (`administrator`, `administr0r`), et de courtes chaînes aléatoires méritent tous un regard.
- **`SubjectUserName` / `SubjectLogonId`** — *qui* l'a créé. Pivotez vers le [4624](/fr/blog/understanding-event-id-4624) qui a créé cette session. Un 4720 depuis `LocalSystem` sur un poste hors heures de bureau n'est pas un vrai workflow de provisionnement.
- **`UserAccountControl`** — l'ensemble *initial* de flags UAC. `0x10` (l'exemple) est `NORMAL_ACCOUNT` ; les flags dangereux apparaissent dans les enregistrements 4738 (compte modifié) ultérieurs. Le bitmap UAC complet est dans MS-SAMR.
- **`PrimaryGroupId`** — 513 (Domain Users) est normal ; 512 (Domain Admins) sur un nouveau compte est une anomalie criante qui ne devrait jamais arriver dans un vrai workflow de provisionnement.
- **`SidHistory`** — un `SidHistory` non vide sur un compte *nouvellement créé* est un signal fort d'un outil de migration — ou, dans le mauvais contexte, d'un artefact d'authentification forgé.

## Les enregistrements que 4720 n'arrive pas seul

La création de compte n'est presque jamais un événement unique. La séquence minimale :

| Événement | Signification | Pourquoi vous y tenez |
|---|---|---|
| **4720** | Compte utilisateur créé | Le titre. |
| **4722** | Compte utilisateur activé | Le compte est paramétré pour permettre le logon. Si 4722 est absent, le compte existe mais ne peut pas se connecter encore. |
| **4724** | Réinitialisation de mot de passe (admin-driven) | Quelqu'un — possiblement pas le créateur — a fixé ou réinitialisé le mot de passe. |
| **4738** | Compte utilisateur modifié | Flags UAC, expiration, groupe, changements d'attributs. |
| **4732** | Membre ajouté à un groupe local security-enabled | Si le groupe local est `Administrators`, c'est l'attribution de privilège. |
| **4728** | Membre ajouté à un groupe global security-enabled | Si le groupe global est `Domain Admins` ou `Enterprise Admins`, escalade. |
| **4756** | Membre ajouté à un groupe universel security-enabled | `Schema Admins`, `Enterprise Admins`, délégations custom. |

Un compte backdoor est rarement créé et laissé à privilège défaut. La chaîne complète — `4720 → 4722 → 4724 → 4738 (flags UAC) → 4732/4728 (ajout groupe)` — se boucle en secondes et est l'événement de persistance réel.

## Patterns de triage

1. **Nouveau compte → groupe admin en minutes** : 4720 suivi de 4732/4728 vers un groupe privilégié en une heure, où l'ajout au groupe privilégié n'a *pas* été précédé par un ticket dans le système de gestion des changements. Couplez le `TargetSid` du 4720 avec `MemberSid` sur 4732/4728.
2. **Création hors heures** : 4720 hors heures de bureau par un `SubjectUserName` qui n'est pas un compte de service faisant du provisionnement automatisé.
3. **Nom sosie** : `Levenshtein(TargetUserName, real_admin_name) <= 2` contre la table d'utilisateurs existants. `administrato`, `administr0r`, `helpd3sk` — tous sont des cas réels.
4. **Créé par un compte récemment compromis** : 4720 où `SubjectLogonId` remonte à un 4624 depuis une IP inhabituelle, ou un 4624 LogonType 3 depuis un poste que le sujet n'utilise pas normalement.
5. **Créé par `LocalSystem` sur un poste** : 4720 avec `SubjectUserSid = S-1-5-18` sur autre chose qu'un contrôleur de domaine ou un serveur de provisionnement connu. Presque toujours malveillant.
6. **`PrimaryGroupId == 512`** : n'arrive jamais en provisionnement normal. Alerte dure.

## Exemple de règle Sigma

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

Une variante haute-confiance : combiner 4720 avec un 4732/4728 vers un groupe privilégié en moins d'une heure, scopé par `TargetSid`.

## Exemple KQL — 4720 + attribution de privilège

KQL (Sentinel) — le pivot « nouveau compte → groupe admin » :

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

## Exemple Splunk

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

## Cartographie ATT&CK

- **T1136.001 — Create Account: Local Account** pour les comptes locaux poste/serveur.
- **T1136.002 — Create Account: Domain Account** pour les créations enregistrées DC.
- **T1136.003 — Create Account: Cloud Account** — ne déclenche *pas* 4720 (les créations de compte cloud sont dans les logs d'audit Azure AD / unified audit log, pas Windows Security).
- **T1098 — Account Manipulation** quand 4720 est suivi par une escalade de groupe ou des changements d'attributs.

## Faux positifs qui ressemblent exactement à des attaques

- **Outils de migration en masse** (ADMT, Quest Migration Manager) créent des comptes à grande vitesse avec `SidHistory` posé. La forme de trafic est identique à un attaquant rapide ; baselinez les fenêtres de migration connues.
- **Pipelines joiner** dans les workflows de provisionnement RH déclenchent 4720 à des heures prévisibles. Si vous alertez sur chaque 4720 hors heures, vous vous noierez dans les runs de système RH qui dérivent après minuit.
- **Outils de gestion type SCCM / Intune / Jamf** créent des comptes locaux pour le provisionnement OS. Le `SubjectUserSid` sera `S-1-5-18` (LocalSystem) sur des hôtes de build connus ; taguez ces hôtes.
- **Installeurs de services** pour certains produits legacy créent un compte de service local au premier run. Baselinez l'installeur.

Les détections 4720 solides combinent toujours la création avec un signal de suivi (ajout de groupe, changement de mot de passe vers un motif faible connu, login immédiat depuis un hôte inhabituel). La création seule est trop bruyante.

## Ce que 4720 ne dit pas

L'enregistrement n'inclut pas le *mot de passe* du nouveau compte (Windows ne le journalise nulle part, jamais). Il n'inclut pas non plus le SID du *domaine cible* explicitement ; vous lisez le domaine depuis `TargetDomainName` ou le dérivez de la portion domaine de `TargetSid`.

Les créations de compte local sur des postes membres sont invisibles pour le DC. Si vous ne collectez pas Security depuis les postes (la plupart des structures ne le font pas), vous manquerez chaque compte backdoor local. Sysmon et un vrai EDR comblent une partie du gap (motifs file create / registry-change quand le SAM local est touché), mais le forwarding 4720 est le plus économique.

## Où 4720 s'inscrit dans une timeline

La chaîne textbook de persistance :

1. [**4624**](/fr/blog/understanding-event-id-4624) — connexion domaine initiale par un utilisateur phishé.
2. [**4769**](/fr/blog/event-id-4769-kerberoasting) en rafale — kerberoasting contre les comptes de service domaine.
3. **4624** comme un compte de service compromis sur un serveur membre.
4. [**4688**](/fr/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain` (ou la même chose via PowerShell `New-ADUser`).
5. **4720** — compte créé sur le DC.
6. **4724** — mot de passe fixé.
7. **4722** — compte activé.
8. **4728** — ajouté à Domain Admins.
9. [**7045**](/fr/blog/service-creation-event-id-7045) — service installé sur un serveur, tournant sous le nouveau compte.

Si vous instrumentez 4720 seul, vous attrapez la persistance à l'étape 5 — avant que les étapes 6-9 ne causent des dégâts. C'est ça la valeur.
