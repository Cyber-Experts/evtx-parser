---
title: "Event ID 4624 expliqué : logon Windows réussi et référence LogonType"
description: "Ce qu'un enregistrement 4624 contient réellement, pourquoi le champ LogonType compte plus que l'événement lui-même, et comment les lire à grande échelle."
date: "2026-05-17"
---

L'event ID 4624, "Un compte s'est ouvert une session avec succès", atterrit sur le [canal `Security`](/en/blog/what-is-an-evtx-file) chaque fois que Windows authentifie une identité. C'est le seul enregistrement à plus fort trafic sur la plupart des workstations et la colonne vertébrale de presque chaque investigation IR. Savoir en lire un n'est pas optionnel.

## Ce qu'il y a dans un enregistrement 4624

Les parties intéressantes vivent dans `<EventData>` :

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Les champs `Subject*` sont le contexte de sécurité qui a *demandé* le logon (souvent `S-1-5-18` pour SYSTEM pendant les démarrages de service). Les champs `Target*` sont l'identité qui a fini par être authentifiée. Confondre les deux coûte des heures aux analystes. J'ai vu un analyste senior escalader sur un `Subject` qui s'est avéré être SYSTEM exécutant un service interne. Lisez les deux, deux fois, avant de faire l'appel.

## LogonType est le champ qui décide

Windows livre dix types de logon. En pratique seulement une poignée conduisent le triage :

- **2 Interactif**. Logon physique ou console.
- **3 Réseau**. SMB, RPC, WinRM, n'importe quoi à travers le fil. La vaste majorité du trafic normal.
- **4 Batch**. Tâches planifiées tournant comme un utilisateur.
- **5 Service**. Un service démarré sous un compte spécifique.
- **7 Unlock**. Workstation déverrouillée après un verrouillage d'écran.
- **8 NetworkCleartext**. Rare et suspect. Credentials envoyés en clair (Basic auth sur IIS, imprimantes anciennes, simple bind LDAP mal configuré).
- **9 NewCredentials**. `runas /netonly`. Souvent utilisé par des attaquants portant des credentials de domaine sur une machine sur laquelle ils n'ont que des droits locaux.
- **10 RemoteInteractive**. RDP. S'apparie avec `IpAddress` pour l'attribution de source.
- **11 CachedInteractive**. Compte de domaine connecté avec credentials cachés. Pas de DC joignable.

Un 4624 avec LogonType **10** depuis une IP externe à 03:00 un dimanche raconte une histoire très différente de 50 enregistrements LogonType **3** depuis un serveur de backup à 02:00.

## Avec quoi le chaîner

Un 4624 réussi seul est rarement un constat. Il en devient un quand apparié avec :

- [4625](/en/blog/detecting-4625-brute-force) le précédant depuis la même source. Un succès après une rafale d'échecs est la signature de manuel brute-force-puis-succès.
- [4672](/en/blog/event-id-4672-special-privileges). Signale les logons qui ont accordé des privilèges comme `SeDebugPrivilege`.
- 4648 (logon avec credentials explicites). Capture `runas` et autres patterns de passage de credentials. La plupart des défenseurs le sous-utilisent.
- [7045](/en/blog/service-creation-event-id-7045) le suivant avec LogonType 3. Installation de service après un logon réseau est la signature de PsExec.

## Les cinq patterns

Ceux qui déclenchent vraiment des alertes dans un vrai SOC, en ordre approximatif de combien souvent ils gagnent leur valeur :

1. **Brute-force-puis-succès.** Une rafale de [4625](/en/blog/detecting-4625-brute-force) depuis une IP source suivie en minutes par un 4624 depuis la même IP pour le même `TargetUserName`. L'attaquant a trouvé un credential fonctionnel. Capture la moins chère du catalogue d'audit.
2. **RDP hors-heures.** 4624 avec `LogonType=10` depuis IP externe en dehors des heures de bureau. Taguez les IPs d'egress VPN admin connues. Tout le reste est une vraie piste.
3. **`runas /netonly`.** 4624 avec `LogonType=9`. L'usage légitime est rare (outils admin utilisant des credentials de domaine étranger). L'usage attaquant est un pattern de pivot credentials après avoir capturé des credentials d'un hôte sur lequel ils ne veulent pas apparaître.
4. **NetworkCleartext (LogonType=8).** Credentials en clair sur le fil. Causes réelles sont les vieilles applis IIS Basic-auth, imprimantes anciennes, ou simple bind LDAP mal configuré. Chacune est une responsabilité de fuite de credentials.
5. **Dérive de LogonType sur les comptes de service.** Un compte de service qui historiquement ne tire que LogonType 3 produisant soudain LogonType 10 ou LogonType 2. Signifie presque toujours que quelqu'un utilise le compte de service interactivement. Signal fort de credentials volés.

## Sigma : logon réussi suivant une rafale d'échecs

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source. Brute-force-then-success.
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: windows
  service: security
detection:
  fail_burst:
    EventID: 4625
  success:
    EventID: 4624
    LogonType:
      - 3
      - 10
  timeframe: 10m
  condition: ( fail_burst | count() by IpAddress,TargetUserName > 10 ) and success
falsepositives:
  - Users repeatedly typing passwords after a recent password change
  - SSO endpoints with retry behavior on first auth
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## KQL : RDP hors-heures depuis IPs externes

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and not (IpAddress startswith "172." and toint(split(IpAddress, ".")[1]) between (16 .. 31))
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 7 or Hour > 20
| project TimeGenerated, Account, IpAddress, WorkstationName, Computer
| order by TimeGenerated desc
```

## Splunk : dérive de LogonType sur un compte de service

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

Les comptes de service devraient produire un `LogonType` unique et stable (généralement 3 ou 5). Plusieurs types sous le même compte est l'alerte.

## Mapping ATT&CK

- T1078 Valid Accounts (et sous-techniques `.001` Default, `.002` Domain, `.003` Local). Chaque logon réussi par un credential compromis se mappe ici. 4624 est la *preuve* de la technique.
- T1110 Brute Force. Combiné avec les rafales [4625](/en/blog/detecting-4625-brute-force).
- T1021 Remote Services (`.001` RDP, `.002` SMB, `.006` WinRM). Le gros du trafic 4624 LogonType=3/10 côté réseau.
- T1550 Use Alternate Authentication Material. `.002` Pass the Hash (4624 NTLM-package depuis source inattendue), `.003` Pass the Ticket (4624 Kerberos-package sans [4769](/en/blog/event-id-4769-kerberoasting) correspondant sur aucun DC).

## Faux positifs qui ressemblent exactement à des attaques

- Les scanners de vulnérabilité (Tenable, Qualys, Rapid7) génèrent un trafic dense 4624 LogonType=3 depuis un set stable d'IPs de scanner. Taguez et excluez.
- Les check-ins de client SCCM et Intune produisent un trafic 4624 récurrent vers les endpoints de management.
- Les agents de backup s'authentifient à de nombreux hôtes selon un planning. Ressemble à de la propagation. Ça ne l'est pas.
- Les boîtes Citrix et RDS multi-session voient légitimement LogonType=10 depuis de nombreuses IPs internes. Filtrez par plage source.
- UX de changement de mot de passe. Les utilisateurs qui viennent de changer un mot de passe et ont retapé l'ancien deux fois produisent 4625 / 4625 / 4624. Ce n'est pas du brute force, c'est de la mémoire musculaire.

Le signal est la récurrence *inattendue* ou les combinaisons *nouvelles*, pas le volume brut.

## Ce que 4624 ne vous dit pas

- Pas d'information de processus. Vous voyez le logon, pas ce qui a tourné dans la session résultante. Pivotez `LogonId` vers [4688](/en/blog/event-id-4688-process-creation) ou [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) pour voir l'activité processus.
- Pas de processus source pour le logon lui-même. Vous savez que NTLM ou Kerberos a été utilisé, mais pas quelle app client l'a initié.
- `IpAddress` peut être vide ou `-` pour les logons NTLM depuis un DC. Le champ n'est pas fiable sur chaque enregistrement.
- Les logons interactifs cachés (Type 11) se produisent quand le DC est injoignable. Ils confirment qu'un credential a fonctionné localement, pas que le compte vivant est activé sur le DC.

## Lire à grande échelle

Le [parser navigateur sur ce site](/en/blog/how-to-open-an-evtx-file) extrait ces champs directement du XML de l'enregistrement et les expose dans la table. Filtrez par `LogonType` via les buckets de timeline et le filtre texte, tirez le set filtré en CSV, puis pivotez sur `SubjectUserSid` et `IpAddress` dans votre outil de choix. Le XML complet de chaque enregistrement est à un clic. Appariez avec les [artefacts de cache RDP](https://www.jumplistparser.com), le tracking de [fichiers récents](https://www.recentfilecacheparser.com), et l'[historique du navigateur](https://www.browserforensics.app) quand le compte utilisateur en question est un vrai utilisateur, pas un service.

## Pour aller plus loin

- [Documentation Microsoft pour 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [JPCERT/CC : Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
