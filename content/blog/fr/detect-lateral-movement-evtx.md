---
title: "Détecter le mouvement latéral dans Security.evtx"
description: "Comment les outils d'adversaires réels se déplacent d'hôte en hôte dans les parcs Windows, et les combinaisons précises d'Event ID dans Security.evtx qui attrapent PsExec, Impacket et WMIExec."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

Le mouvement latéral, c'est là où la plupart des intrusions passent de « ils ont un pied dans la porte » à « ils possèdent le domaine ». C'est aussi là où le logging Windows est le plus utile et le plus trompeur. Les événements dont vous avez besoin sont tous dans `Security.evtx` et `System.evtx`. Les lire isolément ne vous mènera nulle part. Les lire dans les bonnes paires, avec la bonne corrélation cross-host, est ce qui sépare une timeline utile d'un mur de `4624`.

C'est la partie d'une enquête où j'arrête de scroller et je commence à greper par `LogonId`.

## Le squelette : ce qui se passe quand un attaquant se déplace

Il n'y a pas de motif universel de mouvement latéral, mais il y a une *forme* universelle :

1. L'attaquant s'authentifie de l'hôte A vers l'hôte B, soit avec le token de l'utilisateur actuel (pass-the-hash, pass-the-ticket ou un TGT/TGS Kerberos volé), soit avec des identifiants explicites pour un autre compte.
2. Quelque chose sur l'hôte B exécute leur payload : un service, une tâche planifiée, un WMI process create, une session PowerShell distante ou une invocation DCOM.
3. Ils ressortent pour chercher du tooling, des secrets ou le prochain saut.

Chaque étape laisse des événements. La question est de savoir si vous regardez les bons, et si le tooling a même été instrumenté.

## 4624 LogonType 3 est la porte d'entrée

Une connexion réseau réussie, `EventID=4624` avec `LogonType=3`, est la primitive de mouvement latéral la plus courante dans le journal. C'est aussi l'événement le plus bruyant que Windows génère. Un serveur de fichiers dans un bureau de 500 postes produit des dizaines de milliers de ceux-ci par jour, tous légitimes. Filtrer uniquement par `LogonType=3` ne vous mènera nulle part.

Ce qui vous mène quelque part :

- `IpAddress` et `WorkstationName` dans les données d'événement. Les anomalies se regroupent ici. Un poste se connectant sur un serveur depuis un sous-réseau différent à 02:14 UTC n'est pas rien.
- `AuthenticationPackageName` et `LogonProcessName`. Les logons NTLM (`NTLM` / `NtLmSsp`) entre hôtes joints au domaine dans un environnement Kerberos sont suspects par défaut. Un environnement Kerberos propre devrait être Kerberos-only pour l'auth intra-domaine, avec NTLM en repli uniquement pour l'accès par nom non-DNS et le legacy.
- Motifs de `TargetUserName`. Les comptes de service qui se connectent en interactif sont des drapeaux rouges. Les comptes domain admin qui se connectent sur des postes de travail sont des drapeaux rouges.

Le pivot que vous voulez : associez chaque `4624 Type 3` intéressant au `4672` (privilèges spéciaux) correspondant sur le même `TargetLogonId`. Si le logon a obtenu des privilèges admin, vous avez un candidat pour abus d'identifiants. Sinon, l'attaquant opère avec un token de moindre privilège et vous avez du temps.

## 4648 est l'événement que la plupart des défenseurs sous-utilisent

`4648`, « une tentative de logon a été faite avec des identifiants explicites », est généré chaque fois qu'un processus tournant sous le compte A invoque des identifiants pour le compte B pour faire quelque chose. C'est l'événement que vous voulez pour l'attribution. Quand `mimikatz` ou `Rubeus` injecte un ticket et que l'opérateur lance `net use \\TARGET /user:CORP\admin <pass>`, vous obtenez un `4648` sur l'hôte d'origine montrant les deux comptes et la cible.

Les champs qui comptent :

- `SubjectUserName` / `SubjectLogonId` : qui a initié.
- `TargetUserName` / `TargetServerName` : les identifiants de qui, contre quoi.
- `ProcessName` : quel binaire a fait l'invocation. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (pour exécution via WMI) et de plus en plus `pwsh.exe` sont les suspects habituels.

`4648` est le lien entre un hôte compromis et le prochain saut. Si vous avez un hôte suspect, dumpez `4648` de son journal Security d'abord. Il vous dira quels identifiants l'attaquant a et où il a tenté de les utiliser, en ordre temporel, à un seul endroit.

## 4672 et l'histoire des privilèges

`4672` est posé immédiatement après `4624` pour tout logon qui se termine avec au moins un privilège sensible (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc.). Il est généré pour chaque logon d'un membre de `Administrators`, `Domain Admins` ou de tout compte avec des privilèges élevant le token.

Traitez-le comme un tag, pas comme un constat. La requête utile est « montre-moi chaque `4672` suivi dans les 60 secondes d'un `4624 Type 3` depuis une IP source non-DC », qui fait remonter l'usage de token admin depuis des postes de travail qui ne devraient pas en émettre. La requête non utile est « montre-moi chaque `4672` », qui renverra chaque démarrage de service sur chaque serveur.

## 4697 et 7045 : les services comme exécution distante

PsExec, le `psexec.py` d'Impacket et `smbexec.py` fonctionnent en écrivant un binaire de service sur le partage `ADMIN$` de la cible, en l'enregistrant via le Service Control Manager, en le démarrant et en le démontant. Cela laisse :

- `5145` sur la cible montrant l'accès à `\\target\ADMIN$` avec le nom du fichier écrit (si l'audit d'accès aux objets est activé).
- `7045` dans `System.evtx` montrant l'installation du service. Le chemin du binaire du service et le nom du service sont dans les données d'événement. PsExec utilise `PSEXESVC` par défaut dans `%SystemRoot%` ; Impacket randomise les deux, avec des motifs qui varient selon la version et qui sont bien documentés.
- `4697` dans `Security.evtx` pour la même installation de service si vous avez la stratégie d'audit système configurée.
- `4624 Type 3` depuis le poste source de l'opérateur.

La signature est la *combinaison* : `4624 Type 3` depuis une source inhabituelle, immédiatement suivi de `5145` vers `ADMIN$`, immédiatement suivi de `7045` pour un service dont le binaire vit quelque part où il ne devrait pas. Chaque événement seul est plausible. La combinaison, en quelques secondes, avec le même `LogonId` les liant, ne l'est pas.

Noms de services à surveiller dans `7045` : chaînes aléatoires de 8 caractères minuscules (par défaut Impacket), `PSEXESVC` (par défaut PsExec), `WinExec` ou ses variantes, tout ce qui a un chemin de binaire sous `C:\Windows\` qui n'est pas signé et ne fait pas partie de l'ensemble normal de services du système.

## 5140 et 5145 : accès aux partages SMB en détail

`5140` journalise qu'un partage a été accédé ; `5145` journalise le nom de fichier accédé dans le partage, *si* l'audit d'accès aux objets pour le partage est activé. La plupart des environnements n'activent pas `5145` à cause du bruit. La plupart des environnements aimeraient aussi l'avoir lors d'un incident.

Pour le mouvement latéral, les événements `5145` qui comptent sont les accès à `ADMIN$`, `C$`, `IPC$` et toute voie `SYSVOL`/`NETLOGON` depuis des sources inhabituelles. `psexec.py` écrit son binaire de service en écrivant vers `\\target\ADMIN$\<random>.exe`. `secretsdump.py` lit `\\target\C$\Windows\System32\config\SAM` (et SYSTEM et SECURITY). Chacun d'eux est un `5145` avec un `RelativeTargetName` qui devrait sortir du lot.

Associez `5145` au [journal USN](https://www.usnparser.com) sur la cible. Le journal aura un `FILE_CREATE` pour le même fichier au même horodatage, ce qui vous donne une confirmation de seconde source que le fichier a réellement atterri, et une référence d'enregistrement [MFT](https://www.mftparser.com) à poursuivre.

## WMI comme vecteur de mouvement latéral

L'exécution distante basée sur WMI (`wmic /node:... process call create`, `wmiexec.py` d'Impacket, `Invoke-WmiMethod` de PowerShell) est plus difficile à repérer dans Security.evtx seul parce qu'elle n'installe pas de service. Vous obtenez :

- `4624 Type 3` sur la cible.
- Une création de processus sur la cible avec `WmiPrvSE.exe` comme parent. C'est dans Sysmon `EventID=1` si Sysmon est activé. Dans `4688` c'est la même image si l'audit de ligne de commande est activé.
- Des événements WMI dans `Microsoft-Windows-WMI-Activity%4Operational.evtx` montrant le consumer.

Si Sysmon n'est pas activé, le mouvement latéral basé sur WMI est essentiellement invisible dans les journaux d'événements en config par défaut. C'est une des raisons pour lesquelles chaque baseline de config pousse Sysmon fortement.

## Corréler entre hôtes

Le mouvement latéral est un problème de graphe. Un `4648` sur l'hôte A nommant l'hôte B et le compte `corp\admin` est une arête. Le `4624 Type 3` correspondant sur l'hôte B depuis l'IP de l'hôte A, avec `TargetUserName=admin`, est l'autre bout de la même arête. Le `4769` (ticket de service Kerberos) sur le DC montrant la demande de ticket pour `cifs/hostB` depuis `admin@CORP` est le troisième témoin.

En pratique, vous voulez tout de :

- Événements de logon depuis le `Security.evtx` de l'hôte source.
- Événements de logon depuis le `Security.evtx` de l'hôte cible.
- Événements TGT (`4768`) et TGS (`4769`) depuis le `Security.evtx` du contrôleur de domaine.
- Événements transférés depuis n'importe quel collecteur WEC, qui ont parfois la seule copie intacte si le journal local d'un hôte a été effacé.

Liez-les par `LogonId` à l'intérieur d'un hôte et par horodatage + compte + IP à travers les hôtes. Le papier classique de JPCERT/CC expose tout cela en détail et est le meilleur document gratuit sur le sujet.

Pour les artefacts côté hôte qui survivent à l'effacement du journal, appuyez-vous sur le [Prefetch](https://www.prefetchparser.com) comme preuve d'exécution du tooling attaquant, la clé `Services` du [registre](https://www.registryparser.com) pour la trace d'un binaire de service installé puis retiré, et les [fichiers LNK](https://www.lnkparser.com) ainsi que les [jump lists](https://www.jumplistparser.com) comme preuves de fichiers ouverts par un opérateur lors d'une session hands-on.

## Pour aller plus loin

- ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) de JPCERT/CC. La référence. Lisez-la deux fois.
- La [matrice Lateral Movement](https://attack.mitre.org/tactics/TA0008/) de MITRE ATT&CK et les mappings de sources de données par technique.
- Le [répertoire examples](https://github.com/fortra/impacket/tree/master/examples) d'Impacket. Si vous n'avez pas lu ce que `psexec.py`, `wmiexec.py` et `smbexec.py` font vraiment sur le câble, vos détections sont des suppositions.
