---
title: "Triage EVTX : que lire en premier quand vous avez une heure et un hôte"
description: "Un ordre des opérations de praticien pour le triage des Windows Event Logs pendant la réponse à incident : quels canaux comptent, quels event IDs vous mentent, et où Sysmon fait le gros du travail."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

Si quelqu'un vous remet un bundle EVTX d'un hôte qu'il croit compromis et vous donne une heure, vous n'avez pas le temps pour l'élégance. Vous avez le temps pour un ordre des opérations qui a fonctionné assez de fois pour que vous lui fassiez confiance avant d'avoir lu un seul enregistrement.

Le voici. Ce n'est pas la référence complète et ce n'est pas la bonne chose pour chaque cas, les investigations d'initié à feu lent nécessitent une posture complètement différente, mais pour la question standard "est-ce que cette chose est piratée, et comment", c'est ce que je lance.

## Quels canaux remboursent vraiment le temps

Une installation Windows par défaut livre quelque part au nord de trois cents canaux EVTX. Vous en regarderez peut-être sept. Ceux qui comptent constamment :

- `Security.evtx` logons, utilisation de privilèges, changements de compte. Le premier arrêt pour chaque incident interactif.
- `Microsoft-Windows-Sysmon%4Operational.evtx` si Sysmon est déployé (et vous devriez supplier, plaider, menacer jusqu'à ce qu'il le soit), c'est là que vit le vrai signal. Process creates avec lignes de commande, file creates, connexions réseau, DNS, image loads. Tout ce que `Security.evtx` évoque sans le dire.
- `System.evtx` installations de service, drivers chargés, événements de boot, changements d'heure. Souvent le seul endroit où le lateral movement laisse une installation de service derrière lui.
- `Application.evtx` généralement du bruit, mais les erreurs de macro Office, les exceptions .NET et certains side-channels EDR émergent ici.
- `Microsoft-Windows-PowerShell%4Operational.evtx` module logging et événements de pipeline, si activés. Le log de script block `4104` est là où vous trouvez chaque ligne de PowerShell malveillant, en supposant que le logging était activé. C'est le deuxième canal le plus important après Sysmon quand les deux sont actifs.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` création, suppression et exécution de tâches planifiées. Se lit court, paye rapidement.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` souscriptions WMI et enregistrements de consommateur. Bon marché à lire ; attrape un schéma de persistance spécifique.

Si l'hôte a Defender, attrapez aussi `Microsoft-Windows-Windows Defender%4Operational.evtx`. La famille `1116` / `1117` est parfois la seule mention contemporaine du fichier qui comptait.

Tout le reste vous pouvez le laisser pour la deuxième passe.

## La première chose que j'ouvre n'est pas le Security log

Le réflexe par défaut est de greper `Security.evtx` pour `4624`. J'ai arrêté de faire ça à la première passe et vous devriez probablement aussi. Le Security log sur un serveur occupé logge des milliers de logons légitimes par heure. Vous allez vous noyer dans le bruit avant d'avoir cadré la question.

Ce que j'ouvre en premier, quand il existe, est `Sysmon%4Operational.evtx` filtré sur `EventID=1` (process create) dans la fenêtre suspectée. Sysmon vous donne le processus parent, la ligne de commande telle qu'invoquée réellement, l'utilisateur, le niveau d'intégrité, et les hashes du parent et de l'enfant. C'est assez pour lire une histoire à l'écran.

Si Sysmon n'est pas présent (et sur un nombre déprimant de parcs Windows d'entreprise il ne l'est toujours pas), mon mouvement suivant est `Security.evtx` filtré sur `4688` *avec l'audit de ligne de commande activé*. Si les lignes de commande ne sont pas auditées vous obtenez le nom de programme seul, ce qui est à peine utile, à ce point je saute à AmCache, Prefetch et le [journal USN](https://www.usnparser.com) pour reconstruire ce qui a tourné.

Le corollaire qui mérite d'être dit à voix haute : une investigation EVTX sans Sysmon et sans lignes de commande `4688` est en grande partie un jeu de devinettes. Si vous lisez ceci avant un incident, corrigez ça d'abord.

## Les event IDs que vous arrêtez de devoir chercher

Vous les apprenez par cœur avec le temps. La version courte, avec la façon dont je pense à chacun en IR :

- `4624` logon réussi. Lisez `LogonType` en premier : `3` est réseau (partage de fichier, outil distant), `10` est RDP / Terminal Services, `2` est interactif, `9` est `runas` avec credentials explicites. `5` est service. Le `LogonType` porte plus de sens que l'événement lui-même.
- `4625` logon échoué. Les rafales sont des attaques par spray ; les isolés sur de nombreux comptes sont du credential stuffing.
- `4634` / `4647` logoff et logoff initié par l'utilisateur. Utile pour fermer la parenthèse sur une session.
- `4648` logon avec credentials explicites. Celui que vous voulez vraiment pour l'attribution du lateral movement : quand le compte A utilise les credentials du compte B pour démarrer un processus ou se connecter quelque part, c'est l'enregistrement. La plupart des défenseurs le sous-utilisent.
- `4672` privilèges spéciaux assignés au logon. La ligne "ce compte vient de devenir admin". À apparier avec le `4624` qu'il suit.
- `4688` process create. Utile uniquement quand l'audit de ligne de commande est activé (Group Policy : *Audit Process Creation* et *Include command line in process creation events*). Sans ça, vous obtenez des noms de programme.
- `4697` service installé. Lateral movement via PsExec, Impacket-`smbexec`, et outillage similaire vit ici.
- `4720` / `4732` / `4738` compte créé, changement d'appartenance à groupe, compte modifié. La persistance adore ceux-ci.
- `1102` le Security log a été effacé. Si vous voyez ça, le reste du security log jusqu'à ce point est suspect ou absent. Le fait que l'événement existe du tout est le pistolet fumant.
- `5140` / `5145` partage réseau accédé. Le dernier logge le nom du fichier ; s'il est activé, le lateral movement via SMB est auditable en détail.
- `7045` service installé (System log). Reflète `4697` mais depuis le canal System.
- `Sysmon 1` process create avec contexte complet. L'event ID le plus utile en DFIR si Sysmon est activé.
- `Sysmon 3` connexion réseau. Attrape les C2 sortants même quand Defender ne l'a pas fait.
- `Sysmon 10` process access. Celui qui attrape le credential dumping depuis `lsass.exe`.
- `Sysmon 11` file create. Attrape l'activité de dropper qui n'a pas eu la chance de s'exécuter.
- `PowerShell 4104` script block logging. Enregistre le texte complet de chaque commande PowerShell, y compris les obfusquées (déobfusquées post-décodage dans de nombreux cas).

Je garde une feuille imprimée à côté de mon bureau et vous devriez aussi. Ce n'est pas glamour et ça économise de vraies minutes.

## Les événements qui vous mentent ou sont faciles à mal lire

`4624 Type 3` depuis `\\NT AUTHORITY\ANONYMOUS LOGON` n'est pas "l'attaquant est dedans". C'est généralement une énumération de partage mal configurée, un scanner de vulnérabilités, ou un parmi une demi-douzaine de mécanismes internes Windows. Validez avant d'escalader.

`4625` contre un seul compte de service au rythme d'un par minute est presque toujours un credential périmé caché quelque part. Regardez le champ de workstation source avant de l'appeler brute force.

Les horodatages dans Security.evtx sont en heure locale sur l'hôte qui les a générés par défaut dans certains outils, UTC dans d'autres. Quand vous chargez un bundle dans un nouvel outil, faites une vérification de bon sens en trouvant un logon que vous pouvez corréler avec un événement externe connu (une mise à jour de ticket, une session VPN) et confirmez les offsets. J'ai vu des rapports entiers décalés de 4 heures parce que quelqu'un avait oublié de vérifier.

L'effacement d'event log (`1102`) est généralement bruyant, mais la suppression sélective d'enregistrements est une autre bête. `wevtutil cl` efface le canal entier, ce qui est détectable. Des outils comme `phant0m` et `Invoke-Phant0m` suspendent à la place les threads du service d'événements, ce qui ne laisse pas d'événement d'effacement mais crée un trou visible. Cherchez le trou, pas juste le `1102`.

Les forwarded events (`Microsoft-Windows-EventLog%4ForwardedEvents`) préservent le RecordID original de l'hôte d'origine et les horodatages originaux. Si vous avez un abonné WEC qui a survécu à l'incident, ces copies sont parfois le seul enregistrement intact qui reste.

Si le Security log montre `1100` (arrêt du service d'événements) suivi d'un trou inexpliqué, vous regardez une des tentatives les plus propres d'effacer des preuves. Cross-validez contre [les hives du registre](https://www.registryparser.com), la [Master File Table](https://www.mftparser.com), et Prefetch.

## Carving et récupération, quand les enregistrements manquent

Les enregistrements EVTX peuvent être carvés depuis le disque non alloué et depuis [pagefile.sys](https://www.pagefilesysparser.com) quand le fichier vivant a été effacé ou a tourné. L'en-tête d'enregistrement (magie `2a 2a 00 00`) est suffisamment distinctif pour que le carving par signature fonctionne raisonnablement bien. `hayabusa` de Yamato Security et `evtx_dump` gèrent tous deux les fichiers malformés avec des flux d'enregistrements rapiécés.

Si vous traitez un hôte où vous suspectez que le log a été altéré, essayez aussi de récupérer des enregistrements EVTX d'un [dump RAM](https://www.ramparser.com). Le service d'event log met en cache les enregistrements récents en mémoire ; un snapshot pris près de l'incident contient parfois des enregistrements qui ne sont jamais arrivés sur le disque.

## Où aller depuis un hit

Un seul événement ferme rarement un cas. Les points de pivot que je cherche, dans l'ordre :

- Un `4624` suspect cherchez le `4672` correspondant, les échecs `4625` précédents, et quel processus a été créé avec ce token ensuite (Sysmon 1 avec `LogonId` correspondant).
- Une installation de service `7045` ou `4697` vérifiez `Microsoft-Windows-TaskScheduler%4Operational.evtx` pour des tâches consécutives, et le [registre](https://www.registryparser.com) `HKLM\SYSTEM\CurrentControlSet\Services\` pour le chemin du binaire.
- Un Sysmon 10 contre `lsass.exe` arbre de processus du processus demandeur, drops de fichier dans le répertoire de travail, connexions réseau vers des destinations non-corporate.
- Un PowerShell 4104 avec contenu obfusqué décodez dans une sandbox, puis cherchez le même payload atterrissant sur d'autres hôtes (la plupart des acteurs d'entreprise réutilisent).

## Lire EVTX dans le navigateur

Le parser sur ce site lit EVTX entièrement côté client : déposez un fichier et vous obtenez une table triable et filtrable avec canal, RecordID, EventID, heure, computer et le XML rendu. Pas d'upload, ce qui compte parce que EVTX d'environnements régulés contient presque toujours du PII que vous ne voulez pas traverser une frontière de fournisseur.

## Pour aller plus loin

- [JPCERT/CC "Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) le document unique le plus utile sur la corrélation d'événements de lateral movement. Vaut une lecture lente.
- [EvtxECmd](https://github.com/EricZimmerman/evtx) d'Eric Zimmerman parser offline avec les sorties canoniques de mapping de champs.
- La configuration Sysmon que Microsoft Threat Intelligence (anciennement SwiftOnSecurity) maintient comme baseline : [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Démarrez d'ici, n'écrivez pas la vôtre à partir de zéro.

La version cynique de tout ce qui précède : avec Sysmon et audit de ligne de commande, EVTX vous donne 80% de ce dont vous avez besoin pour reconstruire une intrusion. Sans eux, vous faites de la forensique sur la silhouette de l'événement plutôt que sur l'événement lui-même.
