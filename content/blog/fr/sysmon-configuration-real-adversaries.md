---
title: "Configuration Sysmon qui attrape de vrais adversaires"
description: "Une vision tranchée sur Sysmon : quels event IDs comptent vraiment en IR, pourquoi olafhartong/sysmon-modular est la bonne baseline, et les erreurs de configuration qui vous aveuglent face aux vraies attaques."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon est la chose unique avec le plus de levier que vous pouvez déployer sur un endpoint Windows. C'est gratuit, signé par Microsoft, et un Sysmon bien configuré transforme Windows d'une boîte noire en quelque chose que vous pouvez réellement enquêter. Un Sysmon mal configuré, en revanche, est le même coût d'espace disque avec la plupart de la visibilité exclue par des filtres trop agressifs. Je suis entré dans plus d'environnements avec le second qu'avec le premier.

C'est la posture de configuration que je défends dans chaque engagement qui touche la visibilité endpoint.

## Les EIDs qui méritent leur espace disque

Sysmon définit 29 event IDs à partir de la version 15. Vous n'en avez pas besoin de tous. Ceux qui remboursent le stockage qu'ils coûtent, en ordre de retour par octet :

- **EID 1 Process create**. L'événement le plus utile en DFIR. Processus parent, processus enfant, ligne de commande, niveau d'intégrité, utilisateur, les deux hashes de processus, et le process GUID. Si vous ne loggez rien d'autre de Sysmon, loggez ça.
- **EID 3 Network connection**. Chaque connexion TCP/UDP sortante avec processus source, IP destination, port, et l'image du processus. L'événement de détection C2. Le filtre est essentiel ici (une installation par défaut logge chaque requête de navigateur et votre rétention brûle en une semaine) mais la valeur par événement est extrême. Attrapez les sorties vers des destinations inhabituelles depuis des processus inhabituels (`rundll32.exe` vers une IP résidentielle, `mshta.exe` vers n'importe quoi).
- **EID 7 Image loaded**. Chargements de DLL et driver avec le hash de l'image chargée et le statut de signature. C'est comme ça que vous attrapez le DLL search-order hijacking, le sideloading, et les drivers non signés. Cher de tout logger ; bon marché et à haut rendement de logger les modules non signés et les modules chargés depuis des emplacements non standards.
- **EID 10 Process accessed**. Événements d'accès mémoire cross-process avec le processus source, processus cible, masque d'accès accordé, et le call trace. C'est l'événement de credential dumping. `mimikatz` ouvre `lsass.exe` avec `PROCESS_VM_READ` (`0x10`) et `PROCESS_QUERY_INFORMATION` (`0x400`). Tout dumper moderne le fait. La détection s'écrit toute seule.
- **EID 11 File created**. Nouvelles créations de fichier avec le processus qui écrit. Attrape l'activité de dropper qui n'a pas eu le temps de s'exécuter, le staging de ransomware, et la plupart des écritures de payload médiées par LOLBin.

Ces cinq sont les fondations. Si vous n'avez que celles-là, bien configurées, vous avez attrapé la plupart de ce que vous appelleriez une vraie intrusion avant qu'elle n'en devienne une.

Le niveau suivant qui vaut la peine d'être activé :

- **EID 8 CreateRemoteThread**. Injection de thread à travers les frontières de processus. L'événement classique de process injection.
- **EID 13 Registry value set**. Persistance via registre. Réglez vers les run keys, services, image file execution options, et les chemins de COM hijack.
- **EID 17/18 Named pipe created/connected**. Les beacons Cobalt Strike et de nombreux frameworks de post-exploitation utilisent des named pipes pour SMB et les communications inter-processus. Les noms de pipe sont souvent des défauts qui survivent d'engagement en engagement.
- **EID 22 DNS query**. DNS sortant avec le processus demandeur. Attrape le C2 basé DNS (DGA, DNS tunnel) quand EID 3 a manqué la connexion parce qu'elle n'a jamais ouvert de socket TCP/UDP.
- **EID 25 Process tampering**. Événements de manipulation d'image (process hollowing, doppelganging). Sysmon 13+.

EID 12 (registry key/value create), 14 (registry key/value renamed), 15 (file stream created avec FileCreateStreamHash) et 23 (file delete avec archive) sont utiles dans des investigations spécifiques mais produisent trop de volume pour être loggés partout par défaut. Activez-les pour un hôte que vous surveillez de près ou pour des chemins spécifiques.

EID 2 (process changed file creation time) est un événement anti-timestomp de niche. Vaut la peine sur les serveurs de fichiers. Optionnel ailleurs.

EID 4, 5, 6 (événements d'état Sysmon) sont opérationnels, pas de détection. Loggez-les pour pouvoir savoir quand Sysmon a été altéré.

## Pourquoi `olafhartong/sysmon-modular` est le bon point de départ

Il y a une demi-douzaine de configs Sysmon publics de qualité variable. Les deux les plus cités sont `sysmon-config` de SwiftOnSecurity et `sysmon-modular` d'Olaf Hartong. Les deux sont bons. `sysmon-modular` est celui vers lequel je pousse à cause de sa structure.

Le layout modulaire divise les filtres par EID et par technique en fichiers XML individuels qui sont concaténés au déploiement. Les bénéfices que ça donne :

- **Diffabilité**. Les changements au filtre d'une seule technique apparaissent comme un diff de fichier unique en git. Comparez à un XML monolithique de 4000 lignes où un petit changement disparaît dans le bruit.
- **Overlays par environnement**. Vous commitez l'arbre upstream et layered vos exclusions spécifiques à l'environnement par-dessus dans vos propres fichiers. Quand upstream met à jour un filtre, vous faites `git merge` et vos overlays survivent.
- **Authoring guidé par la couverture**. Les filtres sont organisés par technique MITRE ATT&CK. Vous pouvez voir d'un coup d'œil quelles techniques vous couvrez et lesquelles non. L'analyse de gap est l'arbre de fichiers.
- **Maintenance active**. Hartong met à jour le repo contre de nouvelles techniques et nouvelles versions de Sysmon. Le config SwiftOnSecurity a de longues phases de stagnation entre mises à jour.

Commencez depuis `sysmon-modular`. Commitez-le dans votre arbre de gestion de config. Layeriez vos exclusions. N'écrivez pas le vôtre depuis zéro ; vous allez manquer des choses.

## Les erreurs de configuration qui vous aveuglent

Les patterns que je vois dans les vrais engagements qui coûtent le plus de visibilité :

**Exclure trop agressivement sur EID 1**. L'instinct est d'exclure chaque processus légitime bavard pour garder le volume gérable. L'erreur est d'exclure par chemin parent ou image sans penser à ce qu'un attaquant peut spawn depuis ce parent. Si vous excluez chaque enfant de `services.exe`, vous avez exclu l'endroit exact où tournent les binaires de service installés par PsExec. Excluez par `User` (comptes système exécutant des binaires connus comme bons), par `IntegrityLevel`, et par correspondance précise de `CommandLine`, pas seulement par parent.

**Exclure EID 3 par nom d'image**. "Exclure toutes les connexions réseau de `chrome.exe`" est la règle canonique mauvaise. La première chose qu'un attaquant fait quand il doit évader le logging EID 3 est de hijacker un processus de navigateur. Excluez par plage d'IP destination (RFC1918 vers RFC1918, votre propre infra), par port (l'ensemble de ports IPC que vous avez validé), ou par tuple processus+destination. Jamais par image seule.

**Ne pas logger EID 7 du tout**. Le logging Image load est l'EID Sysmon le plus lourd en volume. La tentation de le désactiver est forte. Le coût de le désactiver est que le DLL sideloading, la technique la plus commune dans les intrusions modernes, est invisible pour vous. Le chemin du milieu : filtrer `Image load` aux modules non signés, modules chargés depuis `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%`, et `%PROGRAMDATA%`, et modules avec des noms correspondant à des listes d'abus connues. Ça réduit le volume d'un ordre de grandeur et garde le signal.

**Manquer EID 11 entièrement sur les chemins inscriptibles utilisateur**. EID 11 loggé pour `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%`, et `%PUBLIC%` attrape presque tous les droppers. Certains configs excluent ceux-ci à cause du volume. Le volume est le point : c'est là que se produisent les écritures qui comptent.

**Ne pas inclure l'algorithme de hash que vous voulez**. L'élément `<HashAlgorithms>` contrôle quels hashes Sysmon calcule. Le défaut est SHA1 seulement. `IMPHASH` est l'import-hash, utilisé fortement dans le tracking de malware ; `SHA256` est ce sur quoi la plupart des plateformes de threat intel se basent. Définissez `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` pour que les événements s'alignent sur ce que vos données d'intel utilisent.

**Ne pas logger les lignes de commande sur le parent**. Sysmon EID 1 logge à la fois `CommandLine` (enfant) et `ParentCommandLine` (parent). Certains configs désactivent `ParentCommandLine`. Ça tue le pivot le plus utile dans l'investigation d'arbre de processus ; sans ça vous avez un nom d'image parent mais aucune idée de quels arguments ont démarré ce parent.

**Ne pas activer EID 22 (DNS) du tout**. Le logging DNS est récent (Sysmon 10+) et de nombreux configs lui sont antérieurs. Activez-le. Filtrez les hôtes bavards (`*.windowsupdate.com`, votre AD interne), loggez tout le reste.

## Le compromis d'espace disque

Un Sysmon bien configuré sur une workstation typique produit 100-500 Mo d'EVTX par jour. Sur un serveur occupé, 1-5 Go. La taille de canal par défaut est 64 Mo, ce qui signifie que le fichier `Microsoft-Windows-Sysmon%4Operational.evtx` tourne en heures et votre rétention utilisable est courte.

La correction est en deux étapes. Premièrement, augmentez la taille du canal. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` la définit à 4 Go, ce qui vous donne des jours à des semaines sur la plupart des hôtes. Deuxièmement, forwardez vers un collector central avec une rétention plus longue. WEC fonctionne ; les agents SIEM fonctionnent ; le repo [Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) a le XML pour la souscription du canal.

La rétention centralisée compte plus que la rétention locale parce que le fichier local est ce que l'attaquant peut effacer. Une copie forwardée sur un collector qu'il ne peut pas atteindre est l'enregistrement durable. Configurez les deux.

## À quoi ressemble un bon Sysmon dans une investigation

Un hôte avec `sysmon-modular` déployé, tous les cinq EIDs core loggant, EID 7 filtré vers les modules intéressants, et forwardant vers un collector, vous donne :

- Un arbre de processus pour chaque exécution sur l'hôte, avec lignes de commande, hashes, et contexte utilisateur.
- Chaque connexion réseau sortante avec le processus d'origine.
- Chaque chargement DLL depuis un répertoire inscriptible utilisateur.
- Chaque accès mémoire contre `lsass.exe`.
- Chaque création de fichier dans `%TEMP%` et `%APPDATA%`.
- Chaque requête DNS avec le processus demandeur.

L'histoire de l'intrusion se lit toute seule à partir de ces données. Vous n'avez pas besoin de deviner. Vous n'avez pas besoin de carver. Vous la lisez, de haut en bas, et les lacunes dans l'histoire sont les questions à poursuivre. Croisez les références avec [AmCache](https://www.amcacheparser.com) et [Prefetch](https://www.prefetchparser.com) pour les preuves d'exécution binaire, le [registre](https://www.registryparser.com) pour la persistance, et le [journal USN](https://www.usnparser.com) pour les mutations de système de fichiers que l'EID 11 de Sysmon a peut-être manquées si son filtre était désactivé. Le parser sur ce site lit les canaux Sysmon avec la même fidélité que Security.evtx.

Sans Sysmon, vous avez `Security.evtx` et une wishlist.

## Pour aller plus loin

- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) d'Olaf Hartong. Le repo. Lisez le README, puis lisez trois ou quatre des fichiers XML spécifiques à une technique pour avoir une idée du style de filtre.
- [Documentation Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) de Microsoft. La référence officielle ; mince mais précise.
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) de Roberto Rodriguez. Chasses guidées par Sysmon avec les requêtes écrites.
- Le [sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide) de TrustedSec. Le doc de référence pour la sémantique des filtres.
