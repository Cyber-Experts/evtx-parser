---
title: "Carving d'enregistrements EVTX supprimés et récupération de journaux écrasés"
description: "Carving par signature d'enregistrements EVTX dans l'espace non alloué, le pagefile et la mémoire, et les outils qui gèrent gracieusement les chunks malformés quand le journal vivant n'a plus ce qu'il vous faut."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

Le journal Security d'un contrôleur de domaine chargé s'enroule en heures, pas en jours. La taille de canal par défaut est 20 Mo, soit quelques milliers d'enregistrements sur un hôte bavard. Le temps que vous [imagiez le disque](https://www.diskimageparser.com) en réponse à un incident qui a débuté il y a trois semaines, les événements que vous vouliez vraiment ont déjà déroulé hors du fichier vivant et se trouvent dans l'espace non alloué, le pagefile et possiblement l'hibernation. Les recarver fait partie de la routine de toute enquête pilotée par EVTX, et la plupart des défenseurs sautent cette étape parce qu'ils traitent le fichier vivant comme source de vérité.

Il ne l'est pas. Le fichier vivant, ce sont les derniers 20 Mo. Le disque a le reste.

## La signature : `2a 2a 00 00`

Tout enregistrement EVTX commence par le magic de 4 octets `2a 2a 00 00`. C'est `**` suivi de deux octets nuls. Cette signature est suffisamment distinctive pour que scanner une image disque brute avec `bulk_extractor`, `scalpel`, ou même un grep maison de 4 octets, renvoie un ensemble utile de candidats. La densité de signature sur un volume Windows est faible ; la plupart des hits sont des enregistrements réels.

La structure qui suit le magic est suffisamment bien définie pour valider les hits à bas coût :

- Octets 4-7 : `Size` (uint32). Doit être plausible (32 octets minimum, typiquement sous 4 Ko).
- Octets 8-15 : `EventRecordIdentifier` (uint64). Doit être un RecordID raisonnable pour la fenêtre temporelle.
- Octets 16-23 : `WriteTime` en FILETIME. Doit tomber entre Vista (la première version avec EVTX) et maintenant.
- Octets `Size-4` à `Size` : la même valeur `Size`, répétée comme marqueur de fin.

Un candidat où le `Size` de tête correspond au `Size` de queue, où le FILETIME se parse en une date plausible et où le RecordID est dans la plage, est presque à coup sûr un enregistrement réel. Les faux positifs tombent à presque zéro avec ces quatre vérifications.

Le défi est quoi faire avec les octets entre la tête et la queue.

## Le problème du chunk

Les enregistrements EVTX référencent des templates et des chaînes stockés une fois par chunk. Un enregistrement carvé isolé a des tableaux de substitution sans template à leur appliquer. Vous pouvez lire les valeurs typées directement depuis le tableau de substitution, ce qui suffit à récupérer des données niveau champ ("l'utilisateur X s'est connecté à l'heure T depuis l'IP Y"), mais le XML rendu que vous obtiendriez d'un parser vivant n'est pas reconstructible sans le chunk.

C'est la différence entre deux résultats de carving :

- **Carving record-only** : vous récupérez RecordID, timestamp, EventID et les valeurs de substitution. Vous pouvez construire une vue champ par champ de l'événement, mais pas le XML rendu humainement lisible.
- **Carving de chunk** : vous trouvez un chunk (magic `ElfChnk\0`, aligné sur 64 Ko) et récupérez sa table de templates avec les enregistrements. Maintenant vous avez tout.

`ElfChnk\0` est également carvable par signature. L'alignement 64 Ko aide parce que les chunks tombent sur des frontières de secteur sur disque ; un scan de signature aligné par offset est rapide. La plupart des outils de carving supportent les deux modes, et vous devriez exécuter les deux. Les chunks vous donnent des événements lisibles ; les enregistrements orphelins vous donnent le reste quand aucun chunk englobant n'a survécu.

## Où vivent les octets

Les endroits qui valent un scan, par ordre de rendement :

- **Clusters non alloués sur le volume qui héberge `%SystemRoot%\System32\winevt\Logs\`**. Quand un fichier EVTX s'enroule ou est effacé, le contenu ancien devient non alloué. NTFS ne met pas à zéro les clusters non alloués, donc les octets sont récupérables jusqu'à ce qu'ils soient réutilisés. Sur un serveur à faible churn en écriture, cela peut être des semaines.
- **Slack space dans le fichier EVTX vivant**. Les fichiers EVTX sont écrits par chunks de 64 Ko. Le dernier chunk du fichier est souvent partiellement rempli, et le slack contient la génération précédente de données écrites dans ces octets avant que le chunk actuel ne soit redimensionné. Ça vaut un scan.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. Le service event log cache les enregistrements et templates récents en mémoire. Les pages qui supportent ces structures se font swapper sous pression mémoire. Le pagefile est une mine d'or pour les enregistrements jamais flushés sur disque parce que l'hôte a crashé ou a été tué avant qu'ils n'y parviennent.
- **`hiberfil.sys`**. Snapshot compressé de la mémoire physique au moment de l'hibernation. Décompressez avec `Volatility 3` ou Hibr2Bin et cherchez les signatures d'enregistrement dans la mémoire brute résultante.
- **[Dump RAM](https://www.ramparser.com)** capturé pendant la réponse vivante. Le working set du service event log contiendra les enregistrements récents et les templates nécessaires à leur rendu.
- **Shadow copies (VSS)**. Les snapshots anciens du volume contiennent des versions anciennes des fichiers EVTX vivants. `vshadow` ou `vssadmin list shadows` suivi de `mklink /d` pour monter le shadow vous donne une copie de génération précédente du fichier avec les enregistrements qui étaient vivants au moment du shadow.

VSS est la source à plus fort levier sur les hôtes qui l'ont activé et n'ont pas été altérés au niveau VSS. Un serveur Windows moderne a typiquement 7-30 jours de shadow copies. Si l'incident s'est produit il y a trois semaines, le shadow du moment de l'incident peut contenir le journal vivant tel qu'il existait alors, non altéré.

## Outils qui gèrent l'entrée malformée

Un fichier EVTX propre est rare dans les scénarios de carving. Vous allez avoir des chunks partiels, des enregistrements sans queue, des templates qui référencent des offsets hors chunk, et des échecs de CRC partout. Les parsers qui gèrent ça ne sont pas les mêmes que ceux qui gèrent les fichiers propres.

- **`EvtxECmd`** (Eric Zimmerman). Le meilleur de sa catégorie pour le travail terrain IR. Passez `--inc` pour inclure les enregistrements qui ont échoué au parsing normal et il émettra ce qu'il a pu lire des enregistrements partiels. La sortie CSV est ce que vous voulez pour le travail de timeline.
- **`hayabusa`** (Yamato Security). Construit pour le hunting sur de grands corpus EVTX, avec des règles style sigma. Il gère raisonnablement les chunks partiels et est rapide. Le filtre `--exclude-status` vous permet de réduire le bruit des enregistrements corrompus.
- **`evtx_dump`** (la crate Rust d'Omer Ben-Amram). Robuste face aux structures malformées, sortie JSONL. Bon pour pipeliner dans `jq` ou un SIEM.
- **`evtxtools`** (Joachim Metz, partie de libevtx). L'implémentation de référence canonique du format. Plus lent que les autres mais il vous dit exactement quel champ a échoué quelle validation quand un enregistrement est partiellement récupéré, ce que vous voulez en déboguant une sortie de carving.
- **`bulk_extractor`** avec le scanner EVTX. L'étape de carving elle-même. Sort les enregistrements candidats avec leurs offsets dans l'image source pour validation ultérieure.

Un pipeline pratique :

1. `bulk_extractor -E evtx -o out/ image.dd` pour carver les enregistrements et chunks candidats depuis l'image disque.
2. Réassembler les chunks en fichiers EVTX synthétiques en concaténant les chunks carvés avec un en-tête de fichier forgé. Les exemples `libevtx` incluent un réassembleur de chunks compatible `evtxexport`.
3. Lancer `EvtxECmd` sur le fichier réassemblé avec `--inc` pour dumper tout ce qui est lisible en CSV.
4. Diffuser les RecordIDs carvés contre les RecordIDs du fichier vivant pour trouver les enregistrements qui n'étaient pas dans le journal vivant.

La sortie de l'étape 4 est ce que le carving vous donne : les événements que l'attaquant ou le temps a retirés du fichier vivant.

## Quand le journal vivant ne montre rien parce qu'il s'est enroulé

Le cas courant pour le carving n'est pas l'effacement anti-forensique ; c'est le rollover. Un incident d'il y a 30 jours sur un hôte avec un journal Security de 20 Mo et 50 événements par seconde a enroulé tout le fichier des dizaines de fois. Le journal vivant montre les dernières heures. Tout ce qui est entre les deux est dans le non alloué.

Le carving ici est direct parce qu'il n'y a pas eu d'altération. Vous scannez le non alloué, vous trouvez des chunks, vous réassemblez. Le rendement dépend de la quantité de churn en écriture qu'a eue le volume depuis le rollover. Un volume serveur avec des fichiers système majoritairement statiques et le répertoire EVTX comme source d'écriture dominante gardera longtemps les anciens chunks intacts. Un volume avec de lourdes écritures applicatives écrasera les régions non allouées plus vite.

Une astuce qui aide : le répertoire EVTX est à `%SystemRoot%\System32\winevt\Logs\`, ce qui est un des points les plus froids du volume en termes d'écritures concurrentes. Les runs de clusters libérés lors du rollover du fichier EVTX restent souvent non alloués pendant des semaines. Ce n'est pas vrai des volumes qui hébergent des données applicatives.

## Quoi faire avec ce que vous récupérez

Les enregistrements carvés vont dans la même timeline que les enregistrements vivants. Le RecordID et le WriteTime survivent au carving et sont les clés de jointure. Un `4624 Type 3` carvé au moment de l'accès initial soupçonné est aussi utile qu'un vivant, à la nuance près que vous ne pouvez pas nécessairement rendre son XML complet.

Croiser avec :

- Les entrées de la [Master File Table](https://www.mftparser.com) pour `Security.evtx` pour voir quand le fichier a été réécrit par effacement ou rollover.
- Le [journal USN](https://www.usnparser.com) pour les événements `DATA_OVERWRITE` sur le fichier EVTX, qui donne des timestamps haute résolution pour chaque rollover.
- Le [Prefetch](https://www.prefetchparser.com) pour les binaires qui ont tourné durant le trou, puisque `Prefetch` est indépendant de `Security.evtx` et survit à l'effacement du journal.
- [AmCache](https://www.amcacheparser.com) et [Shimcache](https://www.shimcacheparser.com) pour les preuves de première exécution.
- Les ruches du [registre](https://www.registryparser.com) dans les shadow copies pour l'état au moment de l'incident.

Un enregistrement carvé qui s'aligne avec une entrée Prefetch et un timestamp MFT sur un binaire suspect est une découverte. Un enregistrement carvé seul est une piste qui mérite d'être poursuivie.

## Pour aller plus loin

- Le travail de carving original d'Andreas Schuster dans le [papier DFRWS 2007](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). Les heuristiques de carving de tout outil moderne y remontent.
- La documentation [EvtxECmd](https://github.com/EricZimmerman/evtx) d'Eric Zimmerman et le flag `--inc` pour la gestion des enregistrements partiels.
- [hayabusa](https://github.com/Yamato-Security/hayabusa) de Yamato Security et son corpus d'exemple fourni, utile pour tester les pipelines de carving.
- [bulk_extractor](https://github.com/simsong/bulk_extractor) de Simson Garfinkel et son module scanner EVTX.
