---
title: "Effacement de journaux d'événements et les trous qui survivent"
description: "Comment les attaquants effacent les journaux d'événements Windows, quelles preuves restent sur disque et dans les canaux transférés, et la différence entre wevtutil cl et les outils de suspension de threads comme Invoke-Phant0m."
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

L'effacement des journaux d'événements est la technique anti-forensique que tout opérateur apprend en premier et celle qui laisse la piste la plus exploitable. Cette seconde partie est contre-intuitive. Tout l'intérêt d'effacer des journaux est de retirer les preuves, et un attaquant qui parvient à effacer `Security.evtx` a retiré des milliers d'événements que vous vouliez lire. Mais l'acte d'effacer est en lui-même bruyant, les techniques qui essaient d'être plus discrètes laissent une signature différente et tout aussi diagnostique, et les canaux que la plupart des opérateurs oublient préservent assez pour reconstruire ce qui a été effacé.

Savoir ce qui survit compte parce que ça change la question que vous posez à l'hôte. « Qu'y a-t-il dans le journal Security » devient « qu'est-ce qui manque au journal Security, et où sont allés ailleurs ces événements ».

## 1102, 104, 1100 : la manière bruyante

Le réflexe par défaut d'un opérateur qui veut voir disparaître le journal Security est `wevtutil cl Security`. Cela produit :

- Un unique `EventID=1102` dans `Security.evtx`, généré immédiatement après l'effacement, enregistrant le compte qui a effectué l'effacement et l'heure. Cet événement survit dans le journal effacé parce que c'est le premier événement écrit dans le fichier fraîchement effacé. Traitez-le comme l'arme du crime. Le nom du compte, le poste source et l'heure de l'effacement sont tous dans les données de l'événement.
- Un `EventID=104` correspondant dans `System.evtx` du provider `Microsoft-Windows-Eventlog`, avec le nom du canal effacé. C'est le miroir System de `1102`. Parfois seul l'un des deux survit parce que l'opérateur a effacé plusieurs canaux et l'ordre compte.
- Un `1100` du service Event Log indiquant l'arrêt du service, si l'opérateur a arrêté le service avant d'effacer. La combinaison de `1100` suivi d'un trou inexpliqué suivi de `1102` est le motif classique « arrêt, altération, redémarrage ».

Ces trois événements sont la signature bruyante. Un attaquant qui sait ce qu'il fait ne les générera pas, ou il les générera et puis effacera *à nouveau* pour les retirer, ce qui produit un second `1102` et un journal survivant encore plus petit. Chaque passe d'effacement laisse un `1102`. Le fait qu'un hôte ait plusieurs `1102` dans son historique est en soi anormal.

Les événements effacés ne sont pas les seules victimes. Effacer un canal réinitialise le fichier EVTX sous-jacent, ce qui veut dire que le fichier sur disque est réécrit. Les chunks de l'ancien fichier sont désalloués. Ils sont récupérables depuis le disque si vous imagez l'hôte dans une fenêtre raisonnable, ce qui est l'autre branche de cette histoire (couverte dans le post de carving).

## `wevtutil cl` contre suspension de threads

Un opérateur plus sophistiqué n'efface pas du tout les journaux. Il suspend les threads du service Windows Event Log (`eventlog`), fait la chose bruyante qu'il veut faire, et reprend les threads. Pendant que les threads sont suspendus, les événements générés par l'OS et les applications sont mis en file dans l'infrastructure ETW mais ne sont pas écrits dans le fichier EVTX. À la reprise des threads, la file est principalement vidée, mais les événements qui ont débordé le buffer durant la fenêtre de suspension sont perdus à jamais.

C'est ce que fait `Invoke-Phant0m` (PowerShell, par Halil Dalabasmaz). Le module Mimikatz `event::drop` fait quelque chose de similaire mais opère en hookant le callback ETW à l'intérieur du processus du service. Les deux laissent :

- Pas de `1102`. Rien n'a été effacé.
- Pas de `104`. Même raison.
- Un trou. Les événements d'avant et d'après la fenêtre de suspension sont présents ; ceux de l'intérieur manquent. C'est la détection.

Le trou est détectable de deux manières. La première est un contrôle de cohérence des RecordID contigus : l'en-tête de chunk EVTX enregistre `FirstEventRecordIdentifier` et `LastEventRecordIdentifier`, et vous pouvez vérifier que les ID d'enregistrement sont monotones entre chunks. La suspension ne casse pas le compteur de RecordID (le service est suspendu, pas le provider ETW noyau), mais les horodatages à l'intérieur du chunk montreront une fenêtre sans événements de providers actifs, ce qui sur un contrôleur de domaine est criant d'évidence.

La seconde est la corrélation contre les canaux qu'on ne peut suspendre sans élever à nouveau. Le canal `Microsoft-Windows-EventLog%4Operational.evtx` journalise le cycle de vie du service event log lui-même. La suspension de threads ne génère pas ici d'événements explicites « thread suspendu », mais le heartbeat interne du service (événements `105`, `106`, et événements de debug spécifiques au provider quand le canal Operational est à plus forte verbosité) enregistre parfois l'incohérence.

La troisième, plus difficile, est la piste [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config). Sysmon écrit dans son propre canal via son propre driver et n'est pas affecté par la suspension du service event log. Un hôte avec Sysmon aura un enregistrement continu des créations de processus et des chargements d'image à travers la fenêtre de suspension. Croisez l'heure du trou suspecté dans `Security.evtx` avec le canal `Operational` de Sysmon ; si Sysmon montre un processus `powershell.exe` avec un contenu de ligne de commande correspondant au code source de Phant0m (ou à l'une des douzaines de variantes publiques) qui tourne au début du trou, vous avez votre réponse.

## Le canal forwarded events

Windows Event Collector (WEC) est le mécanisme standard pour transférer des événements vers un collecteur central. Les événements transférés arrivent au collecteur dans `Microsoft-Windows-EventLog%4ForwardedEvents` (sur les abonnés Windows Event Collector) et conservent le champ `Computer` de l'hôte d'origine, le `RecordID` original et les horodatages originaux.

Si votre environnement a WEC et que le collecteur lui-même n'a pas été compromis, le canal forwarded events est parfois le seul enregistrement intact de ce qui s'est passé sur un hôte dont le journal local a été effacé. Les événements sont identiques octet pour octet à ceux générés sur l'hôte d'origine (modulo les métadonnées ajoutées par le collecteur), et le `RecordID` de l'hôte d'origine vous permet de recoudre la copie transférée dans la timeline RecordID du journal local.

Le hic : les subscriptions WEC sont en pull par défaut, avec un heartbeat de 15 minutes. Un attaquant rapide peut effacer le journal local entre les heartbeats de forwarding et le collecteur n'aura que les événements antérieurs au dernier pull réussi. Configurez les subscriptions en mode `MinLatency` (push, avec latence de batch de 30 secondes) sur les canaux qui vous tiennent à cœur. Cela coûte du débit réseau et collecteur ; ça paie la première fois que vous en avez besoin.

L'autre hic : WEC ne transfère pas par défaut. Si personne n'a configuré la subscription, le canal collecteur est vide. Vérifiez l'état de subscription sur les collecteurs candidats avant de parier une enquête sur ce chemin probatoire.

## Suppression sélective et la question au niveau EVTX

La suppression sélective d'enregistrements (retirer des événements spécifiques d'un EVTX vivant en laissant le reste) est théoriquement possible en éditant le fichier avec la connaissance du format et en recalculant les CRC de chunk. En pratique personne ne le fait en opérations vivantes parce que le service event log a le fichier ouvert et verrouillé ; vous ne pouvez pas l'éditer depuis le user-land sans descendre le service, et descendre le service génère des événements `1100`/`105`.

Ce qui se passe dans la nature est l'altération hors ligne a posteriori. Un opérateur qui exfiltre le fichier EVTX, l'édite sur sa propre machine et le re-uploade pour remplacer le fichier vivant (après avoir arrêté le service) laissera :

- Des CRC incohérents sur les chunks édités, sauf à avoir correctement recalculé à la fois le CRC d'en-tête de chunk et le CRC de la région d'enregistrements.
- Des `LastEventRecordNumber` incohérents dans les en-têtes de chunk s'il ne les a pas mis à jour aussi.
- Des discontinuités dans les RecordID à travers les frontières de chunk.

Tout parser décent signale ces choses. `evtx_dump` avertit sur mismatch de CRC par défaut. `EvtxECmd` journalise l'écart dans sa sortie. Traitez tout avertissement CRC durant le parsing d'un EVTX d'un hôte suspecté compromis comme un indicateur d'altération potentielle et imagez le disque sous-jacent avant de faire quoi que ce soit d'autre.

## Ce qui ne remonte que dans `Microsoft-Windows-EventLog%4Operational.evtx`

Ce canal est séparé de `Security.evtx` et la plupart des attaquants l'ignorent. Il enregistre :

- Démarrage et arrêt du service event log (`105`, `106`).
- Changements d'état de canal (subscription démarrée, canal activé/désactivé).
- Événements d'enregistrement de manifeste.

Quand le service Event Log est redémarré (parce que l'opérateur a utilisé `Stop-Service eventlog`, ou parce qu'il a patché quelque chose et redémarré), vous obtenez ici des événements qui s'associent à la famille `1100`/`105`/`106`. Si `Security.evtx` montre `1100` à l'heure T et `EventLog%4Operational.evtx` montre un changement d'état de service correspondant à la même T, l'arrêt a été ordonné. Si `Security.evtx` montre un trou sans `1100` mais `EventLog%4Operational.evtx` montre que le service a été redémarré, le service a crashé ou a été tué sans arrêt ordonné, ce qui est suspect en soi.

Ce canal est petit et se lit vite. Ajoutez-le à votre checklist de triage par défaut.

## Validation croisée contre les artefacts d'hôte

Quand le journal Security est parti ou trafiqué, les artefacts qui survivent sont les suspects habituels :

- La [Master File Table](https://www.mftparser.com) pour le fichier EVTX lui-même. Les horodatages `$STANDARD_INFORMATION` et `$FILE_NAME` montreront quand le fichier a été réécrit par effacement.
- Le [journal USN](https://www.usnparser.com) pour les événements `DATA_OVERWRITE` et `DATA_TRUNCATION` sur `Security.evtx`. Ceux-ci montrent l'effacement en termes journal avec des horodatages haute résolution.
- Le [Prefetch](https://www.prefetchparser.com) pour l'exécution de `wevtutil.exe`, ou pour les exécutions de `powershell.exe` qui s'alignent avec l'effacement suspecté.
- [Shimcache](https://www.shimcacheparser.com) et [AmCache](https://www.amcacheparser.com) pour l'outillage que l'opérateur a apporté pour effectuer l'effacement, en particulier s'il a utilisé un binaire non par défaut.
- Les artefacts de [dump RAM](https://www.ramparser.com) si vous en avez capturé un. Le cache en mémoire du service event log aura des enregistrements qui n'ont jamais été flushés sur disque.

Le journal Security est une source. Traitez-le comme une source. L'enquête qui dépend de lui seul est à un fichier altéré d'être inutile. Le [parser de ce site](https://www.evtxparser.com) signale les mismatches CRC de chunk et les trous de RecordID dans sa sortie, ce qui est la vérification de premier passage la moins chère pour savoir si vous regardez un journal altéré avant d'y avoir investi une heure de lecture.

## Pour aller plus loin

- Le [source d'Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) de Halil Dalabasmaz. Lisez ce qu'il fait. La détection en découle directement.
- L'[entrée du ThreatHunter-Playbook sur 1102](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html) de Roberto Rodriguez et le matériel de détection de clearing alentour.
- La documentation Microsoft sur les [subscriptions Windows Event Collector](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) pour la configuration WEC qui vous donne le filet de sécurité des forwarded events.
