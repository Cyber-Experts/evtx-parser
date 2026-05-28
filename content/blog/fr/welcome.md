---
title: "Commencer ici : guide .evtx pour l'analyste DFIR"
description: "Ce qu'est .evtx, quels canaux comptent, les Event ID à connaître et où trouver chacun sur le disque. Un point de départ pour tout le reste du blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` est le format binaire du journal d'événements Windows livré par Microsoft avec Vista pour remplacer l'ancien `.evt`. C'est l'épine dorsale de toute réponse à incident Windows : connexions, installations de services, tâches planifiées, lignes de commande PowerShell, arbres de processus Sysmon. Tout cela est sérialisé dans ce format. Ce post est l'index. Une orientation sur un écran, puis des liens vers les articles plus profonds sur les canaux et Event ID qui comptent vraiment sur un cas.

Nouveau avec `.evtx` ? Commencez par [ce qu'est un fichier .evtx](/fr/blog/what-is-an-evtx-file) et [comment l'ouvrir](/fr/blog/how-to-open-an-evtx-file). Le reste de ce post suppose que vous êtes déjà à l'aise avec le format et que vous voulez savoir quoi lire en premier quand un hôte est en feu.

## Où vivent les fichiers

Les journaux actifs résident sous `C:\Windows\System32\winevt\Logs\`. Un canal, un fichier `.evtx`. Les défauts que vous aurez toujours :

- `Security.evtx`. Connexions, usage de privilèges, changements de politique d'audit. La valeur forensique la plus haute sur la plupart des cas.
- `System.evtx`. Pilotes, services, erreurs niveau OS.
- `Application.evtx`. Erreurs au niveau application.
- `Setup.evtx` et `ForwardedEvents.evtx`. Enregistrements d'installation et trafic WEF transféré.

Plus les canaux par application sous `Microsoft-Windows-*`. Ceux qui gagnent leur place sur un cas :

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Présent uniquement si Sysmon est installé. Vaut de l'or quand il l'est.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Journalisation des scriptblocks et des modules.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Création et exécution de tâches planifiées.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Cycle de vie des sessions RDP.

Pour les détails approfondis sur la mise en page d'un fichier (les chunks de 64 Ko, les tables de modèles XML, BinXML), voyez [le deep dive au niveau chunk](/fr/blog/evtx-file-format-chunks).

## Les Event ID à connaître

La liste courte qui couvre l'essentiel des pivots d'un analyste :

- [**4624** connexion réussie](/fr/blog/understanding-event-id-4624). Lisez-le via `LogonType`. Le champ décide si vous regardez une console (2), un réseau (3), un RDP (10) ou un `runas /netonly` (9).
- [**4625** connexion échouée](/fr/blog/detecting-4625-brute-force). Les rafales sont de la reconnaissance, du brute force ou du password spray selon les champs qui se regroupent.
- [**1102** journal de sécurité vidé](/fr/blog/event-id-1102-cleared-log). Si vous voyez cela, le journal que vous avez en main a un trou connu. Notez-le bruyamment.
- [**4104** scriptblock PowerShell](/fr/blog/powershell-4104-scriptblock). Le corps du script *après* décodage et réflexion. Le contrôle défensif gratuit le plus utile de la plateforme.
- [**7045** service installé](/fr/blog/service-creation-event-id-7045). L'une des techniques de persistance les plus citées de MITRE ATT&CK (T1543.003). Aussi la signature de PsExec.
- [**Sysmon 1** création de processus](/fr/blog/sysmon-event-id-1-process-create). L'enregistrement de création de processus le plus riche que Windows puisse produire quand Sysmon est présent.

Pour le workflow qui les relie, lisez [triage EVTX quand vous avez une heure et un hôte](/fr/blog/evtx-triage-incident-response).

## Comment ce site s'intègre

Le parser sur la page d'accueil est le crate Rust [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compilé en WebAssembly et exécuté dans un Web Worker. Vous déposez un `.evtx`, le worker parcourt les chunks, et vous obtenez une timeline d'événements filtrable plus le XML par enregistrement. Le tout dans le navigateur, rien n'est téléversé. Utilisez-le pour du triage ad hoc quand vous ne voulez pas monter un EDR ou déplacer un fichier hors d'un système qui ne vous appartient pas.

Si vous [collectez du `.evtx` depuis un hôte vif](/fr/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), ce post couvre les quatre méthodes standard avec les compromis de chaîne de garde de chacune.

EVTX est rarement le seul artefact dont vous avez besoin. Combinez-le avec les parsers [registre](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [prefetch](https://www.prefetchparser.com) et [LNK](https://www.lnkparser.com). Quand il faut creuser plus loin, le parsing du [pagefile](https://www.pagefilesysparser.com) et du [dump RAM](https://www.ramparser.com) récupère ce que les journaux résidents en disque ont perdu. Pour les timelines d'activité utilisateur, [SRUM](https://www.srumparser.com), [jump lists](https://www.jumplistparser.com), [corbeille](https://www.recyclebinparser.com), [recent file cache](https://www.recentfilecacheparser.com) et [historique du navigateur](https://www.browserforensics.app) comblent les manques qu'EVTX ne peut combler.
