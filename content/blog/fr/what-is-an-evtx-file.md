---
title: "Qu'est-ce qu'un fichier .evtx ? Le format du journal d'événements Windows expliqué"
description: "Un fichier .evtx est un journal d'événements Windows binaire. Où ils résident, ce qu'ils contiennent, en quoi ils diffèrent du .evt, et comment les ouvrir. Sans rien installer."
date: "2026-05-24"
faq:
  - question: "Qu'est-ce qu'un fichier .evtx ?"
    answer: "Un fichier .evtx est le format binaire du journal d'événements Windows introduit avec Windows Vista. Il stocke les événements système, sécurité et application écrits par le service EventLog. Chaque machine Windows possède des dizaines de fichiers .evtx sous C:\\Windows\\System32\\winevt\\Logs\\, un par canal."
  - question: "Où les fichiers .evtx sont-ils stockés sous Windows ?"
    answer: "L'emplacement par défaut est C:\\Windows\\System32\\winevt\\Logs\\. Les trois fichiers les plus chargés sont Security.evtx, System.evtx et Application.evtx. Les canaux propres à chaque application résident dans le même dossier, sous des noms comme Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Quelle est la différence entre .evtx et .evt ?"
    answer: ".evt est le format binaire historique utilisé par Windows jusqu'à XP et Server 2003. .evtx l'a remplacé avec Windows Vista (2007) avec une structure par chunks basée sur BinXML qui prend en charge des métadonnées d'événement plus riches, des journaux plus volumineux et des requêtes structurées via wevtutil et Get-WinEvent. Les deux formats ne sont pas interchangeables."
  - question: "Comment ouvrir un fichier .evtx ?"
    answer: "Outils Windows natifs : l'Observateur d'événements (eventvwr.msc), wevtutil en ligne de commande, ou Get-WinEvent en PowerShell. Multiplateforme : ouvrez-le dans l'analyseur en navigateur de ce site (sans installation, sans envoi), ou utilisez evtxecmd en ligne de commande. Voir notre article how-to-open-an-evtx-file pour toutes les options."
  - question: "Puis-je ouvrir un fichier .evtx sur macOS ou Linux ?"
    answer: "Oui. Les outils Windows natifs ne fonctionneront pas, mais plusieurs analyseurs multiplateformes le font : l'analyseur en navigateur de ce site (tout OS avec un navigateur moderne), python-evtx, la crate Rust evtx, et evtxecmd via .NET. Aucun ne nécessite un hôte Windows."
---

Un fichier `.evtx` est le format binaire du journal d'événements Windows que Microsoft a livré avec Vista en 2007 pour remplacer l'ancien `.evt`. Chaque événement que le système d'exploitation, un pilote, un service ou une application écrit dans le journal d'événements Windows atterrit dans un fichier `.evtx` sur disque. Ils constituent la colonne vertébrale de toute enquête sous Windows. Si vous faites du DFIR sous Windows, vous passerez plus de temps dans ces fichiers que dans n'importe quelle autre classe d'artefacts.

## Réponse rapide

Les fichiers `.evtx` sont écrits par le service Windows EventLog dans `C:\Windows\System32\winevt\Logs\`. Un fichier par **canal** (`Security.evtx`, `System.evtx`, `Application.evtx`, plus les canaux propres à chaque application). En interne, chaque fichier est un conteneur binaire découpé en chunks d'enregistrements encodés en `BinXML`. Pas du texte brut. On les lit avec l'Observateur d'événements, `wevtutil`, `Get-WinEvent`, ou un analyseur tiers.

## Où résident les fichiers .evtx

Emplacement standard sur toutes les versions de Windows prises en charge (de Vista à Windows 11 et Server 2025) :

```text
C:\Windows\System32\winevt\Logs\
```

Chaque fichier `.evtx` correspond à un canal d'événements. Les canaux par défaut :

- `Security.evtx`. Connexions, usages de privilèges, modifications de la stratégie d'audit. La valeur forensique la plus élevée sur la plupart des cas.
- `System.evtx`. Pilotes, services, erreurs au niveau noyau.
- `Application.evtx`. Erreurs et événements informationnels au niveau applicatif.
- `Setup.evtx`. Enregistrements d'installation.
- `ForwardedEvents.evtx`. Événements collectés depuis d'autres hôtes via Windows Event Forwarding (WEF).

Les canaux propres à chaque application sont stockés dans le même dossier, où `%4` remplace le séparateur de chemin :

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Événements Sysmon de processus, réseau et fichiers (lorsqu'il est installé).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Journalisation des scriptblocks et des modules PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Créations et exécutions de tâches planifiées.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Cycle de vie des sessions RDP.

Les canaux faisant l'objet d'une rotation produisent des fichiers d'archive horodatés dans le même dossier (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). Le fichier actif est tenu ouvert par le service EventLog tant que Windows est en cours d'exécution, ce qui est la raison entière pour laquelle il existe [un article de collecte sur la façon de récupérer ces fichiers depuis un hôte vivant](/fr/blog/collecting-evtx-from-live-system).

## Ce que contient un fichier .evtx

Le fichier est un conteneur binaire, pas du texte brut. Un en-tête de 4 Ko (magic `ElfFile\0`) est suivi d'une séquence de **chunks** de 64 Ko. Chaque chunk possède son propre en-tête (`ElfChnk`), une table des **templates** XML qui apparaissent à l'intérieur, et un flux d'enregistrements qui référencent ces templates par identifiant. Un analyseur reconstruit chaque événement en substituant les valeurs propres à l'enregistrement aux placeholders du template. C'est ce qui rend le `.evtx` plus compact que du XML littéral sur disque.

Une fois décodé, chaque enregistrement est un document XML en deux moitiés :

- `<System>`. Nom du provider, canal, Event ID, niveau (1 Critical à 5 Verbose), nom de l'ordinateur, contexte de sécurité, et horodatage d'écriture UTC.
- `<EventData>`. Paramètres propres au provider : le compte cible sur une connexion, le chemin d'image sur une création de processus, la clé de registre sur une écriture auditée, etc.

L'Event ID seul suffit rarement au triage. Le signal forensique vit dans `<EventData>`. Pour la mécanique en profondeur du format (chunks, BinXML, templates, récupération des dirty chunks), voir [le deep dive au niveau chunk](/fr/blog/evtx-file-format-chunks).

## .evtx vs .evt : pourquoi le format a changé

Le format `.evt` historique utilisé par Windows jusqu'à XP et Server 2003 avait trois limites strictes que le nouveau format a été conçu pour corriger :

- **Chaînes de taille fixe.** Les enregistrements `.evt` transportaient des références à des tables de messages plutôt que le message complet. Les jointures à la lecture cassaient quand les DLL sources étaient absentes ou mises à jour.
- **Pas d'interrogation structurée.** Le filtrage exigeait de lire et d'analyser chaque enregistrement linéairement.
- **Un seul canal par fichier.** Les journaux applicatifs personnalisés nécessitaient leurs propres formats non standard.

Le `.evtx` (Vista, 2007) a introduit les enregistrements BinXML, des fichiers par canal avec une imbrication arbitraire, le filtrage de style XPath via `wevtutil qe` et `Get-WinEvent -FilterHashtable`, ainsi qu'une structure en chunks qui survit aux écritures partielles. La contrepartie était une rupture totale de compatibilité. `.evt` et `.evtx` ne sont pas interchangeables, et le seul outil intégré qui lit `.evt` sur un Windows moderne est `wevtutil` avec son drapeau hérité (et uniquement pour exporter vers `.evtx`).

## Comment ouvrir un fichier .evtx

Cinq voies courantes, par ordre approximatif de friction :

1. **Dans votre navigateur, sans installation.** Déposez le fichier dans l'analyseur sur la page d'accueil de ce site. Il fait tourner la crate Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilée en WebAssembly à l'intérieur d'un Web Worker. Rien ne quitte votre machine. Adapté pour un triage ad hoc lorsque vous ne voulez pas démarrer une VM forensique.
2. **Observateur d'événements (`eventvwr.msc`).** L'interface graphique intégrée à Windows. Action / Ouvrir un journal enregistré / sélectionnez le `.evtx`. Bon pour la navigation, faible pour le filtrage à grande échelle.
3. **`wevtutil` / `Get-WinEvent`.** Ligne de commande et PowerShell, tous deux livrés avec Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` déverse chaque enregistrement. `Get-WinEvent -Path` renvoie des objets que vous pouvez piper dans `Where-Object`.
4. **EvtxECmd.** L'analyseur d'Eric Zimmerman. Multiplateforme via .NET, rapide, produit du CSV avec une ligne par enregistrement et tout `<EventData>` aplati.
5. **`python-evtx`.** Pur Python, facile à scripter. Plus lent que la crate Rust mais utile lorsque vous disposez déjà d'une chaîne d'outillage Python.

Pour un parcours complet de chaque méthode avec les commandes réellement à exécuter, voir [Comment ouvrir un fichier .evtx](/fr/blog/how-to-open-an-evtx-file).

## Quand vous rencontrez du .evtx sur le terrain

- **Réponse à incident.** Extrait d'un hôte compromis dans le cadre du triage. Les canaux d'intérêt dépendent de la piste : `Security` pour les connexions et l'abus de privilèges, `Sysmon` pour les arborescences de processus, `PowerShell` pour le contenu des scriptblocks. Combinez avec les parsers [registre](https://www.registryparser.com), [MFT](https://www.mftparser.com), [journal USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com) et [prefetch](https://www.prefetchparser.com) pour la corroboration d'exécution.
- **Audits de conformité.** Les auditeurs demandent `Security.evtx` sur une fenêtre définie pour vérifier l'historique des connexions et des changements de politique.
- **Débogage applicatif.** `Application.evtx` ainsi que les canaux par éditeur contiennent souvent un contexte de crash et d'erreur que les propres journaux de l'application n'ont pas.
- **Threat hunting.** Des règles long-tail contre des `.evtx` archivés (ou un SIEM transférant le canal en direct) capturent des patterns à combustion lente comme du RDP hors heures ou des dérives de `LogonType` sur des comptes de service.

Le pivot le plus utile à lui seul est l'Event ID. Pour la liste courte qui mérite sa place dans un vrai SOC ([4624](/fr/blog/understanding-event-id-4624), [4625](/fr/blog/detecting-4625-brute-force), [1102](/fr/blog/event-id-1102-cleared-log), [4104](/fr/blog/powershell-4104-scriptblock), [7045](/fr/blog/service-creation-event-id-7045), [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create)), voir [l'orientation de départ](/fr/blog/welcome).

## Pour aller plus loin

- [Documentation Microsoft : Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Spécification du format EVTX libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (analyseur Rust)](https://github.com/omerbenamram/evtx)
