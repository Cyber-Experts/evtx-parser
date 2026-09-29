---
title: "Exécuter des règles Sigma sur des EVTX dans votre navigateur"
description: "2 395 règles SigmaHQ sur vos journaux .evtx sans installer Hayabusa ni Chainsaw : détection Sigma dans le navigateur, contexte ATT&CK, pivots et vos propres règles YAML."
date: "2026-09-29"
tags:
  - evtx
  - dfir
  - threat-hunting
  - sigma
  - sysmon
author: "Florian Amette"
---

Sigma est ce qui se rapproche le plus d'une langue commune en ingénierie de détection. Une règle décrit *à quoi* ressemble le suspect — un processus, une écriture dans le registre, une ouverture de session du mauvais type — et un backend la traduit dans la langue de votre SIEM. Pour des journaux posés sur le portable d'un analyste, la réponse habituelle est un outil en ligne de commande comme Hayabusa ou Chainsaw : télécharger un binaire, le pointer sur un dossier de fichiers `.evtx`, lire le CSV.

Cela fonctionne, mais suppose que vous ayez le droit d'exécuter un binaire non signé sur la machine où se trouvent les preuves, et le temps de l'installer. Ce visualiseur exécute désormais le jeu de règles SigmaHQ directement dans l'onglet du navigateur, à côté des événements. Rien n'est installé, rien n'est envoyé.

## Ce que vous obtenez en déposant un journal

Ouvrez un ou plusieurs fichiers `.evtx` comme d'habitude. Dès la fin de l'analyse, le Web Worker du parseur exécute toutes les règles intégrées sur chaque enregistrement, et l'onglet **Sigma** affiche un badge avec le nombre de règles qui ont détecté quelque chose.

Dans l'onglet :

- Les règles détectées sont regroupées par niveau — critique, élevé, moyen, faible, informatif — avec le nombre d'événements touchés par chacune.
- Sélectionner une règle affiche sa description, les tactiques et techniques MITRE ATT&CK (avec lien vers attack.mitre.org), les faux positifs documentés par l'auteur, les références, la source de journaux et l'identifiant de la règle.
- Les événements détectés sont listés avec les champs que la règle a réellement testés. Cliquez sur un horodatage pour ouvrir l'événement dans le tableau principal ; **Autour de cet événement** règle la plage horaire sur une fenêtre autour de lui, pour voir ce qui s'est passé juste avant et juste après.
- **Voir dans le tableau des événements** restreint le tableau aux détections de la règle : la recherche, la barre des champs et les exports travaillent dessus.
- La plage horaire existante s'applique : resserrez-la sur la fenêtre de l'incident et les compteurs suivent.
- **Exporter les détections** produit un CSV ou un JSON avec l'identifiant, le titre et le niveau de la règle, le numéro d'enregistrement, l'heure, l'ordinateur, le canal et les valeurs des champs clés.

Si les identifiants d'événements en jeu ne vous sont pas familiers, [Sysmon Event ID 1](/fr/blog/sysmon-event-id-1-process-create) et [Security 4688](/fr/blog/event-id-4688-process-creation) sont les deux enregistrements que la plupart des règles finissent par examiner.

## Quelles règles, et comment elles correspondent aux EVTX

Le jeu de règles est `rules/windows/**` d'une version figée de SigmaHQ (r2026-07-01 au moment de l'écriture). Il est récupéré au moment du build et livré avec le site sous forme de fichier JSON : le navigateur ne contacte jamais GitHub, et la Content Security Policy du site ne le permettrait de toute façon pas. Sur 2 403 règles Windows, 2 395 s'exécutent. Les 8 écartées utilisent les catégories `file_access` et `file_rename`, qui proviennent de fournisseurs ETW n'écrivant jamais dans un fichier `.evtx`. Les règles obsolètes ne sont pas importées.

Une règle Sigma désigne une source de journaux, pas un fichier. La correspondance est celle qu'utilisent Hayabusa, Chainsaw et pySigma :

- `category: process_creation` s'applique à Sysmon Event ID 1 **et** à Security 4688. Pour le 4688, les champs sont traduits : `Image` lit `NewProcessName`, `ParentImage` lit `ParentProcessName`, `IntegrityLevel` est déduit de `MandatoryLabel`, et les identifiants de processus hexadécimaux sont convertis.
- Les autres catégories Sysmon correspondent à leurs Event IDs : connexions réseau en 3, chargements d'images en 7, accès aux processus en 10, création de fichiers en 11, registre en 12–14, DNS en 22.
- `ps_script` et `ps_module` lisent les 4104 et 4103 de PowerShell Operational ; les règles `ps_classic_start` lisent le 400 de Windows PowerShell, où `HostApplication=` et ses voisins sont extraits du bloc `Data`.
- `service: security`, `system`, `windefend`, `taskscheduler`, `bits-client` et une quarantaine d'autres correspondent à leur canal.

Un 4688 n'a ni `OriginalFileName`, ni `Hashes`, ni `CurrentDirectory` : les règles qui ne reposent que sur ces champs ne peuvent pas s'y déclencher. C'est une propriété du journal, pas du moteur : si vous voulez que ces règles fonctionnent, collectez Sysmon.

## Apportez vos propres règles

Le bouton **Vos règles** accepte du YAML collé dans une zone de texte ou des fichiers `.yml` déposés dessus (plusieurs règles séparées par `---` conviennent). Chaque règle est analysée et compilée dans le worker ; les erreurs sont signalées règle par règle, et les règles valides rejoignent l'exécution suivante :

```yaml
title: Service installé depuis un profil utilisateur
id: 3b0f0b6e-6b1d-4e36-9a44-6d2f7d8f7a11
author: Votre nom
level: high
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains: '\Users\'
  condition: selection
```

Vos règles restent dans le stockage local de ce navigateur pour survivre à un rechargement. Elles ne sont jamais envoyées nulle part.

## Ce que le moteur prend en charge

Le moteur implémente la partie détection de la spécification Sigma : sélections sous forme de maps et de listes, recherches par mots-clés, jokers avec les règles d'échappement de Sigma, et les modificateurs `contains`, `startswith`, `endswith`, `all`, `exists`, `re` (avec `i`, `m`, `s`), `cased`, `base64`, `base64offset`, `utf16le`, `utf16be`, `wide`, `windash`, `cidr`, `gt`, `gte`, `lt`, `lte` et `fieldref`. Les conditions acceptent `and`, `or`, `not`, les parenthèses, `1 of`, `all of` et `them`.

Deux choses ne sont volontairement pas prises en charge, et l'outil le dit au lieu de les ignorer en silence : les conditions d'agrégation (`| count() by …`) et les règles de corrélation Sigma. Aucune des règles Windows intégrées ne les utilise ; si vous en collez une, elle est listée comme non chargée avec la raison.

## Est-ce assez rapide ?

Exécuter naïvement 2 400 règles sur chaque événement serait lent : un seul enregistrement Sysmon de création de processus est candidat pour environ 1 200 règles. Le moteur range les règles par canal et Event ID, puis donne à chaque règle un pré-filtre littéral — par exemple, `Image` doit se terminer par `\certutil.exe`, ou `CommandLine` doit contenir `urlcache`. Ces littéraux sont indexés par champ, les sous-chaînes dans un automate d'Aho–Corasick, si bien que chaque enregistrement n'exécute que la poignée de règles dont le pré-filtre s'est déclenché. Dans la suite de tests, 200 000 événements synthétiques contre le jeu complet prennent environ cinq secondes, et le worker rend compte de sa progression et continue de répondre pendant l'exécution.

Pour une très grosse collecte — les journaux de tout un domaine — un outil natif sur un poste de travail restera plus rapide. Pour l'hôte que vous avez sous les yeux, c'est en général terminé avant que vous ayez fini de lire le panneau des constats. Pour savoir par où commencer pendant cette première heure, voir [que lire en premier lors du triage EVTX](/fr/blog/evtx-triage-incident-response).

## Rendre à César

Les règles sont le travail de la communauté SigmaHQ et sont publiées sous la Detection Rule License 1.1. Chaque détection affiche « Règle de *auteur* · SigmaHQ · DRL 1.1 » avec un lien vers la règle d'origine, et chaque ligne exportée porte la même attribution. Si une règle vous aide à boucler un dossier, sa section de références pointe en général vers la recherche qui la sous-tend — elle mérite la lecture.
