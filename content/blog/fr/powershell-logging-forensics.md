---
title: "Logging PowerShell : ce que vous obtenez avec module logging et script block logging activés"
description: "La différence pratique entre PowerShell module logging, script block logging, transcriptions et buffers AMSI, et les paramètres GPO qui activent vraiment les utiles."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Tout toolkit d'adversaire qui vaut la peine d'inquiéter exécute PowerShell à un moment donné. Les beacons Cobalt Strike le lancent. Empire et Covenant sont construits dessus. Les guides de living-off-the-land commencent avec ça. La bonne nouvelle est que depuis PowerShell 5.0, Microsoft livre du logging qui, quand correctement configuré, capture le texte littéral de tout ce que PowerShell exécute, y compris des payloads obfusqués après désobfuscation. La mauvaise nouvelle est que "quand correctement configuré" fait beaucoup de travail dans cette phrase. La plupart des environnements dans lesquels j'entre ont un des quatre logs pertinents activé, pas les quatre, et pas le plus utile.

Ce billet est ce que vous obtenez réellement, ce qui vaut la peine d'être activé, et où sont les lacunes.

## Les quatre logs, par ordre d'utilité

PowerShell écrit dans `Microsoft-Windows-PowerShell%4Operational.evtx`. Les event IDs qui comptent :

- `4104` script block logging. Le texte littéral de chaque script block que PowerShell compile et exécute. Si un block est signalé comme suspect par les heuristiques intégrées, il est loggé en sévérité Warning ; sinon en Verbose, qui est désactivé par défaut. C'est l'événement que vous voulez.
- `4103` module logging. Enregistre l'exécution de pipeline par module, avec binding de paramètres. Moins de prose que `4104`, plus structuré. Utile pour "quelles cmdlets ont tourné" sans le corps du script.
- `4105` et `4106` pipeline démarrée et pipeline arrêtée. Utiles pour le bracketing, pas pour le contenu.
- `400` / `403` (legacy, ère PowerShell 2.0) changements d'état du moteur. Les événements forensico-historiques. Vous les verrez encore sur des hôtes où quelqu'un a forcé une attaque de downgrade PS 2.0.

Si vous ne pouvez activer qu'une seule chose, activez `4104` en Verbose. Tout le reste est supplémentaire.

## Ce que `4104` capture réellement

Un événement `4104` contient le texte complet d'un script block tel que PowerShell l'a compilé. Deux choses découlent de "tel que PowerShell l'a compilé" :

- Le texte dans l'événement est la représentation *post-désobfuscation* dans la plupart des cas. Si un opérateur exécute `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`, vous obtenez à la fois l'appel `iex` externe (qui est lui-même un `4104`) et un *deuxième* `4104` pour le script block décodé interne, parce que PowerShell a dû compiler ce block pour l'exécuter. C'est la propriété la plus précieuse unique du logging `4104`.
- Les gros scripts sont divisés sur plusieurs événements en utilisant `MessageNumber` et `MessageTotal` dans les données d'événement. Un script de 50 Ko devient une chaîne d'événements que vous devez réassembler avant l'analyse. La plupart des outils font ça ; certains non. Si votre parser vous montre des fragments, vérifiez s'il gère la chaîne.

Le champ `Path` montre le fichier source s'il y en avait un. `Path` vide plus un corps de script entièrement inline équivaut à "ça vient du fil ou de la mémoire" et est la meilleure heuristique unique pour trouver l'activité d'opérateur interactive versus les scripts planifiés.

Le `ScriptBlockId` est un GUID. Les ré-exécutions du même block sur le même hôte réutilisent typiquement le GUID (à cause du cache), ce qui est pratique pour trouver "chaque hôte sur lequel ce code a tourné" si vous avez un SIEM avec recherche cross-host.

## Module logging : ce que `4103` ajoute

Module logging est plus ancien et plus bruyant que script block logging. Il s'accroche à la couche d'exécution de pipeline, donc pour chaque invocation de cmdlet dans un module loggé vous obtenez un `4103` avec le nom de la cmdlet, les paramètres bindés et une chaîne de payload.

En IR moderne, `4103` est le plus utile dans trois cas :

- L'attaquant a utilisé des cmdlets qui bindent des paramètres intéressants (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` montre la source ; `4103` montre les valeurs de paramètres résolues après expansion de variables.
- L'attaquant a utilisé des commandes encodées. `powershell -enc <base64>` produit un `4103` avec le texte décodé dans le payload avant que le `4104` correspondant ne soit émis.
- L'attaquant a désactivé `4104` (atteignable par édition de registre s'il a les droits admin locaux). `4103` vit sous un chemin de logging séparé et est parfois laissé activé quand `4104` est rendu silencieux.

Le piège : module logging logge seulement les modules explicitement activés. Le paramètre GPO veut soit `*` (logger tout) soit une liste de noms de modules. `*` est la réponse dans tout environnement qui prend le logging au sérieux. L'objection de "l'impact de performance" que vous entendrez est réelle pour des charges PowerShell très lourdes et fausse pour des desktops de flotte ordinaires.

## Les transcriptions ne sont pas des script block logs

Il y a un paramètre séparé appelé "Turn on PowerShell Transcription" qui écrit l'entrée et la sortie de chaque session dans un fichier texte sous un répertoire configuré. Ce n'est pas la même chose que `4104` et les gens les confondent constamment.

Les différences qui comptent :

- Les transcriptions incluent la *sortie* des cmdlets. `4104` non. Si vous voulez savoir ce que `Get-ADUser` a réellement retourné, les transcriptions sont ça.
- Les transcriptions sont des fichiers texte. Elles sont trivialement supprimables et trivialement modifiables sur un hôte compromis. Les événements `4104` vont vers un canal EVTX qui nécessite le clearing de log ou pire pour être perturbés.
- Les transcriptions vont par défaut dans le dossier documents de l'utilisateur sauf si `OutputDirectory` est défini. Si vous ne définissez pas `OutputDirectory` vers un partage réseau write-only, les transcriptions ne sont pas des preuves ; elles sont une courtoisie.

Activez les transcriptions avec `OutputDirectory` pointant vers un chemin UNC où l'utilisateur qui écrit a des permissions NTFS write-only (pas de lecture, pas de suppression). Ça vous donne le trail de sortie de cmdlets que `4104` ne donne pas, sans donner à l'attaquant l'option d'altérer ou supprimer son propre historique.

## AMSI et l'angle buffer

AMSI (l'Antimalware Scan Interface) est le hook runtime qui permet à Defender et à d'autres produits AV d'inspecter le contenu de scripts PowerShell avant l'exécution. Deux conséquences pour la forensique :

- Même si l'attaquant désactive le logging PowerShell, AMSI voit toujours le contenu du script juste avant l'exécution, et Defender loggera un `1116` ou `1117` dans `Microsoft-Windows-Windows Defender%4Operational.evtx` si le contenu correspond à une signature. L'événement Defender inclut le texte du script, partiellement, dans l'enregistrement de détection de menace. Sur les hôtes où script block logging était désactivé, c'est parfois le seul endroit où vit le code malveillant.
- Les techniques de "bypass AMSI" que les attaquants utilisent (patcher `amsi.dll!AmsiScanBuffer` en mémoire, fournir un `AmsiContext` forgé, hijack COM du provider AMSI) génèrent eux-mêmes typiquement des événements `4104` pour le code de bypass, *avant* que le bypass ne prenne effet. Le bypass ne peut pas désactiver le logging rétroactivement. Donc même sur des hôtes où l'opérateur a neutralisé AMSI avec succès, le moment où il l'a fait est enregistré.

Le pattern à chercher dans `4104` : petits script blocks contenant les chaînes `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect`, ou `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`. Ce sont les signatures de chaque bypass commun.

## Activer le logging

Les paramètres GPO vivent sous `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. Les trois que vous voulez activés :

- "Turn on PowerShell Script Block Logging" activé. Cochez "Log script block invocation start / stop events" si vous voulez les événements `4105`/`4106` de bracketing ; désactivé par défaut et généralement pas digne du volume.
- "Turn on Module Logging" activé. Noms de modules : `*`.
- "Turn on PowerShell Transcription" activé. `OutputDirectory` : un chemin UNC. `Include invocation headers` : coché.

Les chemins de registre correspondants si vous les définissez en dehors de GPO :

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

Appliquez aux OUs qui contiennent des machines que vous devriez enquêter. C'est "toutes" dans toute organisation sérieuse.

## Ce à quoi ça ressemble pendant une investigation

Une compromission où script block logging était activé vous dit, dans l'ordre :

1. Le premier `4104` avec un script block non-trivial d'un parent non-standard. Heure de première exécution.
2. La chaîne de `4104`s alors que le loader se déballe lui-même. Chaque couche d'obfuscation pelée et loggée.
3. Les cmdlets runtime du framework C2 (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, chaque nom de cmdlet offensif commun et ses variantes renommées).
4. Les commandes hands-on-keyboard de l'opérateur interactif. Elles se lisent comme une session shell enregistrée, parce que c'est ce que c'est.

Croisez les références avec [Prefetch](https://www.prefetchparser.com) pour trouver quand `powershell.exe` a tourné, [fichiers LNK](https://www.lnkparser.com) pour les fichiers que l'opérateur a ouverts, [AmCache](https://www.amcacheparser.com) pour le hash du binaire PowerShell lui-même (il est renommé parfois), et le [registre](https://www.registryparser.com) pour l'état GPO pour confirmer que le logging était réellement activé au moment des événements que vous lisez.

Une compromission où script block logging était désactivé vous dit presque rien sur PowerShell, et beaucoup sur votre posture de détection. Corrigez ça en premier.

## Pour aller plus loin

- La [documentation logging PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) de Microsoft. La référence officielle.
- Le post de FireEye / Mandiant [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility). Ancien mais toujours le writeup de perspective de terrain le plus propre.
- Le projet [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) de Daniel Bohannon. Le toolkit de désobfuscation qui complète l'analyse `4104`.
