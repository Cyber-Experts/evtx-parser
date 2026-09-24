---
title: "« Description de l'ID d'événement introuvable » : corriger"
description: "Pourquoi l'Observateur d'événements ne trouve pas la description d'un Event ID, ce que signifient les codes %%1833, et comment lire l'événement hors ligne."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "Que signifie « The description for Event ID X from source Y cannot be found » ?"
    answer: "L'enregistrement lui-même est intact. Un enregistrement .evtx ne stocke que l'ID d'événement, le nom du provider et les chaînes d'insertion (EventData / UserData). La phrase que vous lisez habituellement dans l'Observateur d'événements est un modèle stocké dans la DLL de messages du provider, sur la machine qui affiche le journal. Si ce provider n'est pas enregistré sur votre machine, l'Observateur ne peut pas construire la phrase et affiche cette erreur suivie des chaînes d'insertion brutes."
  - question: "Les données de l'événement sont-elles perdues ou corrompues ?"
    answer: "Non. Tous les champs sont toujours dans l'enregistrement. Ouvrez l'onglet Détails (Affichage XML) de l'Observateur d'événements, ou lisez les champs EventData avec Get-WinEvent, wevtutil ou un analyseur. Seul le texte lisible qui les enrobe manque."
  - question: "Que signifie %%1833 dans un événement ?"
    answer: "%%1833 est une référence de message de paramètre résolue depuis msobjs.dll, le fichier de messages de paramètres du provider d'audit de sécurité. %%1833 signifie Impersonation (champ ImpersonationLevel du 4624). Autres codes fréquents : %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 type d'élévation de jeton 1/2/3."
  - question: "Comment exporter un .evtx pour qu'il s'ouvre avec les descriptions sur un autre ordinateur ?"
    answer: "Sur la machine source, dans l'Observateur d'événements, utilisez Enregistrer tous les événements sous, choisissez .evtx, puis sélectionnez l'option d'affichage des informations pour les langues voulues. L'Observateur écrit un dossier LocaleMetaData contenant des fichiers .MTA à côté du .evtx. Copiez les deux ensemble. wevtutil archive-log (wevtutil al) fait la même chose en ligne de commande."
  - question: "Puis-je lire l'événement sans installer le provider ?"
    answer: "Oui. En DFIR, vous avez rarement besoin du message rendu : les champs EventData contiennent toutes les valeurs que le message afficherait. L'analyseur en navigateur d'evtxparser.com affiche aussi une description d'une ligne pour les événements DFIR courants et décode hors ligne les codes %%, les codes NTSTATUS et les types de chiffrement Kerberos, sans envoyer le fichier."
---

Vous copiez un `Security.evtx` depuis un hôte suspect, vous l'ouvrez sur votre poste d'analyse, et chaque enregistrement affiche :

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

Sur un Windows en français, le même message commence par « La description de l'ID d'événement 4625 dans la source Microsoft-Windows-Security-Auditing est introuvable. » Suit un bloc de valeurs brutes : `%%2313`, `0xC000006A`, `0x17`. Rien n'est cassé, rien n'est perdu. C'est un échec de *rendu*, pas un échec de données. Cet article explique où vit réellement le texte de description, pourquoi il disparaît, comment le corriger quand vous en avez besoin, et pourquoi, en triage, vous n'en avez généralement pas besoin. (Si vous voulez simplement des événements lisibles tout de suite : [l'analyseur en navigateur](/fr) rend les descriptions et décode ces codes hors ligne.)

## Ce que l'erreur signifie vraiment

Un enregistrement `.evtx` ne stocke pas la phrase que vous lisez dans l'Observateur d'événements. Il stocke le bloc `<System>` (provider, Event ID, horodatage, ordinateur) et les **chaînes d'insertion** dans `<EventData>` ou `<UserData>` ([ce que contient un enregistrement](/fr/blog/what-is-an-evtx-file)). La phrase, « Un compte n'a pas réussi à se connecter. Sujet : … Raison de l'échec : … », est un modèle avec des placeholders `%1`, `%2` stocké dans une **ressource de table de messages** à l'intérieur d'une DLL ou d'un EXE appartenant au provider de l'événement.

L'endroit où Windows cherche ce fichier dépend du type de provider :

- **Les sources d'événements classiques (legacy)** s'enregistrent sous `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, avec le chemin dans la valeur `EventMessageFile` (plus, éventuellement, `ParameterMessageFile` et `CategoryMessageFile`).
- **Les providers basés sur un manifeste** (Vista et suivants, la famille `Microsoft-Windows-*`) s'enregistrent sous `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. Les valeurs `MessageFileName`, `ResourceFileName` et `ParameterFileName` pointent vers les binaires qui portent le manifeste compilé (ressource `WEVT_TEMPLATE`) et la table de messages.

Le point clé : **l'Observateur d'événements rend le message sur la machine où vous consultez le journal**, avec le registre et les DLL de cette machine. La machine qui a écrit l'événement ne joue aucun rôle à l'affichage. Si le provider n'est pas enregistré localement, il n'y a pas de modèle, et vous obtenez l'erreur suivie des chaînes d'insertion brutes.

## Causes fréquentes

- **Le journal vient d'un autre hôte.** Le cas DFIR classique. Un agent tiers, un EDR, une instance SQL Server ou une application métier présents sur l'hôte source n'ont aucun provider sur votre poste d'analyse. Ouvrir le fichier sur macOS, Linux ou une VM vierge produit le même effet : aucun provider Windows du tout.
- **Le logiciel a été désinstallé.** Le programme de désinstallation a supprimé la DLL, mais les anciens événements référencent toujours la source.
- **DLL manquante, corrompue ou déplacée.** Le registre pointe vers un chemin qui n'existe plus, ou `EventMessageFile` est stocké en `REG_SZ` au lieu de `REG_EXPAND_SZ`, si bien que `%SystemRoot%` n'est jamais développé.
- **Incohérence 32/64 bits.** Un installeur 32 bits a écrit sa DLL dans ce qu'il croyait être `System32` (en réalité `SysWOW64`, via la redirection du système de fichiers), alors que le chemin enregistré est lu par la pile Event Log 64 bits comme le vrai `System32`.
- **Langue.** La table de messages du provider existe mais pas dans la langue d'affichage, ou vous avez ouvert un export enregistré « avec les informations d'affichage » pour une autre langue que celle de votre visionneuse.

## Les codes %% : messages de paramètres

Même quand la description principale s'affiche, certains champs montrent `%%1833` ou `%%2313` au lieu de mots. Ce sont des références de **messages de paramètres** : la valeur est un identifiant dans une seconde table de messages, le `ParameterMessageFile` / `ParameterFileName` du provider. Pour le provider d'audit de sécurité, ce fichier est `msobjs.dll`. Hors ligne, ces références restent non résolues. Celles à connaître par cœur (libellés tels qu'affichés par un Windows en anglais) :

| Code | Signification | Où on le voit |
|------|---------------|---------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Type 1, jeton complet (UAC désactivé ou admin intégré) | 4688 `TokenElevationType` |
| `%%1937` | Type 2, jeton élevé | 4688 `TokenElevationType` |
| `%%1938` | Type 3, jeton limité | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (compte verrouillé) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (compte désactivé) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

Le triplet `%%2080 %%2082 %%2084` est la signature normale d'un compte fraîchement créé dans un [4720](/fr/blog/event-id-4720-account-created). Un `%%1937` sur un [4688](/fr/blog/event-id-4688-process-creation) désigne un processus lancé avec un jeton administrateur complet après une invite UAC.

Les valeurs hexadécimales ne sont pas des codes `%%`. Les champs `Status` / `SubStatus` du [4625](/fr/blog/detecting-4625-brute-force) sont des codes NTSTATUS : `0xC000006A` est un mauvais mot de passe pour un compte valide, `0xC0000064` un nom d'utilisateur qui n'existe pas, `0xC0000234` un compte verrouillé. `TicketEncryptionType` sur le [4769](/fr/blog/event-id-4769-kerberoasting) est un etype Kerberos : `0x17` est RC4-HMAC, `0x12` AES256. Les deux s'affichent en hexadécimal brut même quand le provider est présent.

## Correctif 1 : exporter avec les informations d'affichage

Si vous avez encore accès à l'hôte source, exportez le journal pour qu'il voyage avec ses messages. Dans l'Observateur d'événements : clic droit sur le journal, **Enregistrer tous les événements sous…**, choisissez `.evtx`, puis dans la boîte de dialogue suivante sélectionnez l'affichage des informations pour les langues voulues (**Display information for these languages** sur un Windows en anglais). L'Observateur écrit un dossier `LocaleMetaData` à côté du fichier, avec un fichier `.MTA` par langue. Gardez ce dossier à côté du `.evtx` quand vous le copiez ; l'Observateur de la machine d'analyse le prend en compte.

En ligne de commande :

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) ajoute les métadonnées de langue à un fichier exporté. Pour la collecte à grande échelle, voir [collecter des EVTX sur un système vivant](/fr/blog/collecting-evtx-from-live-system).

## Correctif 2 : installer ou réparer le provider

Sur une machine que vous administrez, quand les événements de vos propres logiciels ne s'affichent pas :

- Réinstallez ou réparez l'application propriétaire de la source.
- Vérifiez `EventMessageFile` sous `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` : le chemin doit exister, et le type de valeur doit être `REG_EXPAND_SZ` s'il contient `%SystemRoot%`.
- Pour les providers à manifeste, vérifiez `Get-WinEvent -ListProvider <Name>` ; s'il échoue ou ne liste aucun message, l'enregistrement du manifeste est cassé (`wevtutil im <manifest>.man` le réenregistre, binaires en place).

## Correctif 3 : rendre sur l'hôte source

`Get-WinEvent` ne remplit la propriété `Message` que si le provider est présent localement. Sur l'hôte source (ou une machine avec les mêmes logiciels installés), ceci fonctionne :

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Sur votre poste, la même commande renvoie un `Message` vide, mais `.Properties` et `.ToXml()` exposent toujours chaque valeur. Plus de recettes de filtrage dans [interroger des EVTX avec Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent) (en anglais).

## Correctif 4 : vous n'avez généralement pas besoin du message

En DFIR, la phrase rendue est un confort. Chaque valeur qu'elle afficherait se trouve dans `<EventData>` : `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. L'onglet **Détails** (Affichage XML) de l'Observateur les montre même quand l'onglet Général affiche l'erreur. Les analystes qui travaillent à l'échelle lisent de toute façon les champs directement, et c'est ainsi qu'il faut aborder le [4624](/fr/blog/understanding-event-id-4624) et le reste de la [famille des événements de logon](/en/blog/windows-logon-events-explained) : les noms de champs sont stables d'une version et d'une langue de Windows à l'autre, le texte rendu ne l'est pas.

## Lire les événements hors ligne dans le navigateur

[L'analyseur EVTX](/fr) affiche désormais une description lisible d'une ligne pour une soixantaine d'événements DFIR courants : logons et échecs 4625, modifications de comptes et de groupes, Kerberos 4768/4769/4771, NTLM 4776, services 7045/4697, tâches planifiées, Sysmon, PowerShell 4104 et RDP. Il décode aussi en ligne les codes `%%`, les codes NTSTATUS (`0xC000006A` mauvais mot de passe, `0xC0000064` utilisateur inconnu) et les types de chiffrement des tickets Kerberos (`0x17` RC4). Aucune DLL de provider, aucun Windows requis ; le fichier est analysé dans votre navigateur et jamais envoyé. Pour les autres façons d'ouvrir le fichier, voir [comment ouvrir un fichier EVTX](/fr/blog/how-to-open-an-evtx-file).

## Checklist

- L'erreur signifie que **la machine qui affiche** n'a pas le provider, pas que l'enregistrement est endommagé.
- Lisez `<EventData>` dans l'onglet Détails, via `.Properties` de `Get-WinEvent`, ou avec un analyseur.
- Décodez les références `%%` avec le tableau ci-dessus ; décodez `Status` / `SubStatus` comme des NTSTATUS.
- Besoin du texte rendu pour un rapport ? Réexportez sur l'hôte source avec les informations d'affichage (`LocaleMetaData`) ou `wevtutil al`.
- Pour vos propres logiciels, corrigez `EventMessageFile` ou réenregistrez le manifeste.
