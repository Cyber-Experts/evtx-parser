import type { Dict } from "./types";

export const fr: Dict = {
  meta: {
    title: "Visionneuse et analyseur EVTX en ligne — journaux d'événements Windows",
    description:
      "Visionneuse et analyseur EVTX en ligne et gratuit. Ouvrez vos journaux .evtx Windows dans le navigateur — sans envoi, sans installation. Filtrez, inspectez le XML et exportez en CSV, JSON ou XML.",
    siteName: "EVTX parser",
  },
  home: {
    heading: "EVTX parser",
    headline: "EVTX parser — visualiseur de journaux Windows dans le navigateur",
    intro:
      "Déposez un journal d'événements Windows .evtx. L'analyse s'exécute entièrement dans votre navigateur via WebAssembly — rien n'est téléversé.",
    featuredHeading: "Guides en vedette",
    dropArea: "Déposez un .evtx ici ou cliquez pour choisir",
    privacyNote: "Les fichiers restent sur votre appareil. Analyse 100 % côté client.",
    statusReading: "Lecture de {name}…",
    statusParsing: "Analyse du journal d'événements…",
    eventsLabel: "événements",
    filterPlaceholder: "Filtrer par ID d'événement, fournisseur, canal, ordinateur…",
    clearFilter: "Effacer",
    noMatches: "Aucun événement ne correspond au filtre.",
    topIds: "IDs fréquents",
    exportCsv: "Exporter CSV",
    exportJson: "Exporter JSON",
    includeXml: "Colonne XML brut",
    exporting: "Export en cours…",
    clearTime: "Effacer la plage horaire",
    clearAll: "Tout effacer",
    removeFile: "Retirer le fichier",
  },
  table: {
    record: "Enr. #",
    time: "Heure (UTC)",
    level: "Niveau",
    eventId: "ID d'événement",
    name: "Nom",
    summary: "Résumé",
    provider: "Fournisseur",
    channel: "Canal",
    computer: "Ordinateur",
    source: "Source",
    viewDetails: "Détails",
    closeDetails: "Fermer",
    eventData: "Données d'événement",
    noEventData: "Aucun champ EventData pour cet enregistrement.",
    showRawXml: "Afficher le XML brut",
    hideRawXml: "Masquer le XML brut",
    prev: "préc.",
    next: "suiv.",
  },
  levels: {
    critical: "Critique",
    error: "Erreur",
    warning: "Avertissement",
    info: "Information",
    verbose: "Détaillé",
    unknown: "—",
  },
  faq: {
    heading: "FAQ journaux d'événements",
    items: [
      {
        q: "Qu'est-ce qu'un fichier EVTX ?",
        a: "EVTX est le format binaire du journal d'événements Windows introduit avec Windows Vista. Chaque fichier .evtx est une suite de blocs de 64 Ko ; chaque bloc contient une table de modèles XML suivie d'un flux d'enregistrements qui y font référence. L'analyse reconstitue le XML complet de chaque événement.",
      },
      {
        q: "Où se trouvent les fichiers .evtx sous Windows ?",
        a: "Les journaux actifs se trouvent sous C:\\Windows\\System32\\winevt\\Logs. Les trois principaux en forensique sont Security.evtx (connexions, privilèges), System.evtx (pilotes, services) et Application.evtx (erreurs applicatives). Les canaux Sysmon et PowerShell sont généralement les plus précieux en réponse à incident.",
      },
      {
        q: "Cet outil envoie-t-il mes .evtx quelque part ?",
        a: "Non. L'analyse s'effectue dans un Web Worker via un parseur EVTX en Rust compilé en WebAssembly. Le fichier est chargé en mémoire dans le navigateur et n'est jamais transmis. Coupez le réseau si vous souhaitez le vérifier.",
      },
      {
        q: "Que signifie la colonne Niveau ?",
        a: "Les niveaux EVTX sont numériques : 1 Critique, 2 Erreur, 3 Avertissement, 4 Information, 5 Détaillé. Microsoft place certains ID classiques (ex. Security 4625 = échec d'authentification au niveau Information) — la gravité seule n'est pas un signal de tri.",
      },
      {
        q: "Les fichiers .evtx volumineux sont-ils gérés ?",
        a: "L'analyse tourne dans un Web Worker. La mémoire croît avec la taille du fichier ; quelques centaines de Mo passent facilement dans un navigateur moderne. Pour les collections plus grosses, exportez avec evtx_dump et chargez par tranches.",
      },
    ],
  },
  footer: {
    blog: "Blog",
    builtWith:
      "Construit avec WebAssembly et le crate Rust omerbenamram/evtx. 100 % côté client — vos fichiers ne quittent jamais votre navigateur.",
  },
  notFound: {
    title: "404 — page introuvable",
    heading: "Page introuvable",
    description:
      "Cette URL n'existe pas sur ce site. Elle a peut-être été déplacée, ou vous avez suivi un lien obsolète.",
    backHome: "← Retour à l'accueil",
  },
  blog: {
    indexTitle: "Notes sur le journal d'événements",
    indexIntro:
      "Notes courtes sur le format binaire du journal d'événements Windows, les ID d'événements forensiquement utiles et les workflows de triage.",
    readMore: "Lire la suite",
    backToBlog: "← Retour au blog",
    publishedOn: "Publié le",
    updatedOn: "Mis à jour le",
    readingTime: "{n} min de lecture",
    prevPost: "← Article précédent",
    nextPost: "Article suivant →",
    relatedHeading: "Articles liés",
    resourcesHeading: "Ressources externes",
    byLine: "Par",
  },
  eventIds: {
    title: "Référence des Event ID Windows",
    intro:
      "Index sélectionné des Event ID Windows qui comptent en investigation forensique — groupés par canal, avec les champs EventData à lire en premier. Cliquez sur un ID couvert pour le guide détaillé ; les autres pointent vers Microsoft Learn.",
    description:
      "Index de référence des Event ID Windows utiles en DFIR : Security 4624/4625/1102, System 7045/7036, Sysmon 1/3/7/11, PowerShell 4104, TaskScheduler, Kerberos — avec liens vers nos guides détaillés.",
    columnId: "Event ID",
    columnName: "Nom",
    columnNotes: "Notes",
  },
  glossary: {
    title: "Glossaire du journal d'événements Windows",
    intro:
      "Les termes qui reviennent dans les enregistrements .evtx et les rapports DFIR, expliqués en une ou deux phrases.",
    description:
      "Définitions claires des termes du journal d'événements Windows : LogonType, BinXML, canal, provider, chunk, template, SID, EventData, RecordID, etc.",
  },
  tools: {
    title: "Outils EVTX comparés : KAPE, FTK Imager, wevtutil, evtx_dump",
    intro:
      "Comparaison côte à côte des outils utilisés en investigation Windows — ce que chacun fait vraiment bien, son coût et ses limites.",
    description:
      "Comparez KAPE, FTK Imager, wevtutil, evtx_dump, python-evtx, RawCopy et EVTX parser — par plateforme, cas d'usage, licence et limites. Choisissez le bon outil pour la collecte, l'analyse ou le triage en navigateur.",
    columnTool: "Outil",
    columnPlatform: "Plateforme",
    columnUseCase: "Cas d'usage principal",
    columnLicense: "Licence",
  },
  breadcrumb: {
    home: "Accueil",
    label: "Fil d'Ariane",
  },
  eventId: {
    title: "Event ID {id} : {name} ({channel})",
    intro:
      "Ce que cet Event ID enregistre vraiment sur disque, les champs EventData à lire en premier et sa place dans un workflow de triage DFIR.",
    description:
      "Windows Event ID {id} ({name}) sur le canal {channel} : signification, champs EventData, techniques offensives courantes et Event IDs liés.",
    channelLabel: "Canal",
    providerLabel: "Fournisseur",
    notesLabel: "Notes de triage",
    inDepthHeading: "Guide détaillé",
    inDepthCta: "Lire l'analyse complète",
    microsoftLearnHeading: "Microsoft Learn",
    microsoftLearnCta: "Ouvrir la référence officielle",
    relatedHeading: "Event IDs liés",
    notCoveredYet:
      "Cet Event ID figure dans l'index mais n'a pas encore d'analyse détaillée. Microsoft Learn couvre les champs au niveau du protocole.",
    notFoundTitle: "Event ID inconnu",
    notFoundDescription:
      "Cet Event ID ne figure pas encore dans l'index de référence.",
  },
  tags: {
    indexTitle: "Sujets — tous les tags du blog",
    indexIntro:
      "Tous les sujets couverts sur le blog, avec le nombre d'articles par tag. Utilisable comme second axe de navigation à côté de l'index Event ID.",
    indexDescription:
      "Parcourez les sujets du blog EVTX parser : audit Security, Sysmon, PowerShell, Kerberos, services, internes du format EVTX et collecte forensique.",
    tagTitleTemplate: "Articles taggés « {tag} »",
    tagIntroTemplate:
      "Tous les articles du blog taggés « {tag} », plus récents d'abord.",
    tagDescriptionTemplate:
      "Articles d'analyse Windows Event Log taggés « {tag } » — notes DFIR, techniques offensives et internes du parseur.",
    postsCount: "{n} articles",
    tagsOnPost: "Tags",
    labels: {
      security: "Audit Security",
      logon: "Logon",
      process: "Processus",
      account: "Compte",
      privileges: "Privilèges",
      "object-access": "Accès aux objets",
      kerberos: "Kerberos",
      "anti-forensics": "Anti-forensique",
      attack: "Techniques offensives",
      sysmon: "Sysmon",
      powershell: "PowerShell",
      system: "Canal System",
      service: "Service",
      persistence: "Persistance",
      format: "Format EVTX",
      fundamentals: "Fondamentaux",
      collection: "Collecte",
      tooling: "Outillage",
      navigation: "Navigation",
    },
  },
  toc: {
    heading: "Sur cette page",
  },
};
