import type { Dict } from "./types";

export const en: Dict = {
  meta: {
    title: "EVTX parser — browser-side Windows Event Log forensics",
    description:
      "Free in-browser .evtx parser for Windows Event Log forensics. No upload, no install — drop a file and triage logons, services and PowerShell in seconds.",
    siteName: "EVTX parser",
  },
  home: {
    heading: "EVTX parser",
    headline: "EVTX parser — Windows Event Log viewer in your browser",
    intro:
      "Drop a Windows .evtx event log. Parsing runs entirely in your browser via WebAssembly — nothing is uploaded.",
    featuredHeading: "Featured guides",
    dropArea: "Drop .evtx here or click to choose",
    privacyNote: "Files stay on your device. Pure client-side parsing.",
    statusReading: "Reading {name}…",
    statusParsing: "Parsing event log…",
    eventsLabel: "events",
    filterPlaceholder: "Filter by Event ID, provider, channel, computer…",
    clearFilter: "Clear",
    noMatches: "No events match the current filter.",
    topIds: "Top IDs",
    exportCsv: "Export CSV",
    exportJson: "Export JSON",
    includeXml: "Raw XML column",
    exporting: "Exporting…",
    clearTime: "Clear time range",
  },
  table: {
    record: "Record #",
    time: "Time (UTC)",
    level: "Level",
    eventId: "Event ID",
    name: "Name",
    summary: "Summary",
    provider: "Provider",
    channel: "Channel",
    computer: "Computer",
    viewDetails: "Details",
    closeDetails: "Close",
    eventData: "Event data",
    noEventData: "No EventData fields on this record.",
    showRawXml: "Show raw XML",
    hideRawXml: "Hide raw XML",
    prev: "prev",
    next: "next",
  },
  levels: {
    critical: "Critical",
    error: "Error",
    warning: "Warning",
    info: "Information",
    verbose: "Verbose",
    unknown: "—",
  },
  faq: {
    heading: "Event log FAQ",
    items: [
      {
        q: "What is an EVTX file?",
        a: "EVTX is the binary Windows Event Log format introduced with Windows Vista. Each .evtx file is a sequence of 64 KB chunks; every chunk holds an XML template table plus a stream of records that reference those templates. Parsing rebuilds the full XML for each event.",
      },
      {
        q: "Where do I find .evtx files on Windows?",
        a: "Live logs live under C:\\Windows\\System32\\winevt\\Logs. The big three for forensics are Security.evtx (logons, privilege use), System.evtx (drivers, services), and Application.evtx (app errors). Sysmon and PowerShell channels are typically the most valuable for incident response.",
      },
      {
        q: "Does this tool upload my .evtx anywhere?",
        a: "No. Parsing happens in a Web Worker using a Rust EVTX parser compiled to WebAssembly. The file is read into your browser's memory and never transmitted. Disconnect your network if you want to verify.",
      },
      {
        q: "What does the Level column mean?",
        a: "EVTX levels are numeric: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose. Microsoft maps a few well-known IDs (e.g. Security 4625 = failed logon at Information level) — severity alone is not a triage signal.",
      },
      {
        q: "Can it parse very large .evtx files?",
        a: "Parsing runs in a Web Worker thread. Memory scales with file size; a few hundred MB is comfortable in modern browsers. Larger collections can be exported with evtx_dump first and re-imported in slices.",
      },
      {
        q: "How do I read .evtx files without Windows?",
        a: "On Linux or macOS you have three practical options: evtx_dump (the Rust CLI from omerbenamram/evtx, MIT-licensed), python-evtx (libyal), or this site — which is the same Rust parser compiled to WebAssembly. All three rebuild the event XML offline; no Microsoft tooling needed.",
      },
      {
        q: "What is the difference between .evt and .evtx?",
        a: ".evt is the legacy binary log format used by Windows 2000/XP/2003 — fixed-size, flat record layout. .evtx replaced it in Windows Vista / Server 2008 with a chunked structure, XML template compression, and per-record provider GUIDs. .evt files are not readable by this parser; convert them with wevtutil first.",
      },
      {
        q: "Can I open .evtx in Notepad?",
        a: "No — .evtx is a binary format with chunked records and BinXML-compressed templates. Notepad will show mostly garbled text. Use Event Viewer (built into Windows), wevtutil, evtx_dump, or this in-browser parser.",
      },
      {
        q: "How do I parse .evtx in PowerShell?",
        a: "Use Get-WinEvent -Path 'C:\\path\\to\\Security.evtx' on Windows; it accepts -FilterHashtable for ID/level/time filtering and -MaxEvents for sampling. For one-off triage on non-Windows hosts, evtx_dump --json (CLI) or this site is faster — Get-WinEvent needs a Windows runtime and the matching provider manifest to fully render messages.",
      },
      {
        q: "Where are Windows event logs stored?",
        a: "Active logs live in C:\\Windows\\System32\\winevt\\Logs as .evtx files; default channels are Application, System, Security, Setup and ForwardedEvents, plus per-application channels under Microsoft-Windows-* (e.g. Sysmon, PowerShell/Operational, TaskScheduler). Archived logs can be anywhere — KAPE and FTK Imager both pull the live directory by default.",
      },
      {
        q: "Which Event IDs should I monitor for security?",
        a: "The MITRE-aligned shortlist: 4624 (logon) and 4625 (failed logon) in Security, 4688 (process creation, with command-line auditing on), 4768/4769 (Kerberos TGT/TGS — kerberoasting), 4672 (special privileges), 4720/4726 (account created/deleted), 1102 (audit log cleared), 7045/7036 (service installation/state), and Sysmon 1/3/7/11 for process, network, image-load and file-create.",
      },
    ],
  },
  footer: {
    blog: "Blog",
    builtWith:
      "Built with WebAssembly and the omerbenamram/evtx Rust crate. 100% client-side — your files never leave your browser.",
  },
  notFound: {
    title: "404 — page not found",
    heading: "Page not found",
    description:
      "That URL doesn't exist on this site. It may have moved, or you might have followed a stale link.",
    backHome: "← Back to home",
  },
  blog: {
    indexTitle: "DFIR blog: Windows Event Log forensics & .evtx parsing",
    indexIntro:
      "Short notes on the Windows Event Log binary format, common forensic event IDs, and triage workflows.",
    readMore: "Read more",
    backToBlog: "← Back to blog",
    publishedOn: "Published",
    updatedOn: "Updated",
    readingTime: "{n} min read",
    prevPost: "← Previous post",
    nextPost: "Next post →",
    relatedHeading: "Related posts",
    resourcesHeading: "External resources",
    byLine: "By",
  },
  eventIds: {
    title: "Windows Event ID reference",
    intro:
      "A curated index of the Windows Event IDs that matter on a forensic case — grouped by channel, with the EventData fields worth reading first. Click any covered ID for a deeper guide; uncovered ones link to Microsoft Learn.",
    description:
      "Reference index of Windows Event IDs that matter for DFIR: Security 4624/4625/1102, System 7045/7036, Sysmon 1/3/7/11, PowerShell 4104, TaskScheduler, Kerberos and more — with links to deep-dive guides.",
    columnId: "Event ID",
    columnName: "Name",
    columnNotes: "Notes",
  },
  glossary: {
    title: "Windows Event Log glossary",
    intro:
      "The terms that appear in .evtx records and DFIR write-ups, explained in a sentence or two. If you can read these, you can read the records.",
    description:
      "Plain-language definitions for the Windows Event Log terms an analyst hits daily: LogonType, BinXML, channel, provider, chunk, template, SID, EventData, RecordID and more.",
  },
  tools: {
    title: "EVTX tools compared: KAPE, FTK Imager, wevtutil, evtx_dump",
    intro:
      "A side-by-side comparison of the tools an analyst reaches for when working with Windows Event Logs — what each one is actually good at, what it costs, and where it falls down.",
    description:
      "Compare KAPE, FTK Imager, wevtutil, evtx_dump, python-evtx, RawCopy and EVTX parser — by platform, use case, license and trade-offs. Pick the right tool for collection, parsing, or in-browser triage.",
    columnTool: "Tool",
    columnPlatform: "Platform",
    columnUseCase: "Primary use case",
    columnLicense: "License",
  },
  breadcrumb: {
    home: "Home",
    label: "Breadcrumb",
  },
  eventId: {
    title: "Event ID {id}: {name} ({channel})",
    intro:
      "What this Event ID actually records on disk, the EventData fields worth reading first, and where it sits in a DFIR triage workflow.",
    description:
      "Windows Event ID {id} ({name}) on the {channel} channel: meaning, EventData fields, common attacker tradecraft, and related Event IDs to pivot to.",
    channelLabel: "Channel",
    providerLabel: "Provider",
    notesLabel: "Triage notes",
    inDepthHeading: "Deep-dive guide",
    inDepthCta: "Read the full write-up",
    microsoftLearnHeading: "Microsoft Learn",
    microsoftLearnCta: "Open the official reference",
    relatedHeading: "Related Event IDs",
    notCoveredYet:
      "This Event ID is in the reference index but doesn't yet have a deep-dive write-up. Microsoft Learn covers the field-level details.",
    notFoundTitle: "Unknown Event ID",
    notFoundDescription:
      "We don't track this Event ID in the reference index yet.",
  },
  tags: {
    indexTitle: "Topics — every tag on the blog",
    indexIntro:
      "Every topic covered on the blog, with the number of posts under each one. Use this as a second navigation layer alongside the Event ID reference.",
    indexDescription:
      "Browse EVTX parser blog topics: security auditing, Sysmon, PowerShell, Kerberos, services, EVTX format internals, and forensic collection.",
    tagTitleTemplate: "Posts tagged \"{tag}\"",
    tagIntroTemplate:
      "Every post on this blog tagged \"{tag}\", newest first.",
    tagDescriptionTemplate:
      "Windows Event Log forensics posts tagged \"{tag}\" — DFIR notes, attacker tradecraft, and parser internals.",
    postsCount: "{n} posts",
    tagsOnPost: "Tags",
    labels: {
      security: "Security auditing",
      logon: "Logon",
      process: "Process",
      account: "Account",
      privileges: "Privileges",
      "object-access": "Object access",
      kerberos: "Kerberos",
      "anti-forensics": "Anti-forensics",
      attack: "Attacker tradecraft",
      sysmon: "Sysmon",
      powershell: "PowerShell",
      system: "System channel",
      service: "Service",
      persistence: "Persistence",
      format: "EVTX format",
      fundamentals: "Fundamentals",
      collection: "Collection",
      tooling: "Tooling",
      navigation: "Navigation",
    },
  },
  toc: {
    heading: "On this page",
  },
};
