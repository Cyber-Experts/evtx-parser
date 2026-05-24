// Plain-text glossary entries, used by both the rendered glossary page and
// the rehype glossary-linker plugin that rewrites the first occurrence of
// each term in a blog post to a glossary anchor. Keeping the data separate
// from the JSX in app/[locale]/glossary/page.tsx avoids pulling React into
// the markdown pipeline.

export type GlossaryEntry = {
  id: string;
  term: string;
  // Plain-text definition used by JSON-LD (DefinedTerm.description) and as
  // an alt source if we ever want a non-JSX rendering.
  plain: string;
};

function slugify(term: string): string {
  return term
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

const RAW: { term: string; plain: string }[] = [
  {
    term: "EVTX",
    plain:
      "The binary Windows Event Log format introduced with Windows Vista (2007), replacing the older flat-record .evt format. Each .evtx file is a sequence of 64 KB chunks; per-record values are bound at parse time to XML templates stored once per chunk.",
  },
  {
    term: "Channel",
    plain:
      "A logical event stream. Defaults: Application, System, Security, Setup, ForwardedEvents. Per-product channels live under Microsoft-Windows-* (e.g. Microsoft-Windows-Sysmon/Operational). On disk each channel is one .evtx file under C:\\Windows\\System32\\winevt\\Logs\\.",
  },
  {
    term: "Provider",
    plain:
      "The component that emits records into a channel — identified by name (e.g. Microsoft-Windows-Security-Auditing) and a GUID. The same numeric Event ID can mean very different things across providers (Sysmon 1 ≠ Security 1), so provider+ID is the real key.",
  },
  {
    term: "Chunk",
    plain:
      "A 64 KB block inside an .evtx file. Each chunk has its own header (ElfChnk magic), a CRC-checked table of XML templates, and a stream of records that reference those templates by ID. Records cannot cross chunk boundaries.",
  },
  {
    term: "Template",
    plain:
      "A skeleton XML document with substitution placeholders. The chunk's template table is parsed once; each record contributes only the values that fill the placeholders. This is how .evtx achieves its compression — the constant text is stored once per chunk.",
  },
  {
    term: "BinXML",
    plain:
      "Binary-encoded XML — the on-disk serialisation used for both templates and substitution values. Tokens (opening tag, attribute, value) are length-prefixed bytes rather than ASCII tags, which is why a hex view of an .evtx looks like nothing you can read.",
  },
  {
    term: "EventData",
    plain:
      "The XML child element in each rendered record that holds the provider-specific parameters: TargetUserName on a 4624, ImagePath on a 7045, CommandLine on a Sysmon 1. The forensic signal almost always lives here — not in the numeric Event ID.",
  },
  {
    term: "System block",
    plain:
      "The XML sibling of EventData that carries generic metadata: provider name/GUID, channel, Event ID, level, timestamp (TimeCreated SystemTime), the computer name, and the record's RecordID and EventRecordID.",
  },
  {
    term: "Level",
    plain:
      "Numeric severity: 1 Critical, 2 Error, 3 Warning, 4 Information, 5 Verbose. Microsoft maps known IDs to fixed levels (Security 4625 sits at Information), so severity alone is not a triage signal.",
  },
  {
    term: "LogonType",
    plain:
      "EventData field on logon records (4624/4625) identifying how the session was established. Common values: 2 Interactive (console), 3 Network (SMB/RPC), 5 Service, 7 Unlock, 9 NewCredentials (runas /netonly), 10 RemoteInteractive (RDP), 11 CachedInteractive.",
  },
  {
    term: "SID",
    plain:
      "Security Identifier — the unique identifier Windows assigns to every security principal (user, group, computer). Built-in SIDs are well-known: S-1-5-18 is LocalSystem, S-1-5-19 is LocalService, S-1-5-20 is NetworkService. Domain SIDs end in a Relative ID (RID); -500 is the local Administrator, -501 is Guest.",
  },
  {
    term: "LogonId",
    plain:
      "A 64-bit identifier Windows assigns to each logon session. Lets you link records across channels (4624 / 4634 / 4647 / Sysmon 1) to the same session even when SIDs are too generic to disambiguate. SubjectLogonId on 1102 pivots to the 4624 that created the privileged session.",
  },
  {
    term: "RecordID",
    plain:
      "Monotonically-increasing per-channel record number, assigned by the EventLog service at write time. Gaps suggest deletion or clearing. Don't confuse with the EventID (which identifies what kind of event) or with the Sysmon EventRecordID.",
  },
  {
    term: "WEF",
    plain:
      "Windows Event Forwarding — the built-in mechanism for shipping subscribed channels to a central collector over WinRM. When WEF is in place, even a cleared local Security log may survive on the collector under the ForwardedEvents channel.",
  },
  {
    term: "Sysmon",
    plain:
      "System Monitor — a free Sysinternals/Microsoft tool that augments the event log with telemetry the base OS doesn't capture in usable form: full process command lines (event 1), network connections (3), DLL loads (7), file creates (11), registry value sets (13), DNS queries (22). Requires a config file; SwiftOnSecurity's and Olaf Hartong's are the canonical references.",
  },
  {
    term: "ScriptBlock logging",
    plain:
      "PowerShell feature that records the full text of every script that runs — interactive commands, scripts from disk, and bodies reflected into memory by Invoke-Expression. The records land under event 4104 on the PowerShell/Operational channel and capture content after decoding/reflection, surviving most obfuscation.",
  },
];

export const GLOSSARY: GlossaryEntry[] = RAW.map((t) => ({
  id: slugify(t.term),
  term: t.term,
  plain: t.plain,
}));
