// Event ID encyclopedia — data model. One YAML file per event under
// data/events/<channel-slug>/<id>.yaml (English source), plus optional
// translations <id>.<locale>.yaml carrying only the prose (see
// EventTranslation). Validated by lib/events/schema.ts.

export const EVENT_CATEGORIES = [
  "logon",
  "account",
  "group",
  "kerberos",
  "ntlm",
  "process",
  "service",
  "scheduled-task",
  "object-access",
  "network-share",
  "policy",
  "log-integrity",
  "system",
  "powershell",
  "remote-access",
  "wmi",
  "network",
  "registry",
  "file",
  "device",
  "antimalware",
  "application-control",
  "directory",
  "software",
] as const;
export type EventCategory = (typeof EVENT_CATEGORIES)[number];

/** Locales that may carry translated event prose. */
export const EVENT_TRANSLATION_LOCALES = ["fr", "es", "de"] as const;

export type FieldValue = { value: string; meaning: string };

export type EventField = {
  name: string;
  description: string;
  values?: FieldValue[];
};

export type Reference = { title: string; url: string };

/** English source entry (data/events/<channel>/<id>.yaml). */
export type EventEntry = {
  id: number;
  /** Channel slug (folder name) — see lib/events/channels.ts. */
  channel: string;
  /** Exact <Channel> name when it differs from the channel's canonical one. */
  channelName?: string;
  provider: string;
  /** Event message title, e.g. "An account was successfully logged on". */
  title: string;
  /** ≤ 40 chars, used in page titles and lists: "Successful logon". */
  shortTitle: string;
  category: EventCategory;
  /** Plain text, 50–160 chars: the meta description and list blurb. */
  summary: string;
  /** Paragraphs (blank-line separated), inline `code` and **bold** only. */
  description: string;
  logging: {
    /** Logged on a default Windows install (no policy/config change). */
    enabledByDefault: boolean;
    /** What must be enabled (audit subcategory, GPO path, config). */
    requirement: string;
    notes?: string;
  };
  fields: EventField[];
  benign: string[];
  attacker: string[];
  investigation: string[];
  /** "channel/id" keys of other entries. */
  related: string[];
  /** ATT&CK technique IDs (names/tactics come from lib/events/attack.json). */
  attack: string[];
  references: Reference[];
};

/** Prose overrides for one locale (data/events/<channel>/<id>.<locale>.yaml). */
export type EventTranslation = {
  title: string;
  shortTitle: string;
  summary: string;
  description: string;
  logging: { requirement: string; notes?: string };
  /** Matched to the English fields by `name`; values matched by `value`. */
  fields: { name: string; description: string; values?: FieldValue[] }[];
  benign: string[];
  attacker: string[];
  investigation: string[];
};
