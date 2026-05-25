/**
 * One-shot glossary extractor. Reads lib/glossary-data.ts (single English
 * source) and emits one markdown file per term under content/glossary/{loc}/
 * for every supported locale.
 *
 * Locale parity is intentional: the old site rendered the English bodies
 * regardless of locale (the per-locale `buildBody(locale)` only varied
 * internal links, not prose). This script reproduces that behavior and
 * gives the user a starting point for per-locale translations later —
 * each .md file is self-contained so translating one doesn't touch others.
 */
import fs from "node:fs";
import path from "node:path";
import { GLOSSARY } from "../lib/glossary-data";
import { LOCALES } from "../lib/i18n";

const ROOT = path.join(process.cwd(), "content", "glossary");
const DATE = "2026-01-01";

function escapeYaml(s: string): string {
  return s.replace(/"/g, '\\"');
}

function shortDescription(plain: string): string {
  const sentence = plain.split(/(?<=\.)\s/)[0] ?? plain;
  return sentence.length > 200 ? sentence.slice(0, 197) + "…" : sentence;
}

function fileContent(term: string, plain: string): string {
  const description = shortDescription(plain);
  return `---
title: "${escapeYaml(term)}"
description: "${escapeYaml(description)}"
date: "${DATE}"
---

${plain}
`;
}

let written = 0;
for (const locale of LOCALES) {
  const dir = path.join(ROOT, locale);
  fs.mkdirSync(dir, { recursive: true });
  for (const entry of GLOSSARY) {
    const target = path.join(dir, `${entry.id}.md`);
    fs.writeFileSync(target, fileContent(entry.term, entry.plain));
    written++;
  }
}

console.log(`Wrote ${written} files across ${LOCALES.length} locales.`);
