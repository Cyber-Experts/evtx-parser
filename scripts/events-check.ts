/**
 * Validate the Event ID encyclopedia (data/events) and regenerate the small
 * client manifest (lib/events/manifest.json) the viewer uses for its
 * "What is event N?" links.
 *
 * Usage:
 *   npm run events:check              # validate + rewrite the manifest
 *   npm run events:check -- --verify  # validate + fail if the manifest is stale
 *   npm run events:check -- security  # only report errors for one channel
 *   npm run events:check -- --allow-missing-related   # while drafting
 */
import fs from "node:fs";
import path from "node:path";

import { readEventDataset } from "../lib/events/load";
import { buildManifest, MANIFEST_PATH } from "../lib/events/manifest-build";

const args = process.argv.slice(2);
const verify = args.includes("--verify");
const only = args.filter((a) => !a.startsWith("--"));
const allowMissingRelated = args.includes("--allow-missing-related");

const ds = readEventDataset();
const errors = (
  only.length
    ? ds.errors.filter((e) => only.some((o) => e.startsWith(`${o}/`) || e.startsWith(`${o}:`)))
    : ds.errors
).filter((e) => !(allowMissingRelated && e.endsWith("has no entry")));

const byChannel = new Map<string, number>();
for (const e of ds.entries) byChannel.set(e.channel, (byChannel.get(e.channel) ?? 0) + 1);
let translated = 0;
for (const m of ds.translations.values()) translated += m.size;
console.log(
  `${ds.entries.length} entries, ${ds.translations.size} translated events (${translated} translation files)`,
);
console.log(
  [...byChannel].map(([c, n]) => `  ${c}: ${n}`).join("\n"),
);

if (errors.length) {
  console.error(`\n${errors.length} error(s):\n  ${errors.join("\n  ")}`);
  process.exit(1);
}

if (allowMissingRelated || only.length) process.exit(0);

const out = `${JSON.stringify(buildManifest(ds), null, 1)}\n`;
const file = path.join(process.cwd(), MANIFEST_PATH);
const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
if (verify) {
  if (current !== out) {
    console.error(`\n${MANIFEST_PATH} is stale — run \`npm run events:check\`.`);
    process.exit(1);
  }
  console.log(`\n${MANIFEST_PATH} is up to date.`);
} else if (current !== out) {
  fs.writeFileSync(file, out);
  console.log(`\nWrote ${MANIFEST_PATH}.`);
}
