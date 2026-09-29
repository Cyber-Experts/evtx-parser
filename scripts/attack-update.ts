/**
 * Refresh lib/events/attack.json — the MITRE ATT&CK Enterprise techniques the
 * Event ID encyclopedia may reference (Windows platform, not revoked or
 * deprecated), with their names and tactics.
 *
 * Usage:
 *   npx tsx scripts/attack-update.ts                    # download latest STIX
 *   npx tsx scripts/attack-update.ts --from ./enterprise-attack.json
 *
 * The encyclopedia data (data/events) stores technique IDs only; names and
 * tactics always come from this table, so a renamed or re-parented technique
 * is fixed in one place. Revoked IDs are kept in `revoked` (old → new) so the
 * dataset validator can point at the replacement.
 */
import fs from "node:fs";
import path from "node:path";

const STIX_URL =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
const OUT = path.join(process.cwd(), "lib/events/attack.json");

type Stix = {
  type: string;
  id: string;
  name?: string;
  revoked?: boolean;
  x_mitre_deprecated?: boolean;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_platforms?: string[];
  x_mitre_shortname?: string;
  x_mitre_version?: string;
  kill_chain_phases?: { kill_chain_name: string; phase_name: string }[];
  external_references?: { source_name: string; external_id?: string }[];
  relationship_type?: string;
  source_ref?: string;
  target_ref?: string;
};

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const attackId = (o: Stix) =>
  o.external_references?.find((r) => r.source_name === "mitre-attack")?.external_id;

async function main() {
  const from = arg("from");
  const raw = from
    ? fs.readFileSync(from, "utf8")
    : await fetch(STIX_URL).then((r) => {
        if (!r.ok) throw new Error(`GET ${STIX_URL}: ${r.status}`);
        return r.text();
      });
  const objects = (JSON.parse(raw) as { objects: Stix[] }).objects;
  const collection = objects.find((o) => o.type === "x-mitre-collection");
  const byStixId = new Map(objects.map((o) => [o.id, o]));

  const tactics = objects
    .filter((o) => o.type === "x-mitre-tactic" && !o.revoked && !o.x_mitre_deprecated)
    .map((o) => ({ id: attackId(o) as string, slug: o.x_mitre_shortname as string, name: o.name as string }));

  const live = objects.filter(
    (o) =>
      o.type === "attack-pattern" &&
      !o.revoked &&
      !o.x_mitre_deprecated &&
      (o.x_mitre_platforms ?? []).includes("Windows"),
  );
  const nameOf = new Map(live.map((o) => [attackId(o) as string, o.name as string]));
  const techniques: Record<string, { name: string; tactics: string[] }> = {};
  for (const o of live) {
    const id = attackId(o);
    if (!id) continue;
    const parent = id.includes(".") ? nameOf.get(id.split(".")[0]) : undefined;
    techniques[id] = {
      name: parent ? `${parent}: ${o.name}` : (o.name as string),
      tactics: (o.kill_chain_phases ?? [])
        .filter((k) => k.kill_chain_name === "mitre-attack")
        .map((k) => k.phase_name),
    };
  }

  // Revoked technique → the technique that replaced it ("revoked-by").
  const revoked: Record<string, string> = {};
  for (const rel of objects) {
    if (rel.type !== "relationship" || rel.relationship_type !== "revoked-by") continue;
    const src = rel.source_ref ? byStixId.get(rel.source_ref) : undefined;
    const dst = rel.target_ref ? byStixId.get(rel.target_ref) : undefined;
    if (src?.type !== "attack-pattern" || !dst) continue;
    const a = attackId(src);
    const b = attackId(dst);
    if (a && b) revoked[a] = b;
  }

  const sorted = Object.fromEntries(
    Object.entries(techniques).sort(([a], [b]) => a.localeCompare(b, "en", { numeric: true })),
  );
  const out = {
    version: collection?.x_mitre_version ?? "unknown",
    source: "https://github.com/mitre-attack/attack-stix-data",
    generated: new Date().toISOString().slice(0, 10),
    tactics,
    techniques: sorted,
    revoked: Object.fromEntries(Object.entries(revoked).sort(([a], [b]) => a.localeCompare(b))),
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, `${JSON.stringify(out, null, 1)}\n`);
  console.log(
    `ATT&CK v${out.version}: ${Object.keys(sorted).length} techniques, ${tactics.length} tactics, ${Object.keys(revoked).length} revoked → ${path.relative(process.cwd(), OUT)}`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
