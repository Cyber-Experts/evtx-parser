/**
 * Bundle the SigmaHQ Windows rules into lib/sigma/sigmahq-rules.json.
 *
 * Usage:
 *   npm run sigma:update                         # pinned release below
 *   npm run sigma:update -- --release r2026-07-01
 *   npm run sigma:update -- --from ./sigma-src   # already-extracted checkout
 *
 * The rules are fetched here, at build time, and committed: the site never
 * fetches rules at runtime (the CSP forbids it) and nothing leaves the
 * browser. Every rule keeps its title, id, author, references and SigmaHQ
 * path, as the Detection Rule License 1.1 requires (see LICENSE-SIGMA).
 *
 * Only `rules/windows/**` is imported (the SigmaHQ "deprecated/" and
 * "unsupported/" trees are not). Rules whose status is deprecated or
 * unsupported, whose logsource has no EVTX channel (ETW-only categories),
 * or which the engine can't evaluate are left out and listed in
 * lib/sigma/sigmahq-skipped.json with the reason.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { parseSigmaYaml } from "../lib/sigma/parse";
import type { SigmaBundle, SigmaRule, SigmaSkipped } from "../lib/sigma/types";

/** Pinned SigmaHQ release (https://github.com/SigmaHQ/sigma/releases). */
const PINNED_RELEASE = "r2026-07-01";
const RULE_ROOTS = ["rules/windows"];

const ROOT = process.cwd();
const OUT_RULES = path.join(ROOT, "lib/sigma/sigmahq-rules.json");
const OUT_SKIPPED = path.join(ROOT, "lib/sigma/sigmahq-skipped.json");
// Small release/counts file the UI and pages can import without the rules.
const OUT_META = path.join(ROOT, "lib/sigma/sigmahq-meta.json");

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function download(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url} → ${res.status}`);
  fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
}

async function resolveCommit(release: string): Promise<string | undefined> {
  try {
    const res = await fetch(`https://api.github.com/repos/SigmaHQ/sigma/commits/${release}`, {
      headers: { accept: "application/vnd.github.sha" },
    });
    if (!res.ok) return undefined;
    const sha = (await res.text()).trim();
    return /^[0-9a-f]{40}$/.test(sha) ? sha : undefined;
  } catch {
    return undefined;
  }
}

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (/\.ya?ml$/i.test(e.name)) out.push(full);
  }
  return out;
}

/** Drop undefined keys so the committed JSON stays compact and stable. */
function compact(rule: SigmaRule): Omit<SigmaRule, "source"> {
  const { source: _source, ...rest } = rule;
  void _source;
  return Object.fromEntries(
    Object.entries(rest).filter(([, v]) => v !== undefined),
  ) as Omit<SigmaRule, "source">;
}

async function main() {
  const release = arg("release") ?? process.env.SIGMA_RELEASE ?? PINNED_RELEASE;
  let src = arg("from");
  let commit: string | undefined;

  if (!src) {
    const cache = process.env.SIGMA_CACHE_DIR ?? fs.mkdtempSync(path.join(os.tmpdir(), "sigma-"));
    fs.mkdirSync(cache, { recursive: true });
    const tarball = path.join(cache, `sigma-${release}.tar.gz`);
    const url = `https://github.com/SigmaHQ/sigma/archive/refs/tags/${release}.tar.gz`;
    console.log(`Downloading ${url}`);
    await download(url, tarball);
    const extractTo = path.join(cache, `extract-${release}`);
    fs.rmSync(extractTo, { recursive: true, force: true });
    fs.mkdirSync(extractTo, { recursive: true });
    execFileSync("tar", ["-xzf", tarball, "-C", extractTo]);
    const [top] = fs.readdirSync(extractTo);
    src = path.join(extractTo, top);
    commit = await resolveCommit(release);
  }

  const skipped: (SigmaSkipped & { kind: "status" | "unsupported" })[] = [];
  const rules: SigmaRule[] = [];
  const seen = new Set<string>();
  let files = 0;

  for (const rootRel of RULE_ROOTS) {
    for (const file of walk(path.join(src, rootRel))) {
      files++;
      const rel = path.relative(src, file).split(path.sep).join("/");
      const text = fs.readFileSync(file, "utf8");
      const status = /^status:\s*([\w-]+)/m.exec(text)?.[1]?.toLowerCase();
      const title = /^title:\s*(.+)$/m.exec(text)?.[1]?.trim() ?? rel;
      const id = /^id:\s*([\w-]+)/m.exec(text)?.[1] ?? rel;
      if (status === "deprecated" || status === "unsupported") {
        skipped.push({ id, title, path: rel, reason: `status: ${status}`, kind: "status" });
        continue;
      }
      const { rules: parsed, errors } = parseSigmaYaml(text, {
        source: "sigmahq",
        idPrefix: rel,
        path: rel,
      });
      for (const e of errors) skipped.push({ ...e, path: rel, kind: "unsupported" });
      for (const r of parsed) {
        if (seen.has(r.id)) {
          skipped.push({ id: r.id, title: r.title, path: rel, reason: "duplicate rule id", kind: "unsupported" });
          continue;
        }
        seen.add(r.id);
        rules.push(r);
      }
    }
  }

  // SigmaHQ's own deprecated/ and unsupported/ trees are never imported;
  // count their Windows rules so the report shows what was left out.
  const countTree = (rel: string) => {
    const dir = path.join(src, rel);
    return fs.existsSync(dir) ? walk(dir).length : 0;
  };
  const deprecated = skipped.filter((s) => s.kind === "status").length + countTree("deprecated/windows");
  const sigmaUnsupported = countTree("unsupported/windows");
  const unsupported = skipped.filter((s) => s.kind === "unsupported").length;
  const bundle: SigmaBundle = {
    release,
    ...(commit ? { commit } : {}),
    source: "https://github.com/SigmaHQ/sigma",
    license: "Detection Rule License (DRL) 1.1 — https://github.com/SigmaHQ/Detection-Rule-License",
    generated: new Date().toISOString().slice(0, 10),
    counts: { files, bundled: rules.length, deprecated, sigmaUnsupported, unsupported },
    rules: rules.map(compact) as SigmaRule[],
  };
  fs.writeFileSync(OUT_RULES, JSON.stringify(bundle) + "\n");
  const { rules: _rules, ...meta } = bundle;
  void _rules;
  fs.writeFileSync(OUT_META, JSON.stringify(meta, null, 2) + "\n");

  // Reasons, grouped, for the README / report.
  const byReason = new Map<string, number>();
  for (const s of skipped) {
    const key = s.reason
      .replace(/"[^"]*"/g, "…")
      .replace(/^[\w-]+: /, "")
      .replace(/\/.*\/: .*/, "(regex)");
    byReason.set(key, (byReason.get(key) ?? 0) + 1);
  }
  fs.writeFileSync(
    OUT_SKIPPED,
    JSON.stringify(
      {
        release,
        counts: bundle.counts,
        skipped: skipped.map(({ kind: _k, ...s }) => {
          void _k;
          return s;
        }),
      },
      null,
      1,
    ) + "\n",
  );

  const size = fs.statSync(OUT_RULES).size;
  console.log(`SigmaHQ ${release}${commit ? ` (${commit.slice(0, 10)})` : ""}`);
  console.log(`  rule files scanned : ${files}`);
  console.log(`  bundled            : ${rules.length}`);
  console.log(`  deprecated (excl.) : ${deprecated}`);
  console.log(`  SigmaHQ unsupported/ (excl.): ${sigmaUnsupported}`);
  console.log(`  not runnable on EVTX: ${unsupported}`);
  for (const [reason, n] of [...byReason].sort((a, b) => b[1] - a[1]))
    console.log(`    ${String(n).padStart(4)}  ${reason}`);
  console.log(`  → ${path.relative(ROOT, OUT_RULES)} (${(size / 1024).toFixed(0)} KB)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
