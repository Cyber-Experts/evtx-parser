/**
 * Content lint — catches the quality bugs that quietly kneecap SEO.
 *
 * Usage:
 *   npm run lint:content                  # all content
 *   npm run lint:content content/blog/en  # narrow scope
 *   npm run lint:content path/to/post.md  # single file
 *
 * Exit code 1 if any error is found. Warnings don't fail the run.
 *
 * Designed to run as a pre-commit hook via husky + lint-staged on staged
 * markdown files only — see .husky/pre-commit + package.json `lint-staged`.
 */
import fs from "node:fs";
import path from "node:path";
import matter from "gray-matter";

const ROOT = process.cwd();
const REQUIRED_FRONTMATTER = ["title", "description", "date"] as const;

/**
 * Minimum word count per collection (path prefix). Glossary entries are short
 * by design — definitions, not articles — so they get a lower floor.
 */
const MIN_WORD_COUNT: { match: RegExp; minimum: number; label: string }[] = [
  { match: /\/content\/glossary\//, minimum: 40, label: "glossary" },
  { match: /\/content\/blog\//, minimum: 300, label: "blog" },
];
const DEFAULT_MIN_WORDS = 300;

type Severity = "error" | "warn";
type Finding = { file: string; line?: number; severity: Severity; rule: string; message: string };

function walk(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && /\.mdx?$/.test(entry.name)) out.push(full);
  }
  return out;
}

function collectTargets(args: string[]): string[] {
  if (args.length === 0) {
    return walk(path.join(ROOT, "content"));
  }
  const out: string[] = [];
  for (const arg of args) {
    const full = path.isAbsolute(arg) ? arg : path.join(ROOT, arg);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) walk(full, out);
    else if (/\.mdx?$/.test(full)) out.push(full);
  }
  return out;
}

function rel(file: string): string {
  return path.relative(ROOT, file);
}

const IMAGE_RE = /!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
const HTML_IMG_RE = /<img\b([^>]*)>/gi;
const FENCE_RE = /^\s*```/;

function* iterImageMatches(content: string): Generator<{
  line: number;
  raw: string;
  alt: string;
  src: string;
}> {
  const lines = content.split(/\r?\n/);
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (FENCE_RE.test(line)) inFence = !inFence;
    if (inFence) continue;
    for (const m of line.matchAll(IMAGE_RE)) {
      yield { line: i + 1, raw: m[0], alt: m[1] ?? "", src: m[2] ?? "" };
    }
    for (const m of line.matchAll(HTML_IMG_RE)) {
      const attrs = m[1] ?? "";
      const altMatch = attrs.match(/\balt=("([^"]*)"|'([^']*)')/);
      const srcMatch = attrs.match(/\bsrc=("([^"]*)"|'([^']*)')/);
      yield {
        line: i + 1,
        raw: m[0],
        alt: altMatch ? (altMatch[2] ?? altMatch[3] ?? "") : "",
        src: srcMatch ? (srcMatch[2] ?? srcMatch[3] ?? "") : "",
      };
    }
  }
}

function* iterHeadings(content: string): Generator<{ line: number; depth: number; text: string }> {
  const lines = content.split(/\r?\n/);
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (FENCE_RE.test(line)) inFence = !inFence;
    if (inFence) continue;
    const match = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (match) {
      yield { line: i + 1, depth: match[1]!.length, text: match[2]!.trim() };
    }
  }
}

function wordCount(content: string): number {
  return content
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`]*`/g, " ")
    .replace(/[#*_>\[\]()!\\-]+/g, " ")
    .split(/\s+/)
    .filter(Boolean).length;
}

function lintFaq(fm: Record<string, unknown>, findings: Finding[], file: string) {
  const faq = fm.faq;
  if (faq === undefined) return;
  if (!Array.isArray(faq)) {
    findings.push({
      file,
      severity: "error",
      rule: "faq-shape",
      message: "frontmatter.faq must be an array",
    });
    return;
  }
  faq.forEach((item, i) => {
    if (!item || typeof item !== "object") {
      findings.push({
        file,
        severity: "error",
        rule: "faq-shape",
        message: `frontmatter.faq[${i}] must be an object with question + answer`,
      });
      return;
    }
    const it = item as Record<string, unknown>;
    if (typeof it.question !== "string" || !it.question.trim()) {
      findings.push({
        file,
        severity: "error",
        rule: "faq-shape",
        message: `frontmatter.faq[${i}].question is required (string)`,
      });
    }
    if (typeof it.answer !== "string" || !it.answer.trim()) {
      findings.push({
        file,
        severity: "error",
        rule: "faq-shape",
        message: `frontmatter.faq[${i}].answer is required (string)`,
      });
    }
  });
}

function lintHowTo(fm: Record<string, unknown>, findings: Finding[], file: string) {
  const howto = fm.howto;
  if (howto === undefined) return;
  if (!howto || typeof howto !== "object" || Array.isArray(howto)) {
    findings.push({
      file,
      severity: "error",
      rule: "howto-shape",
      message: "frontmatter.howto must be an object",
    });
    return;
  }
  const data = howto as Record<string, unknown>;
  const steps = data.steps;
  if (!Array.isArray(steps) || steps.length === 0) {
    findings.push({
      file,
      severity: "error",
      rule: "howto-shape",
      message: "frontmatter.howto.steps must be a non-empty array",
    });
    return;
  }
  steps.forEach((step, i) => {
    if (!step || typeof step !== "object") {
      findings.push({
        file,
        severity: "error",
        rule: "howto-shape",
        message: `frontmatter.howto.steps[${i}] must be an object with name + text`,
      });
      return;
    }
    const s = step as Record<string, unknown>;
    if (typeof s.name !== "string" || !s.name.trim()) {
      findings.push({
        file,
        severity: "error",
        rule: "howto-shape",
        message: `frontmatter.howto.steps[${i}].name is required`,
      });
    }
    if (typeof s.text !== "string" || !s.text.trim()) {
      findings.push({
        file,
        severity: "error",
        rule: "howto-shape",
        message: `frontmatter.howto.steps[${i}].text is required`,
      });
    }
  });
  const cost = data.estimatedCost;
  if (cost !== undefined) {
    if (!cost || typeof cost !== "object" || Array.isArray(cost)) {
      findings.push({
        file,
        severity: "error",
        rule: "howto-shape",
        message: "frontmatter.howto.estimatedCost must be { currency, value }",
      });
    } else {
      const c = cost as Record<string, unknown>;
      if (typeof c.currency !== "string" || c.value === undefined) {
        findings.push({
          file,
          severity: "error",
          rule: "howto-shape",
          message: "frontmatter.howto.estimatedCost requires currency + value",
        });
      }
    }
  }
}

function lintFile(file: string): Finding[] {
  const findings: Finding[] = [];
  const raw = fs.readFileSync(file, "utf8");
  let parsed: { data: Record<string, unknown>; content: string };
  try {
    parsed = matter(raw);
  } catch (err) {
    findings.push({
      file,
      severity: "error",
      rule: "frontmatter-parse",
      message: `Failed to parse frontmatter: ${(err as Error).message}`,
    });
    return findings;
  }
  const { data: fm, content } = parsed;

  // 1. Required frontmatter fields.
  for (const key of REQUIRED_FRONTMATTER) {
    const value = fm[key];
    if (typeof value !== "string" || !value.trim()) {
      findings.push({
        file,
        severity: "error",
        rule: "required-frontmatter",
        message: `frontmatter.${key} is required (string)`,
      });
    }
  }

  // 2. Description length sanity (Google truncates ~155 chars).
  if (typeof fm.description === "string" && fm.description.length > 200) {
    findings.push({
      file,
      severity: "warn",
      rule: "description-length",
      message: `frontmatter.description is ${fm.description.length} chars; Google truncates around 155–160`,
    });
  }

  // 3. Images need alt text (Google + a11y) and a src.
  for (const img of iterImageMatches(content)) {
    if (!img.src) {
      findings.push({
        file,
        line: img.line,
        severity: "error",
        rule: "image-src",
        message: `image is missing src: ${img.raw}`,
      });
    }
    const alt = img.alt.trim();
    if (!alt) {
      findings.push({
        file,
        line: img.line,
        severity: "error",
        rule: "image-alt-missing",
        message: `image has no alt text: ${img.raw}`,
      });
    } else if (/^(image|picture|photo|img|untitled)$/i.test(alt)) {
      findings.push({
        file,
        line: img.line,
        severity: "warn",
        rule: "image-alt-junk",
        message: `image alt looks placeholder ("${alt}"); describe the image instead`,
      });
    }
  }

  // 4. Heading hierarchy: no h1 in body, no skipped levels, ≥1 h2.
  const headings = [...iterHeadings(content)];
  const h1 = headings.find((h) => h.depth === 1);
  if (h1) {
    findings.push({
      file,
      line: h1.line,
      severity: "error",
      rule: "no-body-h1",
      message: `body H1 found ("${h1.text}"); frontmatter.title becomes the page H1`,
    });
  }
  if (headings.length > 0) {
    const h2s = headings.filter((h) => h.depth === 2);
    if (h2s.length === 0) {
      findings.push({
        file,
        severity: "warn",
        rule: "no-h2",
        message: "no H2 headings — long posts benefit from sectioning for jump links and TOC",
      });
    }
    let prev = 1; // pretend the title is the h1
    for (const h of headings) {
      if (h.depth > prev + 1) {
        findings.push({
          file,
          line: h.line,
          severity: "error",
          rule: "heading-skip",
          message: `H${h.depth} ("${h.text}") skips a level (previous depth: ${prev})`,
        });
      }
      prev = h.depth;
    }
  }

  // 5. Word count minimum (warn, not error — collection-aware threshold).
  const wc = wordCount(content);
  const rule = MIN_WORD_COUNT.find((r) => r.match.test(file));
  const minimum = rule?.minimum ?? DEFAULT_MIN_WORDS;
  if (wc < minimum) {
    findings.push({
      file,
      severity: "warn",
      rule: "word-count",
      message: `${wc} words; ${rule?.label ?? "default"} threshold is ${minimum}`,
    });
  }

  // 6. FAQ / HowTo frontmatter shape (matches @next-md-blog/core 1.3+).
  lintFaq(fm, findings, file);
  lintHowTo(fm, findings, file);

  return findings;
}

function format(finding: Finding): string {
  const where = finding.line ? `${rel(finding.file)}:${finding.line}` : rel(finding.file);
  const tag = finding.severity === "error" ? "\x1b[31merror\x1b[0m" : "\x1b[33mwarn\x1b[0m";
  return `  ${tag}  ${where}  [${finding.rule}]  ${finding.message}`;
}

function main() {
  const args = process.argv.slice(2);
  const files = collectTargets(args);
  if (files.length === 0) {
    console.log("No markdown files to lint.");
    process.exit(0);
  }

  const all: Finding[] = [];
  for (const file of files) {
    all.push(...lintFile(file));
  }

  if (all.length === 0) {
    console.log(`✓ ${files.length} file(s) linted, no issues`);
    process.exit(0);
  }

  const errors = all.filter((f) => f.severity === "error");
  const warns = all.filter((f) => f.severity === "warn");

  for (const finding of all) console.log(format(finding));
  console.log("");
  console.log(
    `${errors.length} error(s), ${warns.length} warning(s) across ${files.length} file(s).`,
  );
  process.exit(errors.length > 0 ? 1 : 0);
}

main();
