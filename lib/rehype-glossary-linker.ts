import { visit, SKIP } from "unist-util-visit";
import type { Root, Element, Text, RootContent } from "hast";
import type { Plugin } from "unified";

import { GLOSSARY } from "./glossary-data";
import type { Locale } from "@/src/dict/locales";

// Rewrites the first text-content occurrence of each glossary term in a
// post body into an anchor pointing at the locale-correct glossary entry.
// Two-way glossary linking is a cheap entity-graph signal (Google: "this
// page is about these things") and gives readers an instant definition.
//
// Strict scope:
// - Only descends into <p> and <li> bodies.
// - Skips text inside <code>, <pre>, <a>, and headings — those either
//   carry their own semantics or live in URLs we shouldn't rewrite.
// - First occurrence per term per document; longest-term-first matching
//   so "ScriptBlock logging" wins over "ScriptBlock" inside the same
//   sentence.
//
// Wire it into MarkdownContent's rehypePlugins prop:
//   <MarkdownContent rehypePlugins={[[rehypeGlossaryLinker, { locale }]]} />

type LinkerOpts = {
  locale: Locale;
  // Skip a slug-equal term so a post about EVTX doesn't self-link "EVTX"
  // back to the glossary on every page. Defaults to undefined (link
  // everything).
  selfSlug?: string;
};

const SKIP_TAGS = new Set([
  "code",
  "pre",
  "a",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
]);

export const rehypeGlossaryLinker: Plugin<[LinkerOpts], Root> = (opts) => {
  const { locale } = opts;
  const terms = [...GLOSSARY]
    .sort((a, b) => b.term.length - a.term.length)
    .map((t) => ({
      ...t,
      regex: new RegExp(
        `(?<![\\p{L}\\p{N}])${escapeRegex(t.term)}(?![\\p{L}\\p{N}])`,
        "u",
      ),
    }));

  return (tree) => {
    const linked = new Set<string>();

    visit(tree, "element", (node: Element, _index, parent) => {
      if (SKIP_TAGS.has(node.tagName)) return SKIP;
      if (node.tagName !== "p" && node.tagName !== "li") return;
      if (parent && (parent as Element).type === "element") {
        const p = parent as Element;
        if (SKIP_TAGS.has(p.tagName)) return SKIP;
      }
      rewriteChildren(node.children, terms, linked, locale);
      return;
    });
  };
};

type TermEntry = (typeof GLOSSARY)[number] & { regex: RegExp };

function rewriteChildren(
  children: RootContent[],
  terms: TermEntry[],
  linked: Set<string>,
  locale: Locale,
) {
  for (let i = 0; i < children.length; i++) {
    const child = children[i];
    if (child.type === "text") {
      const replacements = tryReplace(child as Text, terms, linked, locale);
      if (replacements) {
        children.splice(i, 1, ...replacements);
        i += replacements.length - 1;
      }
    } else if (child.type === "element") {
      const el = child as Element;
      if (SKIP_TAGS.has(el.tagName)) continue;
      rewriteChildren(el.children, terms, linked, locale);
    }
  }
}

function tryReplace(
  node: Text,
  terms: TermEntry[],
  linked: Set<string>,
  locale: Locale,
): RootContent[] | null {
  for (const t of terms) {
    if (linked.has(t.id)) continue;
    const match = node.value.match(t.regex);
    if (!match || match.index === undefined) continue;
    linked.add(t.id);
    const before = node.value.slice(0, match.index);
    const after = node.value.slice(match.index + match[0].length);
    const anchor: Element = {
      type: "element",
      tagName: "a",
      properties: {
        href: `/${locale}/glossary/${t.id}`,
        className: ["glossary-link"],
        title: t.plain,
      },
      children: [{ type: "text", value: match[0] }],
    };
    const out: RootContent[] = [];
    if (before) out.push({ type: "text", value: before });
    out.push(anchor);
    if (after) out.push({ type: "text", value: after });
    return out;
  }
  return null;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
