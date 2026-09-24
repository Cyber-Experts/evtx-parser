"use client";

import { createContext, useContext, type ReactNode } from "react";

/** Regex of the current search hits, shared by every table/detail cell. */
export const HighlightContext = createContext<RegExp | null>(null);

export function buildHighlightRegExp(
  terms: string[],
  regex: string | null,
): RegExp | null {
  if (regex) {
    try {
      return new RegExp(regex, "gi");
    } catch {
      return null;
    }
  }
  if (terms.length === 0) return null;
  const esc = terms
    .sort((a, b) => b.length - a.length)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(esc.join("|"), "gi");
}

/** Renders `text` with search hits wrapped in <mark>. */
export function Hl({ text }: { text: string }): ReactNode {
  const shared = useContext(HighlightContext);
  if (!shared || !text) return text;
  // Own copy: exec() advances lastIndex, and the shared one must stay pristine.
  const re = new RegExp(shared.source, shared.flags);
  const out: ReactNode[] = [];
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m[0] === "") {
      // Zero-length match (e.g. a regex like `a*`): step past it.
      re.lastIndex++;
      continue;
    }
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(
      <mark
        key={m.index}
        className="rounded-sm bg-amber-300/60 px-0.5 text-inherit dark:bg-amber-400/30"
      >
        {m[0]}
      </mark>,
    );
    last = m.index + m[0].length;
    if (out.length > 200) break;
  }
  if (out.length === 0) return text;
  if (last < text.length) out.push(text.slice(last));
  return out;
}
