import type { ReactNode } from "react";

// Tiny renderer for the encyclopedia's prose: `code` and **bold** inline,
// paragraphs separated by a blank line. Nothing else is interpreted, so data
// files can't inject markup.

const TOKEN_RE = /(`[^`]+`|\*\*[^*]+\*\*)/g;

export function Inline({ text }: { text: string }): ReactNode {
  const parts = text.split(TOKEN_RE);
  return parts.map((p, i) => {
    if (p.startsWith("`") && p.endsWith("`") && p.length > 2)
      return (
        <code
          key={i}
          className="rounded bg-ink-100 px-1 py-px font-mono text-[0.85em] break-words text-ink-800 dark:bg-ink-800/70 dark:text-ink-200"
        >
          {p.slice(1, -1)}
        </code>
      );
    if (p.startsWith("**") && p.endsWith("**") && p.length > 4)
      return (
        <strong key={i} className="font-semibold text-ink-900 dark:text-ink-100">
          {p.slice(2, -2)}
        </strong>
      );
    return p;
  });
}

export function Paragraphs({ text, className }: { text: string; className?: string }) {
  return (
    <>
      {text
        .split(/\n\s*\n/)
        .map((p) => p.replace(/\s*\n\s*/g, " ").trim())
        .filter(Boolean)
        .map((p, i) => (
          <p key={i} className={className}>
            <Inline text={p} />
          </p>
        ))}
    </>
  );
}

/** Plain text (for meta tags / JSON-LD): strips the inline markers. */
export function plainText(text: string): string {
  return text
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\s+/g, " ")
    .trim();
}
