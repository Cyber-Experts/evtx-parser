export type TocItem = {
  /** HTML id (matches the heading's rehype-slug output). */
  id: string;
  depth: number;
  text: string;
};

function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\p{Letter}\p{Number}\s-]/gu, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

/**
 * Extract h2 / h3 headings from raw markdown for a table of contents.
 * Skips fenced code blocks so `# inside code` does not register.
 */
export function extractHeadings(markdown: string): TocItem[] {
  const lines = markdown.split(/\r?\n/);
  const items: TocItem[] = [];
  let inFence = false;
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const match = /^(#{2,3})\s+(.+?)\s*#*\s*$/.exec(line);
    if (!match) continue;
    const depth = match[1].length;
    const text = match[2].replace(/`/g, "");
    items.push({ depth, text, id: slugify(text) });
  }
  return items;
}
