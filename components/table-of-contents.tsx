import type { TocItem } from "@/lib/toc";
import { cn } from "@/lib/utils";

export function TableOfContents({
  items,
  title,
}: {
  items: TocItem[];
  title: string;
}) {
  if (!items.length) return null;
  return (
    <nav aria-label={title} className="surface p-5 text-sm">
      <h2 className="eyebrow mb-3">{title}</h2>
      <ol className="space-y-2 border-l border-ink-200 dark:border-ink-800">
        {items.map((it) => (
          <li key={it.id} className={cn("pl-3", it.depth === 3 && "pl-6")}>
            <a
              href={`#${it.id}`}
              className={cn(
                "block leading-snug transition-colors hover:text-uv-700 dark:hover:text-uv-300",
                it.depth === 3
                  ? "text-ink-500 dark:text-ink-500"
                  : "text-ink-700 dark:text-ink-300",
              )}
            >
              {it.text}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}
