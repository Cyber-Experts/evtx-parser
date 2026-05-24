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
    <nav aria-label={title} className="text-sm">
      <h2 className="font-semibold mb-3">{title}</h2>
      <ol className="space-y-2 border-l">
        {items.map((it) => (
          <li
            key={it.id}
            className={cn("pl-3", it.depth === 3 && "pl-6 text-muted-foreground")}
          >
            <a href={`#${it.id}`} className="hover:text-foreground hover:underline">
              {it.text}
            </a>
          </li>
        ))}
      </ol>
    </nav>
  );
}
