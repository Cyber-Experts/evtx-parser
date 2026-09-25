import type { Dict } from "@/src/dict/types";
import type { TocItem } from "@/lib/toc";

// Renders a sticky on-desktop table of contents from heading data extracted
// by the rehype-toc plugin. Hidden on mobile (post body wins the limited
// vertical space). On desktop, the surrounding layout reserves a sidebar
// next to the article so we don't need position: sticky inside the article
// column — the parent simply lets this sit beside it.
export function Toc({ dict, items }: { dict: Dict; items: TocItem[] }) {
  if (items.length < 3) return null;
  return (
    <nav
      aria-label={dict.toc.heading}
      className="hidden lg:block lg:sticky lg:top-6 lg:max-h-[calc(100vh-3rem)] lg:overflow-y-auto"
    >
      <div className="surface p-5 text-xs">
        <p className="eyebrow mb-3">{dict.toc.heading}</p>
        <ul className="flex flex-col gap-1.5 border-l border-ink-200 pl-3 dark:border-ink-800">
          {items.map((item) => (
            <li key={item.id} className={item.depth === 3 ? "ml-3" : ""}>
              <a
                href={`#${item.id}`}
                className="block leading-snug text-ink-500 transition-colors hover:text-uv-700 dark:text-ink-400 dark:hover:text-uv-300"
              >
                {item.text}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}
