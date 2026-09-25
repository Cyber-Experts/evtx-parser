import type { Dict } from "@/src/dict/types";
import type { TocItem } from "@/lib/toc";

// Renders a sticky on-desktop table of contents from heading data extracted
// by the rehype-toc plugin. Hidden on mobile (post body wins the limited
// vertical space). On desktop, the surrounding layout reserves a sidebar
// next to the article so we don't need position: sticky inside the article
// column — the parent simply lets this sit beside it.
export function Toc({
  dict,
  items,
}: {
  dict: Dict;
  items: TocItem[];
}) {
  if (items.length < 3) return null;
  return (
    <nav
      aria-label={dict.toc.heading}
      className="hidden lg:block lg:sticky lg:top-6 lg:max-h-[calc(100vh-3rem)] lg:overflow-y-auto"
    >
      <div className="border-l border-ink-200 pl-4 text-xs dark:border-ink-800">
        <p className="mb-2 font-mono font-semibold text-ink-700 dark:text-ink-300">
          {dict.toc.heading}
        </p>
        <ul className="flex flex-col gap-1.5">
          {items.map((item) => (
            <li
              key={item.id}
              className={item.depth === 3 ? "ml-3" : ""}
            >
              <a
                href={`#${item.id}`}
                className="block text-ink-500 leading-snug hover:text-ink-800 dark:hover:text-ink-200"
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
