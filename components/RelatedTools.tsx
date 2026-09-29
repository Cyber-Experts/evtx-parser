import related from "@/data/related-tools.json";
import type { Locale } from "@/lib/i18n";

type RelatedItem = {
  name: string;
  url: string;
  locales: string[];
  reason: Record<string, string>;
};

/**
 * Up to three sister tools chosen by artifact relationship (not a site
 * network). Each item is shown only when the target has this locale.
 */
export function RelatedTools({ locale }: { locale: Locale }) {
  const items = (related.items as RelatedItem[]).filter((i) =>
    i.locales.includes(locale),
  );
  if (items.length === 0) return null;
  const headings = related.heading as Record<string, string>;

  return (
    <section
      aria-labelledby="related-tools-heading"
      className="mx-auto flex w-full max-w-4xl flex-col gap-4"
    >
      <h2 id="related-tools-heading" className="eyebrow">
        {headings[locale] ?? headings.en}
      </h2>
      <ul className="grid gap-4 sm:grid-cols-3">
        {items.map((item) => (
          <li key={item.url}>
            <a
              href={`${item.url}/${locale}`}
              className="surface surface-interactive flex h-full flex-col gap-1.5 p-5"
            >
              <span className="font-medium text-ink-900 dark:text-ink-100">
                {item.name}
              </span>
              <span className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
                {item.reason[locale]}
              </span>
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}
