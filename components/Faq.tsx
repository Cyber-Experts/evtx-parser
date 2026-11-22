import { Plus } from "lucide-react";

import type { Dict } from "@/src/dict/types";

// The FAQPage JSON-LD lives in the page-level @graph (lib/schema.ts), not
// here, so the entity is emitted once and connected to the WebPage node.
// Native <details> keeps every answer in the HTML for crawlers.
export function Faq({ dict }: { dict: Dict }) {
  const items = dict.faq.items;

  return (
    <section
      aria-labelledby="faq-heading"
      className="faq grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] lg:gap-16"
    >
      <div className="flex flex-col gap-4 lg:sticky lg:top-28 lg:self-start">
        <span className="eyebrow">FAQ</span>
        <h2
          id="faq-heading"
          className="text-[2rem] leading-[1.05] tracking-[-0.035em] text-balance text-ink-950 sm:text-5xl dark:text-white"
        >
          {dict.faq.heading}
        </h2>
      </div>
      <div className="border-t border-ink-200 dark:border-white/[0.08]">
        {items.map((item, i) => (
          <details
            key={item.q}
            open={i === 0}
            className="group border-b border-ink-200 dark:border-white/[0.08]"
          >
            <summary className="faq-q flex cursor-pointer list-none items-start justify-between gap-6 py-5 text-base font-medium text-ink-950 transition-colors hover:text-uv-700 dark:text-white dark:hover:text-uv-300 [&::-webkit-details-marker]:hidden">
              {item.q}
              <Plus
                aria-hidden="true"
                className="mt-0.5 size-5 shrink-0 text-ink-400 transition-transform duration-200 group-open:rotate-45 group-open:text-uv-600 dark:group-open:text-uv-400"
              />
            </summary>
            <p className="faq-a max-w-2xl pb-6 text-[15px] leading-relaxed text-ink-600 dark:text-ink-400">
              {item.a}
            </p>
          </details>
        ))}
      </div>
    </section>
  );
}
