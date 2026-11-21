import { Plus } from "lucide-react";

import type { Dict } from "@/src/dict/types";

// The FAQPage JSON-LD lives in the page-level @graph (lib/schema.ts), not
// here, so the entity is emitted once and connected to the WebPage node.
//
// Answers sit in native <details>: they stay in the server-rendered HTML
// (crawlable, find-in-page searchable) while the list reads as a compact
// accordion instead of a wall of text. The first item starts open.
export function Faq({ dict }: { dict: Dict }) {
  const items = dict.faq.items;

  return (
    <section
      aria-labelledby="faq-heading"
      className="faq grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.8fr)] lg:gap-16"
    >
      <div className="flex flex-col gap-3 lg:sticky lg:top-24 lg:self-start">
        <span className="eyebrow">FAQ</span>
        <h2
          id="faq-heading"
          className="text-3xl leading-tight tracking-[-0.02em] text-balance text-ink-950 sm:text-4xl dark:text-ink-50"
        >
          {dict.faq.heading}
        </h2>
      </div>
      <div className="surface divide-y divide-ink-100 overflow-hidden dark:divide-white/[0.06]">
        {items.map((item, i) => (
          <details key={item.q} open={i === 0} className="group">
            <summary className="flex cursor-pointer list-none items-start justify-between gap-4 px-5 py-4 transition-colors select-none hover:bg-ink-50/70 sm:px-6 dark:hover:bg-white/[0.02] [&::-webkit-details-marker]:hidden">
              <span className="faq-q font-medium text-ink-900 dark:text-ink-100">
                {item.q}
              </span>
              <span
                aria-hidden="true"
                className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border border-ink-200 text-ink-500 transition-[transform,color,border-color] duration-200 group-open:rotate-45 group-open:border-uv-300 group-open:text-uv-600 motion-reduce:transition-none dark:border-ink-700 dark:group-open:border-uv-400/40 dark:group-open:text-uv-300"
              >
                <Plus className="size-3.5" strokeWidth={2.2} />
              </span>
            </summary>
            <p className="faq-a -mt-1 px-5 pr-14 pb-5 text-sm leading-relaxed text-ink-600 sm:px-6 sm:pr-16 dark:text-ink-400">
              {item.a}
            </p>
          </details>
        ))}
      </div>
    </section>
  );
}
