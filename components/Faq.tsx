import type { Dict } from "@/src/dict/types";

// The FAQPage JSON-LD lives in the page-level @graph (lib/schema.ts), not
// here, so the entity is emitted once and connected to the WebPage node.
export function Faq({ dict }: { dict: Dict }) {
  const items = dict.faq.items;

  return (
    <section
      aria-labelledby="faq-heading"
      className="faq flex w-full max-w-3xl flex-col gap-5 pt-6"
    >
      <h2 id="faq-heading" className="text-2xl text-ink-950 dark:text-ink-50">
        {dict.faq.heading}
      </h2>
      <dl className="surface flex flex-col divide-y divide-ink-100 px-5 dark:divide-ink-800">
        {items.map((item) => (
          <div key={item.q} className="flex flex-col gap-1.5 py-4">
            <dt className="font-medium text-ink-900 dark:text-ink-100">
              {item.q}
            </dt>
            <dd className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
              {item.a}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
