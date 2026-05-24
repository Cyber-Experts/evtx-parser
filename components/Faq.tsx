import type { Dict } from "@/src/dict/types";

// The FAQPage JSON-LD lives in the page-level @graph (lib/schema.ts), not
// here, so the entity is emitted once and connected to the WebPage node.
export function Faq({ dict }: { dict: Dict }) {
  const items = dict.faq.items;

  return (
    <section
      aria-labelledby="faq-heading"
      className="faq flex w-full max-w-3xl flex-col gap-4 border-t border-zinc-200 pt-8 dark:border-zinc-800"
    >
      <h2 id="faq-heading" className="font-mono text-xl font-semibold">
        {dict.faq.heading}
      </h2>
      <dl className="flex flex-col gap-5">
        {items.map((item) => (
          <div key={item.q} className="flex flex-col gap-1.5">
            <dt className="font-medium text-zinc-900 dark:text-zinc-100">
              {item.q}
            </dt>
            <dd className="text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
              {item.a}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
