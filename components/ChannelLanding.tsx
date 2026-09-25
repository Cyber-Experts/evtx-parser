import Link from "next/link";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import {
  channelContent,
  channelGraph,
  type ChannelKey,
} from "@/lib/landing/channels";

export function ChannelLanding({
  channel,
  locale,
}: {
  channel: ChannelKey;
  locale: Locale;
}) {
  const dict = getDict(locale);
  const c = channelContent(channel, locale);
  const ld = channelGraph(channel, locale);

  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-8 px-4 py-6 sm:px-6 sm:py-10">
      <Breadcrumbs
        dict={dict}
        items={[
          { label: dict.breadcrumb.home, href: `/${locale}` },
          { label: c.h1 },
        ]}
      />

      <header className="flex flex-col gap-3">
        <h1 className="text-2xl font-semibold tracking-tight text-ink-900 dark:text-ink-100 sm:text-3xl">
          {c.h1}
        </h1>
        <p className="text-sm leading-relaxed text-ink-600 dark:text-ink-400">
          {c.intro}
        </p>
        <div>
          <Link
            href={`/${locale}`}
            className="inline-block rounded-md border border-ink-900 bg-ink-900 px-4 py-2 text-sm font-medium text-ink-50 hover:bg-ink-700 dark:border-ink-100 dark:bg-ink-100 dark:text-ink-900 dark:hover:bg-ink-300"
          >
            {c.ctaLabel} ↗
          </Link>
        </div>
      </header>

      <section
        aria-labelledby="what-heading"
        className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="what-heading" className="font-mono text-base font-semibold">
          {c.whatHeading}
        </h2>
        {c.whatBody.map((p, i) => (
          <p
            key={i}
            className="text-sm leading-relaxed text-ink-700 dark:text-ink-300"
          >
            {p}
          </p>
        ))}
      </section>

      <section
        aria-labelledby="events-heading"
        className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="events-heading" className="font-mono text-base font-semibold">
          {c.eventsHeading}
        </h2>
        <ul className="grid gap-2 sm:grid-cols-2">
          {c.events.map((e) => (
            <li key={e.id}>
              <Link
                href={`/${locale}/event-id/${e.id}`}
                className="group flex items-baseline gap-2 rounded border border-ink-200 px-3 py-2 hover:border-ink-400 dark:border-ink-800 dark:hover:border-ink-600"
              >
                <span className="font-mono text-sm font-medium text-ink-900 dark:text-ink-100">
                  {e.id}
                </span>
                <span className="text-sm text-ink-600 group-hover:underline dark:text-ink-400">
                  {e.name}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section
        aria-labelledby="open-heading"
        className="flex flex-col gap-3 border-t border-ink-200 pt-6 dark:border-ink-800"
      >
        <h2 id="open-heading" className="font-mono text-base font-semibold">
          {c.openHeading}
        </h2>
        <p className="text-sm leading-relaxed text-ink-700 dark:text-ink-300">
          {c.openBody}
        </p>
      </section>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
