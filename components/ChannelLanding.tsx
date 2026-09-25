import Link from "next/link";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";
import { jsonLdScript } from "@/lib/schema";
import { Breadcrumbs } from "@/components/BreadcrumbsEvtx";
import { GitHubMark } from "@/components/GitHubMark";
import { CtaBand, REPO_URL } from "@/components/home/HomeSections";
import {
  BTN_PRIMARY,
  BTN_SECONDARY,
  PageHero,
  SectionTitle,
} from "@/components/PageHero";
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
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-16 px-4 py-6 sm:gap-20 sm:px-6 sm:py-10">
      <PageHero
        top={
          <Breadcrumbs
            dict={dict}
            items={[
              { label: dict.breadcrumb.home, href: `/${locale}` },
              { label: c.h1 },
            ]}
          />
        }
        title={c.h1}
        intro={<p>{c.intro}</p>}
      >
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <Link href={`/${locale}`} className={BTN_PRIMARY}>
            {c.ctaLabel}
            <span aria-hidden="true">→</span>
          </Link>
          <a href={REPO_URL} className={BTN_SECONDARY}>
            <GitHubMark className="h-4 w-4" />
            {dict.home.heroCtaGithub}
          </a>
        </div>
      </PageHero>

      <section aria-labelledby="what-heading" className="flex flex-col gap-6">
        <SectionTitle id="what-heading">{c.whatHeading}</SectionTitle>
        <div className="surface flex flex-col gap-4 px-6 py-6 sm:px-8">
          {c.whatBody.map((p, i) => (
            <p
              key={i}
              className="leading-relaxed text-ink-700 dark:text-ink-300"
            >
              {p}
            </p>
          ))}
        </div>
      </section>

      <section aria-labelledby="events-heading" className="flex flex-col gap-6">
        <SectionTitle id="events-heading">{c.eventsHeading}</SectionTitle>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {c.events.map((e) => (
            <li key={e.id}>
              <Link
                href={`/${locale}/event-id/${e.id}`}
                className="surface surface-interactive group flex h-full items-baseline gap-3 px-4 py-3"
              >
                <span className="shrink-0 rounded-md bg-uv-50 px-1.5 font-mono text-sm font-medium text-uv-700 dark:bg-uv-400/10 dark:text-uv-300">
                  {e.id}
                </span>
                <span className="text-sm text-ink-700 group-hover:text-ink-950 dark:text-ink-300 dark:group-hover:text-ink-50">
                  {e.name}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="open-heading" className="flex flex-col gap-6">
        <SectionTitle id="open-heading">{c.openHeading}</SectionTitle>
        <p className="max-w-3xl leading-relaxed text-ink-700 dark:text-ink-300">
          {c.openBody}
        </p>
      </section>

      <CtaBand dict={dict} href={`/${locale}`} />

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={jsonLdScript(ld)}
      />
    </main>
  );
}
