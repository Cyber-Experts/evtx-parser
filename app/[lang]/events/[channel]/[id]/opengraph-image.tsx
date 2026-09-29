import { notFound } from "next/navigation";

import { isLocale, type Locale } from "@/src/dict/locales";
import { allEntries, getEntry, viewEntry } from "@/lib/events";
import { ogContentType, ogSize, renderEventOg } from "@/lib/og-template";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "Windows Event ID encyclopedia entry";
export const dynamicParams = false;

export function generateStaticParams() {
  const out: { lang: string; channel: string; id: string }[] = [];
  for (const e of allEntries())
    for (const lang of viewEntry(e, "en").locales) out.push({ lang, channel: e.channel, id: String(e.id) });
  return out;
}

export default async function EventOpengraphImage({
  params,
}: {
  params: Promise<{ lang: string; channel: string; id: string }>;
}) {
  const { lang, channel, id } = await params;
  if (!isLocale(lang) || !/^\d+$/.test(id)) notFound();
  const entry = getEntry(channel, Number(id));
  if (!entry) notFound();
  const view = viewEntry(entry, lang as Locale);
  return renderEventOg({
    id: entry.id,
    channel: view.channelInfo.label,
    title: view.title,
    summary: view.summary,
    locale: lang as Locale,
  });
}
