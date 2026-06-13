import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { isLocale } from "@/src/dict/locales";
import { ChannelLanding } from "@/components/ChannelLanding";
import { channelMetadata } from "@/lib/landing/channels";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang: locale } = await params;
  if (!isLocale(locale)) return {};
  return channelMetadata("security", locale);
}

export default async function SecurityEvtxPage({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang: locale } = await params;
  if (!isLocale(locale)) notFound();
  return <ChannelLanding channel="security" locale={locale} />;
}
