import { notFound } from "next/navigation";
import type { Metadata } from "next";

import { isLocale } from "@/src/dict/locales";
import {
  LandingPage,
  landingMetadata,
} from "@/components/landing/LandingPage";

const PATH = "/evtx-dump-online";

export async function generateMetadata({
  params,
}: {
  params: Promise<{ lang: string }>;
}): Promise<Metadata> {
  const { lang } = await params;
  if (!isLocale(lang)) return {};
  return landingMetadata(PATH, lang);
}

export default async function Page({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();
  return <LandingPage path={PATH} locale={lang} />;
}
