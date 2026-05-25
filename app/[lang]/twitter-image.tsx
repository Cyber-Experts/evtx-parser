import { notFound } from "next/navigation";

import { isLocale } from "@/src/dict/locales";
import { ogContentType, ogSize, renderOg } from "@/lib/og-template";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "EVTX parser — browser-side Windows Event Log forensics";

export default async function TwitterImage({
  params,
}: {
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();
  return renderOg(lang);
}
