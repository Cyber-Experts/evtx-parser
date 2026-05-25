import { defaultLocale } from "@/src/dict/locales";
import { ogContentType, ogSize, renderOg } from "@/lib/og-template";

export const size = ogSize;
export const contentType = ogContentType;
export const alt = "EVTX parser — browser-side Windows Event Log forensics";

/**
 * Site-wide default OG image (no locale segment in URL). Renders the
 * default-locale variant of the branded template.
 */
export default async function OpengraphImage() {
  return renderOg(defaultLocale);
}
