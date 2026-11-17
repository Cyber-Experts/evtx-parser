import { siteConfig } from "@/site.config";
import type { EventsDict } from "@/src/dict/events";
import { fill } from "@/src/dict/events";

import type { EventView } from "./index";

/** Google truncates titles around 60 characters. */
export const TITLE_MAX = 60;
const SUFFIX = ` | ${siteConfig.name}`;

/** "Sysmon Event ID 1: Process creation" in the page's locale. */
export function eventHeadingText(
  view: Pick<EventView, "id" | "shortTitle" | "channelInfo">,
  d: Pick<EventsDict, "heading">,
): string {
  return fill(d.heading, {
    prefix: view.channelInfo.seoPrefix ? `${view.channelInfo.seoPrefix} ` : "",
    id: view.id,
    title: view.shortTitle,
  });
}

/**
 * Channels whose <title> leads with the official event message ("An account
 * failed to log on") instead of our short label ("Failed logon"). People search
 * Security events by that message, and it is how other references name them.
 * Limited to Security for now so the other channels serve as a CTR control.
 */
const OFFICIAL_TITLE_CHANNELS = new Set(["security"]);

/**
 * Metadata title: the layout template appends " | EVTX parser" when the
 * result still fits in 60 characters; otherwise the heading goes out alone.
 * On OFFICIAL_TITLE_CHANNELS the official message is used when the heading
 * fits in 60 characters, else the short label.
 */
export function eventMetaTitle(
  view: Pick<EventView, "id" | "title" | "shortTitle" | "channel" | "channelInfo">,
  d: Pick<EventsDict, "heading">,
): string | { absolute: string } {
  if (OFFICIAL_TITLE_CHANNELS.has(view.channel)) {
    const official = eventHeadingText({ ...view, shortTitle: view.title }, d);
    if (official.length <= TITLE_MAX) {
      return official.length + SUFFIX.length <= TITLE_MAX ? official : { absolute: official };
    }
  }
  const base = eventHeadingText(view, d);
  return base.length + SUFFIX.length <= TITLE_MAX ? base : { absolute: base };
}

/** The final <title> string (for tests / reports). */
export function renderedTitle(title: string | { absolute: string }): string {
  return typeof title === "string" ? `${title}${SUFFIX}` : title.absolute;
}
