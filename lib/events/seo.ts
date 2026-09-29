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
 * Metadata title: the layout template appends " | EVTX parser" when the
 * result still fits in 60 characters; otherwise the heading goes out alone.
 */
export function eventMetaTitle(
  view: Pick<EventView, "id" | "shortTitle" | "channelInfo">,
  d: Pick<EventsDict, "heading">,
): string | { absolute: string } {
  const base = eventHeadingText(view, d);
  return base.length + SUFFIX.length <= TITLE_MAX ? base : { absolute: base };
}

/** The final <title> string (for tests / reports). */
export function renderedTitle(title: string | { absolute: string }): string {
  return typeof title === "string" ? `${title}${SUFFIX}` : title.absolute;
}
