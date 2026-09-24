import type { LandingContent } from "./landing";
import type { LocaleContent } from "./locale-content";
import { EVTX_TO_XML } from "./evtx-to-xml";
import { EVTX_TO_CSV } from "./evtx-to-csv";
import { EVTX_TO_TXT } from "./evtx-to-txt";
import { EVTX_TO_JSON } from "./evtx-to-json";
import { EVTX_DUMP } from "./evtx-dump";
import { EVTX_VIEWER_MAC_LINUX } from "./evtx-viewer-mac-linux";

/**
 * Single-intent landing pages rendered by components/landing/LandingPage.
 * Keyed by URL path (without locale). Order drives the "Related tools" list.
 */
export const LANDINGS = {
  "/evtx-to-xml": EVTX_TO_XML,
  "/evtx-to-csv": EVTX_TO_CSV,
  "/evtx-to-txt": EVTX_TO_TXT,
  "/evtx-to-json": EVTX_TO_JSON,
  "/evtx-dump-online": EVTX_DUMP,
  "/evtx-viewer-mac-linux": EVTX_VIEWER_MAC_LINUX,
} satisfies Record<string, LocaleContent<LandingContent>>;

export type LandingPath = keyof typeof LANDINGS;

export const LANDING_PATHS = Object.keys(LANDINGS) as LandingPath[];
