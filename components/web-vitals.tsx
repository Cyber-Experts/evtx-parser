"use client";

import { useReportWebVitals } from "next/web-vitals";
import { siteConfig } from "@/site.config";

type GtagFn = (
  command: "event",
  name: string,
  params: Record<string, unknown>,
) => void;

declare global {
  interface Window {
    plausible?: (
      event: string,
      opts?: { props?: Record<string, string | number> },
    ) => void;
    umami?: {
      track: (
        event: string,
        props?: Record<string, string | number>,
      ) => void;
    };
    gtag?: GtagFn;
  }
}

export function WebVitals() {
  useReportWebVitals((metric) => {
    const provider = siteConfig.analytics.provider;
    const value = Math.round(
      metric.name === "CLS" ? metric.value * 1000 : metric.value,
    );
    const props = {
      metric: metric.name,
      value,
      id: metric.id,
    };
    try {
      if (provider === "plausible" && typeof window.plausible === "function") {
        window.plausible("web-vitals", { props });
      } else if (
        provider === "umami" &&
        typeof window.umami?.track === "function"
      ) {
        window.umami.track("web-vitals", props);
      } else if (provider === "ga4" && typeof window.gtag === "function") {
        window.gtag("event", metric.name, {
          event_category: "Web Vitals",
          event_label: metric.id,
          value,
          non_interaction: true,
        });
      } else if (process.env.NODE_ENV === "development") {
        // eslint-disable-next-line no-console
        console.debug("[web-vitals]", metric.name, value);
      }
    } catch {
      // never let analytics break rendering
    }
  });
  return null;
}
