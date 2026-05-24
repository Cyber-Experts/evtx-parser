import { siteConfig } from "@/site.config";

const ANALYTICS_HOSTS: Record<string, string[]> = {
  plausible: ["https://plausible.io"],
  umami: ["https://cloud.umami.is"],
  ga4: ["https://www.googletagmanager.com", "https://www.google-analytics.com"],
};

/**
 * <link rel="preconnect"> for hosts the page is about to talk to.
 * Cuts TTFB for analytics and image CDNs by 100–500ms on cold connections.
 */
export function ResourceHints() {
  const hosts = new Set<string>();
  const provider = siteConfig.analytics.provider;
  if (provider && ANALYTICS_HOSTS[provider]) {
    for (const h of ANALYTICS_HOSTS[provider]) hosts.add(h);
  }
  // Common image CDN for sample posts; extend per project.
  hosts.add("https://images.unsplash.com");
  return (
    <>
      {[...hosts].map((href) => (
        <link key={href} rel="preconnect" href={href} crossOrigin="" />
      ))}
    </>
  );
}
