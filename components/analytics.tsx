import Script from "next/script";
import { siteConfig } from "@/site.config";

export function Analytics() {
  const { provider, domain, id } = siteConfig.analytics;
  if (!provider) return null;
  if (provider === "plausible" && domain) {
    return (
      <Script
        src="https://plausible.io/js/script.js"
        data-domain={domain}
        strategy="afterInteractive"
        defer
      />
    );
  }
  if (provider === "umami" && id) {
    return (
      <Script
        src="https://cloud.umami.is/script.js"
        data-website-id={id}
        strategy="afterInteractive"
        defer
      />
    );
  }
  if (provider === "ga4" && id) {
    return (
      <>
        <Script
          src={`https://www.googletagmanager.com/gtag/js?id=${id}`}
          strategy="afterInteractive"
        />
        <Script id="ga4-init" strategy="afterInteractive">
          {`window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','${id}');`}
        </Script>
      </>
    );
  }
  return null;
}
