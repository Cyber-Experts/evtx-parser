import { JsonLd } from "./json-ld";
import { siteConfig } from "@/site.config";
import { DEFAULT_LOCALE } from "@/lib/i18n";

export function WebsiteJsonLd({ locale = DEFAULT_LOCALE }: { locale?: string } = {}) {
  const data = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    "@id": `${siteConfig.url}/#website`,
    url: `${siteConfig.url}/${locale}`,
    name: siteConfig.name,
    description: siteConfig.description,
    inLanguage: locale,
    potentialAction: {
      "@type": "SearchAction",
      target: {
        "@type": "EntryPoint",
        urlTemplate: `${siteConfig.url}/${locale}/search?q={search_term_string}`,
      },
      "query-input": "required name=search_term_string",
    },
    publisher: { "@id": `${siteConfig.url}/#organization` },
  };
  return <JsonLd data={data} />;
}
