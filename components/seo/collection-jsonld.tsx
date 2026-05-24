import { JsonLd } from "./json-ld";

export type CollectionItem = { name: string; url: string };

/**
 * CollectionPage + ItemList for blog list / tag pages.
 * Eligible for the "Carousel" search appearance.
 */
export function CollectionJsonLd({
  url,
  name,
  description,
  items,
  inLanguage,
}: {
  url: string;
  name: string;
  description?: string;
  items: CollectionItem[];
  inLanguage?: string;
}) {
  const data = {
    "@context": "https://schema.org",
    "@type": "CollectionPage",
    "@id": url,
    url,
    name,
    description,
    inLanguage,
    mainEntity: {
      "@type": "ItemList",
      itemListElement: items.map((it, i) => ({
        "@type": "ListItem",
        position: i + 1,
        name: it.name,
        url: it.url,
      })),
    },
  };
  return <JsonLd data={data} />;
}
