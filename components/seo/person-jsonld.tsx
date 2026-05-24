import { JsonLd } from "./json-ld";
import type { Author } from "@next-md-blog/core";

export function PersonJsonLd({
  author,
  url,
  inLanguage,
}: {
  author: Author;
  url: string;
  inLanguage?: string;
}) {
  const sameAs = [author.twitter, author.github, author.url].filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  const data = {
    "@context": "https://schema.org",
    "@type": "Person",
    "@id": `${url}#person`,
    name: author.name,
    url,
    description: author.bio,
    image: author.avatar,
    email: author.email,
    sameAs: sameAs.length ? sameAs : undefined,
    inLanguage,
  };
  return <JsonLd data={data} />;
}
