import type { ReactElement } from "react";

const LS = String.fromCharCode(0x2028);
const PS = String.fromCharCode(0x2029);

/**
 * Renders a JSON-LD <script> tag for structured data.
 * Escapes characters that would otherwise break out of the script or the JSON.
 */
export function JsonLd({ data }: { data: unknown }): ReactElement {
  const json = JSON.stringify(data)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .split(LS).join("\\u2028")
    .split(PS).join("\\u2029");
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: json }}
    />
  );
}
