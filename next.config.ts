import type { NextConfig } from "next";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
];

type RedirectEntry = {
  source: string;
  destination: string;
  permanent: boolean;
};

async function loadRedirects(): Promise<RedirectEntry[]> {
  try {
    const raw = await readFile(
      join(process.cwd(), "redirects.json"),
      "utf-8",
    );
    const data = JSON.parse(raw) as Array<Record<string, unknown>>;
    return data
      .filter(
        (r) =>
          typeof r.source === "string" &&
          typeof r.destination === "string" &&
          // Skip example/scaffolding entries by convention.
          r.source !== "/old-post-slug",
      )
      .map((r) => ({
        source: r.source as string,
        destination: r.destination as string,
        permanent: r.permanent !== false,
      }));
  } catch {
    return [];
  }
}

const nextConfig: NextConfig = {
  // Trim per-page JS by tree-shaking heavy libs at import time.
  experimental: {
    optimizePackageImports: [
      "lucide-react",
      "@next-md-blog/core",
      "react-markdown",
    ],
  },
  // Partial Pre-Rendering (PPR) is now gated behind Next 16's unified
  // `cacheComponents` flag, which flips every data fetch to dynamic-by-default
  // unless wrapped in `use cache`. For a fully-static content site like this
  // template the migration cost outweighs the win, so we leave it off. To opt
  // in: set `cacheComponents: true`, mark every page-level loader with
  // `use cache`, replace `export const revalidate = N` with `cacheLife()`,
  // and ensure every `generateStaticParams` returns ≥1 entry.
  images: {
    formats: ["image/avif", "image/webp"],
    remotePatterns: [{ protocol: "https", hostname: "**" }],
  },
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
  async redirects() {
    return loadRedirects();
  },
};

export default nextConfig;
