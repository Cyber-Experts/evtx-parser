import type { NextConfig } from "next";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Content-Security-Policy.
 * - `wasm-unsafe-eval` is required to load the in-browser EVTX parser
 *   (Rust → WebAssembly in lib/evtx-wasm).
 * - `worker-src 'self' blob:` lets the parser's Web Worker run.
 * - `'unsafe-inline'` on script-src covers Next.js's per-page hydration
 *   script and the inline JSON-LD blocks emitted by @next-md-blog/core.
 * - Vercel Analytics + Speed Insights and Ahrefs Web Analytics
 *   connect/script-src entries.
 */
const csp = [
  "default-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://va.vercel-scripts.com https://analytics.ahrefs.com",
  "connect-src 'self' https://va.vercel-scripts.com https://*.vercel-insights.com https://analytics.ahrefs.com",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value:
      "camera=(), microphone=(), geolocation=(), interest-cohort=(), browsing-topics=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "X-DNS-Prefetch-Control", value: "on" },
];

type RedirectEntry = {
  source: string;
  destination: string;
  permanent: boolean;
};

async function loadRedirects(): Promise<RedirectEntry[]> {
  try {
    const raw = await readFile(join(process.cwd(), "redirects.json"), "utf-8");
    const data = JSON.parse(raw) as Array<Record<string, unknown>>;
    return data
      .filter(
        (r) =>
          typeof r.source === "string" &&
          typeof r.destination === "string" &&
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
  // Self-contained server bundle for the Docker image (see Dockerfile);
  // regular builds, including Vercel's, are unchanged.
  ...(process.env.NEXT_OUTPUT_STANDALONE === "1" ? { output: "standalone" as const } : {}),
  poweredByHeader: false,
  trailingSlash: false,
  experimental: {
    optimizePackageImports: [
      "lucide-react",
      "@next-md-blog/core",
      "react-markdown",
    ],
  },
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
