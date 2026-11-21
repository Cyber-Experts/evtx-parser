import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ImageResponse } from "next/og";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

// "Flare" palette (see app/globals.css).
const BG = "#0a0a0a";
const TEXT = "#ededed";
const MUTED = "#a1a1a1";
const FAINT = "#5c5c5c";
const FLARE = "#ff5a1a";
const FLARE_SOFT = "#ff7a3d";

// Fonts bundled in assets/fonts (OFL) — read from disk, never fetched, so
// images render offline too (Docker / air-gapped builds).
let fontsPromise: Promise<NonNullable<ConstructorParameters<typeof ImageResponse>[1]>["fonts"]> | null =
  null;
function loadFonts() {
  const read = (file: string) => readFile(join(process.cwd(), "assets/fonts", file));
  fontsPromise ??= Promise.all([
    read("Inter-Regular.woff"),
    read("Inter-SemiBold.woff"),
    read("Inter-Bold.woff"),
    read("InstrumentSerif-Italic.woff"),
    read("JetBrainsMono-Regular.woff"),
    read("JetBrainsMono-Medium.woff"),
  ]).then(([reg, semi, bold, serif, mono, monoMed]) => [
    { name: "Inter", data: reg, weight: 400 as const, style: "normal" as const },
    { name: "Inter", data: semi, weight: 600 as const, style: "normal" as const },
    { name: "Inter", data: bold, weight: 700 as const, style: "normal" as const },
    { name: "Instrument Serif", data: serif, weight: 400 as const, style: "italic" as const },
    { name: "JetBrains Mono", data: mono, weight: 400 as const, style: "normal" as const },
    { name: "JetBrains Mono", data: monoMed, weight: 500 as const, style: "normal" as const },
  ]);
  return fontsPromise;
}

const svgSrc = (svg: string) => `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;

// Brand mark: event baseline with one spike, on a signal-orange tile.
const MARK_SRC = svgSrc(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="8" fill="${FLARE}"/>
  <path d="M5.5 20.5H11.6L14.4 9.5L17.6 23L19.6 16.8L20.9 20.5H26.5" fill="none" stroke="#0a0a0a" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`);

// Backdrop: 12 faint column rules, a flare glow on the spike, and the event
// baseline with its ruler running across the bottom. Drawn as one SVG
// because Satori's CSS gradients are limited.
const cols = Array.from({ length: 11 }, (_, i) => {
  const x = ((i + 1) * 1200) / 12;
  return `<line x1="${x}" y1="0" x2="${x}" y2="630" stroke="white" stroke-opacity="0.045"/>`;
}).join("");
const ticks = Array.from({ length: 151 }, (_, i) => {
  const x = i * 8;
  const major = i % 8 === 0;
  return `<line x1="${x}" y1="${major ? 618 : 624}" x2="${x}" y2="630" stroke="white" stroke-opacity="${major ? 0.3 : 0.12}"/>`;
}).join("");
const BACKDROP = svgSrc(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <radialGradient id="g" cx="890" cy="470" r="300" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="${FLARE}" stop-opacity="0.38"/>
      <stop offset="1" stop-color="${FLARE}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="f" x1="0" x2="1">
      <stop offset="0" stop-color="white" stop-opacity="0"/>
      <stop offset="0.2" stop-color="white" stop-opacity="0.28"/>
      <stop offset="0.85" stop-color="white" stop-opacity="0.28"/>
      <stop offset="1" stop-color="white" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="${BG}"/>
  ${cols}
  <rect width="1200" height="630" fill="url(#g)"/>
  <path d="M0 596H840L866 596L890 470L922 612L940 560L954 596H1200" fill="none" stroke="url(#f)" stroke-width="2"/>
  <path d="M840 596L866 596L890 470L922 612L940 560L954 596" fill="none" stroke="${FLARE}" stroke-width="3.5" stroke-linejoin="round"/>
  <circle cx="890" cy="470" r="7" fill="${FLARE}"/>
  <circle cx="890" cy="470" r="16" fill="${FLARE}" fill-opacity="0.18"/>
  ${ticks}
</svg>`);

function Frame({ children, footer }: { children: React.ReactNode; footer: React.ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: BG,
        padding: "56px 72px 0",
        color: TEXT,
        fontFamily: "Inter",
      }}
    >
      {/* Rendered to PNG by Satori, not the browser: next/image doesn't apply. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={BACKDROP} width={1200} height={630} alt="" style={{ position: "absolute", top: 0, left: 0 }} />

      {/* brand */}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={MARK_SRC} width={48} height={48} alt="" />
        <div style={{ display: "flex", alignItems: "baseline", gap: 9 }}>
          <span style={{ fontWeight: 700, fontSize: 30, letterSpacing: "-0.03em" }}>EVTX</span>
          <span style={{ fontFamily: "Instrument Serif", fontStyle: "italic", fontSize: 38 }}>parser</span>
        </div>
        <div style={{ display: "flex", marginLeft: "auto", fontFamily: "JetBrains Mono", fontSize: 20, color: FAINT }}>
          evtxparser.com
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", flex: 1, justifyContent: "center", paddingBottom: 70 }}>
        {children}
      </div>
      <div style={{ display: "flex", position: "absolute", left: 72, bottom: 40 }}>{footer}</div>
    </div>
  );
}

function Tags({ items }: { items: string[] }) {
  return (
    <div style={{ display: "flex", gap: 12, fontFamily: "JetBrains Mono", fontSize: 19, color: MUTED }}>
      {items.map((t, i) => (
        <span
          key={t}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "7px 14px",
            borderRadius: 999,
            border: `1px solid ${i === 0 ? "rgba(255,90,26,0.55)" : "rgba(255,255,255,0.14)"}`,
            background: i === 0 ? "rgba(255,90,26,0.12)" : "rgba(10,10,10,0.6)",
            color: i === 0 ? FLARE_SOFT : MUTED,
          }}
        >
          {i === 0 ? <span style={{ display: "flex", width: 8, height: 8, background: FLARE }} /> : null}
          {t}
        </span>
      ))}
    </div>
  );
}

/** Site-wide card: the brand line in the serif, the promise in the sans. */
export async function renderOg(locale: Locale) {
  const dict = getDict(locale);
  const [brand, rest] = dict.home.headline.includes(" — ")
    ? dict.home.headline.split(" — ", 2)
    : [null, dict.home.headline];
  return new ImageResponse(
    (
      <Frame footer={<Tags items={["0 bytes uploaded", "Rust → WebAssembly", "Sigma · hunts"]} />}>
        <div style={{ display: "flex", flexDirection: "column", maxWidth: 960 }}>
          {brand ? (
            <div
              style={{
                fontFamily: "Instrument Serif",
                fontStyle: "italic",
                fontSize: 92,
                lineHeight: 1,
                color: FLARE_SOFT,
                letterSpacing: "-0.02em",
              }}
            >
              {brand}
            </div>
          ) : null}
          <div
            style={{
              fontWeight: 600,
              fontSize: rest.length > 48 ? 64 : 76,
              lineHeight: 1.02,
              letterSpacing: "-0.045em",
            }}
          >
            {rest}
          </div>
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}

/** Blog post card: title, description, reading time — same identity. */
export async function renderPostOg(opts: {
  title: string;
  description: string;
  locale: Locale;
  minutes?: number;
}) {
  const { title, description, locale, minutes } = opts;
  const titleSize = title.length > 70 ? 54 : title.length > 45 ? 64 : 74;
  const tags = ["DFIR guide", ...(minutes ? [`${minutes} min read`] : []), locale.toUpperCase()];
  return new ImageResponse(
    (
      <Frame footer={<Tags items={tags} />}>
        <div style={{ display: "flex", flexDirection: "column", gap: 22, maxWidth: 1000 }}>
          <div
            style={{
              fontWeight: 600,
              fontSize: titleSize,
              lineHeight: 1.04,
              letterSpacing: "-0.04em",
            }}
          >
            {title}
          </div>
          {description ? (
            <div style={{ fontSize: 26, lineHeight: 1.4, color: MUTED, maxWidth: 900 }}>
              {description.length > 150 ? `${description.slice(0, 147)}…` : description}
            </div>
          ) : null}
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}

/** Event ID encyclopedia card: the ID large in the serif, then the title. */
export async function renderEventOg(opts: {
  id: number;
  channel: string;
  title: string;
  summary: string;
  locale: Locale;
}) {
  const { id, channel, title, summary, locale } = opts;
  const titleSize = title.length > 60 ? 46 : title.length > 40 ? 54 : 62;
  return new ImageResponse(
    (
      <Frame footer={<Tags items={["Event ID encyclopedia", channel, locale.toUpperCase()]} />}>
        <div style={{ display: "flex", flexDirection: "column", gap: 18, maxWidth: 1000 }}>
          <div
            style={{
              display: "flex",
              alignItems: "baseline",
              gap: 18,
              fontFamily: "JetBrains Mono",
              fontSize: 24,
              color: FAINT,
            }}
          >
            <span style={{ color: MUTED }}>EventID</span>
            <span
              style={{
                fontFamily: "Instrument Serif",
                fontStyle: "italic",
                fontSize: String(id).length > 4 ? 120 : 150,
                lineHeight: 0.9,
                color: FLARE_SOFT,
                letterSpacing: "-0.02em",
              }}
            >
              {id}
            </span>
          </div>
          <div
            style={{
              fontWeight: 600,
              fontSize: titleSize,
              lineHeight: 1.05,
              letterSpacing: "-0.035em",
            }}
          >
            {title}
          </div>
          <div style={{ fontSize: 24, lineHeight: 1.4, color: MUTED, maxWidth: 900 }}>
            {summary.length > 130 ? `${summary.slice(0, 127)}…` : summary}
          </div>
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}
