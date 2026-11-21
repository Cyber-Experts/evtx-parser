import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ImageResponse } from "next/og";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

// "Luminol" palette (see app/globals.css).
const BG = "#08090b";
const TEXT = "#ededf0";
const MUTED = "#979eaa";
const FAINT = "#6b727f";
const COBALT = "#3a6bff";
const COBALT_SOFT = "#90b6ff";
const LUMINOL = "#22d6f0";
const LUMINOL_SOFT = "#a2f5fd";
const HAIRLINE = "rgba(255,255,255,0.09)";

// Geist (OFL) bundled in assets/fonts — read from disk, never fetched, so
// images render offline too (Docker / air-gapped builds).
let fontsPromise: Promise<NonNullable<ConstructorParameters<typeof ImageResponse>[1]>["fonts"]> | null =
  null;
function loadFonts() {
  const read = (file: string) => readFile(join(process.cwd(), "assets/fonts", file));
  fontsPromise ??= Promise.all([
    read("Geist-Regular.ttf"),
    read("Geist-SemiBold.ttf"),
    read("GeistMono-Regular.ttf"),
    read("GeistMono-Medium.ttf"),
  ]).then(([sans, sansSemi, mono, monoMed]) => [
    { name: "Geist", data: sans, weight: 400 as const, style: "normal" as const },
    { name: "Geist", data: sansSemi, weight: 600 as const, style: "normal" as const },
    { name: "Geist Mono", data: mono, weight: 400 as const, style: "normal" as const },
    { name: "Geist Mono", data: monoMed, weight: 500 as const, style: "normal" as const },
  ]);
  return fontsPromise;
}

// The brand mark (graphite tile, log lines, one lit) — same as app/icon.svg.
const MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="${COBALT}"/><stop offset="1" stop-color="${LUMINOL}"/></linearGradient></defs>
  <rect width="64" height="64" rx="15" fill="#16181d"/>
  <rect x="0.75" y="0.75" width="62.5" height="62.5" rx="14.25" fill="none" stroke="#ffffff" stroke-opacity="0.14" stroke-width="1.5"/>
  <rect x="14" y="16" width="22" height="6" rx="3" fill="${TEXT}" opacity="0.4"/>
  <rect x="14" y="25" width="30" height="6" rx="3" fill="${TEXT}" opacity="0.6"/>
  <rect x="14" y="34" width="36" height="6" rx="3" fill="url(#g)"/>
  <rect x="14" y="43" width="16" height="6" rx="3" fill="${TEXT}" opacity="0.4"/>
</svg>`;
const MARK_SRC = `data:image/svg+xml;base64,${Buffer.from(MARK).toString("base64")}`;

// Hairline grid fading downwards, a cobalt glow top-right and a faint
// luminol glow under the event strip.
const BACKDROP = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <pattern id="grid" width="56" height="56" patternUnits="userSpaceOnUse">
      <path d="M56 0H0V56" fill="none" stroke="#ffffff" stroke-opacity="0.055" stroke-width="1"/>
    </pattern>
    <linearGradient id="fade" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fff" stop-opacity="1"/>
      <stop offset="0.85" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
    <mask id="m"><rect width="1200" height="630" fill="url(#fade)"/></mask>
    <radialGradient id="cobalt" cx="1080" cy="-40" r="620" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="${COBALT}" stop-opacity="0.5"/>
      <stop offset="0.45" stop-color="${COBALT}" stop-opacity="0.14"/>
      <stop offset="1" stop-color="${COBALT}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="luminol" cx="760" cy="700" r="460" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="${LUMINOL}" stop-opacity="0.16"/>
      <stop offset="1" stop-color="${LUMINOL}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1200" height="630" fill="${BG}"/>
  <rect width="1200" height="630" fill="url(#grid)" mask="url(#m)"/>
  <rect width="1200" height="630" fill="url(#cobalt)"/>
  <rect width="1200" height="630" fill="url(#luminol)"/>
</svg>`;
const BACKDROP_SRC = `data:image/svg+xml;base64,${Buffer.from(BACKDROP).toString("base64")}`;

// A few plausible log lines; one of them lights up.
const ROWS = [
  { t: "03:51:52.591", id: "4624", text: "Successful logon · jim.tomato · Interactive", hit: false },
  { t: "03:52:07.113", id: "4672", text: "Special privileges assigned · admin", hit: false },
  { t: "03:52:31.842", id: "4104", text: "Script block · IEX (New-Object Net.WebClient).Download…", hit: true },
];

function Frame({ children, footer }: { children: React.ReactNode; footer: React.ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        background: BG,
        padding: "56px 68px 52px",
        color: TEXT,
        fontFamily: "Geist",
      }}
    >
      {/* Backdrop as one SVG: Satori clips CSS radial gradients. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={BACKDROP_SRC}
        width={1200}
        height={630}
        alt=""
        style={{ position: "absolute", top: 0, left: 0 }}
      />

      {/* brand */}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {/* Rendered to PNG by Satori, not the browser: next/image doesn't apply. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={MARK_SRC} width={50} height={50} alt="" />
        <div style={{ display: "flex", fontSize: 31, letterSpacing: "-0.03em" }}>
          <span style={{ fontWeight: 600, color: TEXT }}>evtx</span>
          <span style={{ color: MUTED, marginLeft: 8 }}>parser</span>
        </div>
        <div
          style={{
            display: "flex",
            marginLeft: "auto",
            fontFamily: "Geist Mono",
            fontSize: 21,
            color: FAINT,
          }}
        >
          evtxparser.com
        </div>
      </div>

      {children}
      {footer}
    </div>
  );
}

function EventStrip() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 4,
        fontFamily: "Geist Mono",
        fontSize: 20,
        padding: 10,
        borderRadius: 16,
        border: `1px solid ${HAIRLINE}`,
        background: "rgba(255,255,255,0.025)",
      }}
    >
      {ROWS.map((r) => (
        <div
          key={r.id}
          style={{
            display: "flex",
            gap: 24,
            padding: "8px 14px",
            borderRadius: 9,
            color: r.hit ? LUMINOL_SOFT : FAINT,
            background: r.hit
              ? "linear-gradient(90deg, rgba(58,107,255,0.22), rgba(34,214,240,0.10))"
              : "transparent",
            border: r.hit ? "1px solid rgba(92,142,255,0.35)" : "1px solid transparent",
          }}
        >
          <span>{r.t}</span>
          <span style={{ fontWeight: 500, color: r.hit ? LUMINOL : MUTED }}>{r.id}</span>
          <span>{r.text}</span>
        </div>
      ))}
    </div>
  );
}

function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "6px 14px",
        borderRadius: 999,
        border: "1px solid rgba(92,142,255,0.35)",
        background: "rgba(58,107,255,0.12)",
        color: COBALT_SOFT,
      }}
    >
      <span style={{ display: "flex", width: 8, height: 8, borderRadius: 8, background: LUMINOL }} />
      {children}
    </span>
  );
}

const FOOTER_STYLE = {
  display: "flex",
  alignItems: "center",
  gap: 24,
  fontFamily: "Geist Mono",
  fontSize: 20,
  color: FAINT,
} as const;

const TITLE_STYLE = {
  fontWeight: 600,
  lineHeight: 1.02,
  letterSpacing: "-0.045em",
} as const;

/** Site-wide card: name + tagline + the glowing event strip. */
export async function renderOg(locale: Locale) {
  const dict = getDict(locale);
  return new ImageResponse(
    (
      <Frame footer={<EventStrip />}>
        <div style={{ display: "flex", flexDirection: "column", gap: 18, maxWidth: 1000 }}>
          <div
            style={{
              ...TITLE_STYLE,
              fontSize: 64,

            }}
          >
            {dict.home.headline}
          </div>
          <div style={{ fontSize: 27, lineHeight: 1.4, color: MUTED, maxWidth: 900 }}>
            {dict.meta.description}
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
  return new ImageResponse(
    (
      <Frame
        footer={
          <div style={FOOTER_STYLE}>
            <Tag>DFIR · Windows Event Logs</Tag>
            {minutes ? <span>{minutes} min read</span> : null}
            <span style={{ marginLeft: "auto" }}>{locale.toUpperCase()}</span>
          </div>
        }
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 1050 }}>
          <div
            style={{
              ...TITLE_STYLE,
              fontSize: titleSize,

            }}
          >
            {title}
          </div>
          {description ? (
            <div style={{ fontSize: 27, lineHeight: 1.4, color: MUTED, maxWidth: 1000 }}>
              {description.length > 170 ? `${description.slice(0, 167)}…` : description}
            </div>
          ) : null}
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}

/** Event ID encyclopedia card: the ID large, channel, title and summary. */
export async function renderEventOg(opts: {
  id: number;
  channel: string;
  title: string;
  summary: string;
  locale: Locale;
}) {
  const { id, channel, title, summary, locale } = opts;
  const titleSize = title.length > 60 ? 50 : title.length > 40 ? 58 : 66;
  return new ImageResponse(
    (
      <Frame
        footer={
          <div style={FOOTER_STYLE}>
            <Tag>Event ID encyclopedia</Tag>
            <span>{channel}</span>
            <span style={{ marginLeft: "auto" }}>{locale.toUpperCase()}</span>
          </div>
        }
      >
        <div style={{ display: "flex", alignItems: "center", gap: 44 }}>
          <div
            style={{
              display: "flex",
              fontFamily: "Geist Mono",
              fontWeight: 500,
              fontSize: String(id).length > 4 ? 112 : 150,
              letterSpacing: "-0.06em",
              color: LUMINOL,
              lineHeight: 1,
            }}
          >
            {id}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16, maxWidth: 720 }}>
            <div
              style={{
                ...TITLE_STYLE,
                fontSize: titleSize,

              }}
            >
              {title}
            </div>
            <div style={{ fontSize: 25, lineHeight: 1.4, color: MUTED }}>
              {summary.length > 150 ? `${summary.slice(0, 147)}…` : summary}
            </div>
          </div>
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}
