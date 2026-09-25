import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ImageResponse } from "next/og";

import { getDict } from "@/src/dict";
import type { Locale } from "@/src/dict/locales";

export const ogSize = { width: 1200, height: 630 };
export const ogContentType = "image/png";

// "Alternate Light Source" palette (see app/globals.css).
const INK = "#0a0b14";
const INK_TEXT = "#e8e9f2";
const INK_MUTED = "#9ca1ba";
const INK_FAINT = "#666c88";
const UV = "#9772ff";
const GLOW = "#bdf01e";

// Plex fonts bundled in assets/fonts (OFL) — read from disk, never fetched,
// so images render offline too (Docker / air-gapped builds).
let fontsPromise: Promise<NonNullable<ConstructorParameters<typeof ImageResponse>[1]>["fonts"]> | null =
  null;
function loadFonts() {
  const read = (file: string) => readFile(join(process.cwd(), "assets/fonts", file));
  fontsPromise ??= Promise.all([
    read("IBMPlexSans-Regular.woff"),
    read("IBMPlexSans-SemiBold.woff"),
    read("IBMPlexMono-Regular.woff"),
    read("IBMPlexMono-SemiBold.woff"),
    read("IBMPlexSansCondensed-Bold.woff"),
  ]).then(([sans, sansSemi, mono, monoSemi, condensed]) => [
    { name: "Plex Sans", data: sans, weight: 400 as const, style: "normal" as const },
    { name: "Plex Sans", data: sansSemi, weight: 600 as const, style: "normal" as const },
    { name: "Plex Mono", data: mono, weight: 400 as const, style: "normal" as const },
    { name: "Plex Mono", data: monoSemi, weight: 600 as const, style: "normal" as const },
    { name: "Plex Condensed", data: condensed, weight: 700 as const, style: "normal" as const },
  ]);
  return fontsPromise;
}

// The brand mark (lens over an event histogram), transparent background.
const MARK = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <defs><clipPath id="l"><circle cx="13.5" cy="13.5" r="9.5"/></clipPath></defs>
  <g clip-path="url(#l)">
    <rect x="6" y="15" width="3" height="10" rx="1" fill="${INK_TEXT}" opacity="0.4"/>
    <rect x="10.5" y="10" width="3" height="15" rx="1" fill="${INK_TEXT}" opacity="0.6"/>
    <rect x="15" y="6" width="3" height="19" rx="1" fill="${GLOW}"/>
    <rect x="19.5" y="12" width="3" height="13" rx="1" fill="${INK_TEXT}" opacity="0.5"/>
  </g>
  <circle cx="13.5" cy="13.5" r="10.5" fill="none" stroke="${UV}" stroke-width="2.6"/>
  <line x1="21.3" y1="21.3" x2="28.5" y2="28.5" stroke="${UV}" stroke-width="3.4" stroke-linecap="round"/>
</svg>`;
const MARK_SRC = `data:image/svg+xml;base64,${Buffer.from(MARK).toString("base64")}`;

// A few plausible log lines; the last one "fluoresces" under the lamp.
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
        background: INK,
        backgroundImage:
          "radial-gradient(780px 520px at 92% -8%, rgba(123,76,255,0.42), transparent 62%), radial-gradient(600px 420px at -6% 112%, rgba(123,76,255,0.14), transparent 60%)",
        padding: "60px 68px 54px",
        color: INK_TEXT,
        fontFamily: "Plex Sans",
      }}
    >
      {/* faint log-line rules — the case file under the lamp */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          backgroundImage:
            "repeating-linear-gradient(0deg, rgba(214,208,255,0.035) 0px, rgba(214,208,255,0.035) 1px, transparent 1px, transparent 38px)",
        }}
      />

      {/* brand */}
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        {/* Rendered to PNG by Satori, not the browser: next/image doesn't apply. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={MARK_SRC} width={54} height={54} alt="" />
        <div style={{ display: "flex", fontFamily: "Plex Mono", fontSize: 30, letterSpacing: "-0.02em" }}>
          <span style={{ fontWeight: 600, color: INK_TEXT }}>evtx</span>
          <span style={{ color: UV }}>parser</span>
        </div>
        <div style={{ display: "flex", marginLeft: "auto", fontFamily: "Plex Mono", fontSize: 22, color: INK_FAINT }}>
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
        gap: 6,
        fontFamily: "Plex Mono",
        fontSize: 21,
        borderTop: "1px solid rgba(214,208,255,0.12)",
        paddingTop: 18,
      }}
    >
      {ROWS.map((r) => (
        <div
          key={r.id}
          style={{
            display: "flex",
            gap: 24,
            padding: "6px 14px",
            borderRadius: 8,
            color: r.hit ? "#e2ff8a" : INK_FAINT,
            background: r.hit ? "rgba(189,240,30,0.12)" : "transparent",
            borderLeft: r.hit ? `4px solid ${GLOW}` : "4px solid transparent",
          }}
        >
          <span>{r.t}</span>
          <span style={{ fontWeight: 600, color: r.hit ? GLOW : INK_MUTED }}>{r.id}</span>
          <span>{r.text}</span>
        </div>
      ))}
    </div>
  );
}

/** Site-wide card: name + tagline + the glowing event strip. */
export async function renderOg(locale: Locale) {
  const dict = getDict(locale);
  return new ImageResponse(
    (
      <Frame footer={<EventStrip />}>
        <div style={{ display: "flex", flexDirection: "column", gap: 18, maxWidth: 1000 }}>
          <div
            style={{
              fontFamily: "Plex Condensed",
              fontWeight: 700,
              fontSize: 66,
              lineHeight: 1.04,
              letterSpacing: "-0.02em",
            }}
          >
            {dict.home.headline}
          </div>
          <div style={{ fontSize: 30, lineHeight: 1.35, color: INK_MUTED, maxWidth: 940 }}>
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
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 26,
              fontFamily: "Plex Mono",
              fontSize: 22,
              color: INK_FAINT,
              borderTop: "1px solid rgba(214,208,255,0.12)",
              paddingTop: 20,
            }}
          >
            <span style={{ display: "flex", alignItems: "center", gap: 10, color: GLOW }}>
              <span style={{ display: "flex", width: 10, height: 10, borderRadius: 10, background: GLOW }} />
              DFIR · Windows Event Logs
            </span>
            {minutes ? <span>{minutes} min read</span> : null}
            <span style={{ marginLeft: "auto" }}>{locale.toUpperCase()}</span>
          </div>
        }
      >
        <div style={{ display: "flex", flexDirection: "column", gap: 20, maxWidth: 1050 }}>
          <div
            style={{
              fontFamily: "Plex Condensed",
              fontWeight: 700,
              fontSize: titleSize,
              lineHeight: 1.05,
              letterSpacing: "-0.015em",
            }}
          >
            {title}
          </div>
          {description ? (
            <div style={{ fontSize: 27, lineHeight: 1.4, color: INK_MUTED, maxWidth: 1000 }}>
              {description.length > 170 ? `${description.slice(0, 167)}…` : description}
            </div>
          ) : null}
        </div>
      </Frame>
    ),
    { ...ogSize, fonts: await loadFonts() },
  );
}
