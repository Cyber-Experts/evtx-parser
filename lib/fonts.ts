import { Instrument_Serif, Inter, JetBrains_Mono } from "next/font/google";

// "Flare" type system. Inter carries the UI and headings (set tight, with
// its single-storey "a" and flat-top "1" alternates for a technical voice),
// Instrument Serif italic is the editorial accent used once per hero, and
// JetBrains Mono renders event data. Self-hosted by next/font at build time.
export const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

export const instrumentSerif = Instrument_Serif({
  variable: "--font-instrument",
  subsets: ["latin"],
  weight: "400",
  style: ["italic", "normal"],
  display: "swap",
});

export const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

export const fontVariables = `${inter.variable} ${instrumentSerif.variable} ${jetbrainsMono.variable}`;
