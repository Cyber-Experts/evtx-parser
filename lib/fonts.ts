import { Geist, Geist_Mono } from "next/font/google";

// Geist: a neutral, precise grotesk for UI and display, with a matching mono
// for event data, IDs and labels. Self-hosted by next/font at build time (no
// runtime requests). The OG renderer uses the same faces from assets/fonts.
export const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  display: "swap",
});

export const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
  display: "swap",
});

export const fontVariables = `${geistSans.variable} ${geistMono.variable}`;
