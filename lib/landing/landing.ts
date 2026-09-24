import type { LocaleContent } from "./locale-content";

/**
 * Shape shared by the single-intent SEO landing pages (converters, evtx_dump,
 * Mac/Linux). Rendered by components/landing/LandingPage.
 */
export type LandingContent = {
  metaTitle: string;
  metaDescription: string;
  h1: string;
  intro: string;
  ctaLabel: string;
  /** Section of name/body blocks (formats, options, comparisons…). */
  formatsHeading: string;
  formats: { name: string; body: string; code?: string }[];
  stepsHeading: string;
  steps: { title: string; body: string }[];
  faqHeading: string;
  faq: { q: string; a: string }[];
};

export const RELATED_HEADING: LocaleContent<string> = {
  en: "Related tools",
  fr: "Outils associés",
  de: "Verwandte Tools",
  es: "Herramientas relacionadas",
  it: "Strumenti correlati",
  pt: "Ferramentas relacionadas",
  ja: "関連ツール",
  zh: "相关工具",
};
