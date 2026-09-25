import type { ReactNode } from "react";

// Shared page header for every inner page — the same "under the lamp" look as
// the home hero: ultraviolet haze, faint grid, eyebrow label, gradient title.
// Breadcrumbs (if any) go in `top`, CTAs / meta in `children`.

export function PageHero({
  eyebrow,
  title,
  intro,
  top,
  children,
  align = "left",
  size = "lg",
}: {
  eyebrow?: ReactNode;
  title: ReactNode;
  intro?: ReactNode;
  top?: ReactNode;
  children?: ReactNode;
  align?: "left" | "center";
  size?: "lg" | "md";
}) {
  const centered = align === "center";
  return (
    <header
      className={`relative isolate flex flex-col gap-4 pt-2 pb-2 sm:pt-6 ${
        centered ? "items-center text-center" : ""
      }`}
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-48 left-1/2 -z-10 h-[520px] w-[1100px] -translate-x-1/2 bg-[radial-gradient(closest-side,rgb(123_76_255/0.12),transparent)] dark:bg-[radial-gradient(closest-side,rgb(123_76_255/0.26),transparent)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-40 left-1/2 -z-10 h-[460px] w-[1200px] -translate-x-1/2 bg-[linear-gradient(to_right,rgb(123_76_255/0.07)_1px,transparent_1px),linear-gradient(to_bottom,rgb(123_76_255/0.07)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_45%_55%_at_50%_30%,black,transparent)] bg-[size:48px_48px]"
      />
      {top}
      {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
      <h1
        className={`text-gradient max-w-4xl leading-[1.05] font-semibold tracking-[-0.025em] text-balance ${
          size === "lg" ? "text-4xl sm:text-5xl" : "text-3xl sm:text-4xl"
        }`}
      >
        {title}
      </h1>
      {intro ? (
        <div
          className={`max-w-3xl text-base leading-relaxed text-ink-600 sm:text-lg dark:text-ink-400 ${
            centered ? "mx-auto" : ""
          }`}
        >
          {intro}
        </div>
      ) : null}
      {children}
    </header>
  );
}

/** Section title used below a PageHero (left-aligned counterpart of the home
 *  page's centred SectionHeading). */
export function SectionTitle({
  id,
  eyebrow,
  children,
}: {
  id?: string;
  eyebrow?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
      <h2 id={id} className="text-2xl tracking-[-0.015em] text-ink-950 dark:text-ink-50">
        {children}
      </h2>
    </div>
  );
}

/** Primary / secondary button styles shared with the home page. */
export const BTN_PRIMARY =
  "inline-flex items-center gap-2 rounded-xl bg-uv-600 px-5 py-2.5 text-sm font-semibold text-white shadow-[0_10px_30px_-10px_rgb(106_51_245/0.8),inset_0_1px_0_rgb(255_255_255/0.2)] transition hover:-translate-y-px hover:bg-uv-500 dark:bg-uv-500 dark:hover:bg-uv-400";
export const BTN_SECONDARY =
  "inline-flex items-center gap-2 rounded-xl border border-ink-200 bg-card/70 px-5 py-2.5 text-sm font-medium text-ink-800 backdrop-blur transition hover:border-ink-300 hover:bg-card dark:border-ink-800 dark:text-ink-200 dark:hover:border-ink-700";
