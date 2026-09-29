"use client";

// AutoEvents — portfolio-wide custom events for Vercel Web Analytics, with no
// per-page code. Drop <AutoEvents /> once in the root layout (next to
// <Analytics />). It listens with event delegation and sends:
//
//   sister_link_click  {to, where}        link to another portfolio site
//   outbound_click     {to}               link to any other external site
//   copy               {what, via}        clipboard copy (selection or copy button)
//   search             {via}              site search submitted/typed (query text is never sent)
//   file_selected      {ext, via}         a file picked or dropped into a tool
//   <data-event>       {data-event-*}     any element with data-event="name" (CTAs, book_call…)
//
// Guardrails: max 2 props per event (Vercel limit on some plans), no user
// text/PII, identical events de-duplicated within 1s, at most 40 events per
// page view. Sites keep their own explicit track() calls (parse_file, export…)
// for tool actions that can't be inferred from the DOM.
//
// Source of truth: github.com/Cyber-Experts/sister-links packages/auto-events.
// Vendored copy — edit upstream, then re-sync. Generated domain list below.

import { useEffect } from "react";
import { track } from "@vercel/analytics";

// 142 portfolio domains, generated 2026-09-29 from registry/sites.json
const PORTFOLIO: string[] = [
  "activedirectoryhardening.com",
  "amcacheparser.com",
  "article14.fr",
  "artificialintelligencelibrary.com",
  "attackpaths.org",
  "aurelienamette.com",
  "awsforensics.com",
  "azureforensics.app",
  "bamdamparser.com",
  "bathyl.com",
  "binaryexploitation.org",
  "blockchainbreaches.com",
  "blockchaincourses.org",
  "blockchainctf.com",
  "blockchainglossary.org",
  "blockchainposts.com",
  "blockchainsexperts.io",
  "blockchainshelf.com",
  "blockchainslibrary.com",
  "borromic.com",
  "browserforensics.app",
  "bruteforcetool.com",
  "centridae.com",
  "computerinternals.app",
  "crampous-mad.fr",
  "cyberbook.fr",
  "cyberbreaches.org",
  "cybercertifications.app",
  "cybercheatsheets.org",
  "cyberchronicle.org",
  "cybercompliance.app",
  "cybercosts.com",
  "cybercourses.com",
  "cyberctf.org",
  "cyberdora.org",
  "cyberevents.app",
  "cyberexperts.io",
  "cyberexploits.org",
  "cybergdpr.org",
  "cyberglossary.org",
  "cyberhardware.org",
  "cyberinstagram.com",
  "cyberinterviewquestions.org",
  "cyberlibrary.com",
  "cybermemes.org",
  "cybernis2.com",
  "cyberpodcasts.org",
  "cyberschools.app",
  "cybershelf.org",
  "cyberstars.org",
  "cybertabletop.org",
  "cyberteachers.org",
  "cybertoolbox.app",
  "cybertoys.fr",
  "cyberwordlists.com",
  "cyberwriteups.org",
  "cyberyoutube.com",
  "cyphra.co",
  "cyphra.dev",
  "datapack.app",
  "defaultcredentials.org",
  "diskimageparser.com",
  "evtxparser.com",
  "f4k.fr",
  "fakgroup.co",
  "fakrealty.com",
  "faksight.com",
  "fishi.email",
  "gcpforensics.com",
  "githubforensics.com",
  "googleworkspaceforensics.com",
  "hackerculture.org",
  "hackerposts.org",
  "hackersminds.com",
  "hackerspirit.com",
  "hashesgenerator.com",
  "hashextractor.com",
  "hashidentifier.com",
  "jumplistparser.com",
  "jwttool.com",
  "killteam.org",
  "kubernetesforensics.com",
  "linuxforensics.app",
  "linuxhardening.com",
  "linuxinternals.app",
  "linuxsyscalls.com",
  "lnkparser.com",
  "logfileparser.com",
  "m365forensics.com",
  "macforensics.app",
  "machardening.com",
  "macinternals.app",
  "macsyscalls.com",
  "malwaredevelopment.com",
  "malwarewiki.com",
  "mavalorisation.com",
  "messagingforensics.com",
  "mftparser.com",
  "newsinformatique.com",
  "next-md-blog.com",
  "oktaforensics.com",
  "pagefilesysparser.com",
  "pcapparser.com",
  "peparser.com",
  "powershellparser.com",
  "prefetchparser.com",
  "promptinjectionpayloads.com",
  "protocolports.org",
  "ramparser.com",
  "rdpcacheparser.com",
  "recentfilecacheparser.com",
  "recyclebinparser.com",
  "registryparser.com",
  "reverseengineering.app",
  "reverseshell.app",
  "scheduledtasksparser.com",
  "secretsdump.com",
  "seedphraserecovery.com",
  "shellbagsparser.com",
  "shellcodes.app",
  "shimcacheparser.com",
  "sootmark.com",
  "sqlipayloads.com",
  "srumparser.com",
  "ssrfpayloads.com",
  "synthaea.com",
  "technologylibrary.fr",
  "thumbcacheparser.com",
  "usbforensics.com",
  "usnparser.com",
  "vulnerabilityoperationcenter.org",
  "webshells.app",
  "windowsforensics.app",
  "windowshardening.org",
  "windowsinternals.app",
  "windowsnotificationparser.com",
  "windowssearchparser.com",
  "windowssyscalls.com",
  "windowstimelineparser.com",
  "wmiparser.com",
  "xsspayloads.app",
  "yararules.org"
];

type Props = Record<string, string | number | boolean | null>;

const MAX_PER_PAGE = 40;
// \b only works next to ASCII word chars, so CJK words are matched without it.
const COPY_WORDS = /\b(copy|copier|copiar|kopieren|copia)\b|コピー|复制|複製/i;

const bareHost = (h: string) => h.toLowerCase().replace(/^www\./, "");

function where(el: Element): string {
  if (el.closest("[data-related-tools]")) return "related";
  if (el.closest("header, nav")) return "nav";
  if (el.closest("footer")) return "footer";
  if (el.closest("aside")) return "aside";
  return "content";
}

function copyContext(el: Element | null): string {
  if (!el) return "text";
  if (el.closest("pre, code")) return "code";
  if (el.closest("table")) return "table";
  if (el.closest("input, textarea")) return "field";
  return "text";
}

export function AutoEvents() {
  useEffect(() => {
    const portfolio = new Set(PORTFOLIO.map(bareHost));
    const self = bareHost(location.hostname);
    let sent = 0;
    const last = new Map<string, number>();
    const send = (name: string, props: Props) => {
      const key = name + JSON.stringify(props);
      const now = Date.now();
      if (sent >= MAX_PER_PAGE || now - (last.get(key) ?? 0) < 1000) return;
      last.set(key, now);
      sent++;
      try {
        track(name, props);
      } catch {
        /* analytics must never break the page */
      }
    };

    const onClick = (e: MouseEvent) => {
      const t = e.target as Element | null;
      if (!t || !(t instanceof Element)) return;

      // Explicit opt-in events: <button data-event="book_call" data-event-plan="pro">.
      const tagged = t.closest<HTMLElement>("[data-event]");
      if (tagged?.dataset.event) {
        const props: Props = {};
        for (const [k, v] of Object.entries(tagged.dataset)) {
          if (k.startsWith("event") && k !== "event" && Object.keys(props).length < 2) {
            props[k.slice(5, 6).toLowerCase() + k.slice(6)] = v ?? null;
          }
        }
        send(tagged.dataset.event, props);
      }

      // Copy buttons (clipboard API calls don't fire the DOM "copy" event).
      // Skipped when the click already produced an explicit data-event
      // (e.g. data-event="copy_credential"), so one click = one event.
      const btn = t.closest("button, [role=button]");
      if (btn && !tagged?.dataset.event && COPY_WORDS.test(`${btn.getAttribute("aria-label") ?? ""} ${btn.getAttribute("title") ?? ""} ${btn.textContent ?? ""}`)) {
        send("copy", { what: copyContext(btn.parentElement), via: "button" });
      }

      const a = t.closest<HTMLAnchorElement>("a[href]");
      if (!a) return;
      let url: URL;
      try {
        url = new URL(a.href, location.href);
      } catch {
        return;
      }
      if (!/^https?:$/.test(url.protocol)) return;
      const host = bareHost(url.hostname);
      if (host === self) return;
      if (portfolio.has(host)) send("sister_link_click", { to: host, where: where(a) });
      else send("outbound_click", { to: host });
    };

    const onCopy = () => {
      const sel = document.getSelection();
      const node = sel?.anchorNode;
      const el = node ? (node.nodeType === 1 ? (node as Element) : node.parentElement) : null;
      send("copy", { what: copyContext(el), via: "selection" });
    };

    const onSubmit = (e: SubmitEvent) => {
      const form = e.target as HTMLFormElement | null;
      if (form?.querySelector('input[type=search], input[name=q], input[name=query], input[name=s], [role=searchbox]')) {
        send("search", { via: "submit" });
      }
    };

    // Instant search boxes without a submit: count one search per box after
    // the visitor pauses typing (≥3 chars). The text itself is never sent.
    const typed = new WeakSet<Element>();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onInput = (e: Event) => {
      const el = e.target as HTMLInputElement | null;
      if (!el || !el.matches('input[type=search], [role=searchbox], input[name=q], input[name=query]')) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (el.value.trim().length >= 3 && !typed.has(el)) {
          typed.add(el);
          send("search", { via: "typing" });
        }
      }, 1500);
    };

    const ext = (name: string) => (name.includes(".") ? name.split(".").pop()!.toLowerCase().slice(0, 12) : "none");
    const onChange = (e: Event) => {
      const el = e.target as HTMLInputElement | null;
      if (el?.type === "file" && el.files?.length) send("file_selected", { ext: ext(el.files[0].name), via: "picker" });
    };
    const onDrop = (e: DragEvent) => {
      const f = e.dataTransfer?.files?.[0];
      if (f) send("file_selected", { ext: ext(f.name), via: "drop" });
    };

    document.addEventListener("click", onClick, { capture: true });
    document.addEventListener("copy", onCopy);
    document.addEventListener("submit", onSubmit, { capture: true });
    document.addEventListener("input", onInput, { capture: true });
    document.addEventListener("change", onChange, { capture: true });
    window.addEventListener("drop", onDrop, { capture: true });
    return () => {
      clearTimeout(timer);
      document.removeEventListener("click", onClick, { capture: true });
      document.removeEventListener("copy", onCopy);
      document.removeEventListener("submit", onSubmit, { capture: true });
      document.removeEventListener("input", onInput, { capture: true });
      document.removeEventListener("change", onChange, { capture: true });
      window.removeEventListener("drop", onDrop, { capture: true });
    };
  }, []);
  return null;
}

export default AutoEvents;
