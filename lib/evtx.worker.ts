/// <reference lib="webworker" />

import init, {
  EvtxHandle,
  init_panic_hook,
} from "@/lib/evtx-wasm/evtx_wasm.js";
import { SigmaAborted, parseCustom, runSigma } from "@/lib/sigma/runner";
import type { SigmaBundle } from "@/lib/sigma/types";

// Every message targets one parsed file, identified by `fileId`. The worker
// keeps a handle per file so several EVTX files can be queried (lazy XML,
// EventData) at once without re-parsing — see EvtxClient on the main thread.
type LoadMsg = { id: number; type: "load"; fileId: number; buffer: ArrayBuffer };
type XmlMsg = { id: number; type: "xml"; fileId: number; index: number };
type XmlBatchMsg = {
  id: number;
  type: "xml_batch";
  fileId: number;
  indices: number[];
};
type EventDataMsg = {
  id: number;
  type: "event_data";
  fileId: number;
  index: number;
};
type EventDataBatchMsg = {
  id: number;
  type: "event_data_batch";
  fileId: number;
  indices: number[];
};
type FreeMsg = { id: number; type: "free"; fileId: number };
// Sigma: run the bundled SigmaHQ rules (+ the analyst's own YAML) over the
// given files, in order; `offsets[i]` is file i's first global row index.
type SigmaRunMsg = {
  id: number;
  type: "sigma_run";
  fileIds: number[];
  offsets: number[];
  custom: string[];
};
type SigmaValidateMsg = { id: number; type: "sigma_validate"; text: string };
type Incoming =
  | SigmaRunMsg
  | SigmaValidateMsg
  | LoadMsg
  | XmlMsg
  | XmlBatchMsg
  | EventDataMsg
  | EventDataBatchMsg
  | FreeMsg;

type EventRow = {
  record_id: number | bigint;
  timestamp: string;
  level: number | null;
  event_id: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
};

const handles = new Map<number, EvtxHandle>();

// The rule bundle (~3 MB JSON) is its own chunk, fetched from this origin
// the first time Sigma runs — never on plain parsing.
let sigmaBundle: Promise<SigmaBundle> | null = null;
function loadSigmaBundle(): Promise<SigmaBundle> {
  sigmaBundle ??= import("@/lib/sigma/sigmahq-rules.json").then(
    (m) => (m.default ?? m) as unknown as SigmaBundle,
  );
  return sigmaBundle;
}
// A newer run supersedes an older one (files added/removed mid-run).
let sigmaRun = 0;
const yieldToQueue = () => new Promise<void>((r) => setTimeout(r, 0));
let ready: Promise<void> | null = null;

function ensureInit(): Promise<void> {
  if (!ready) {
    ready = init({ module_or_path: "/evtx_wasm_bg.wasm" }).then(() => {
      init_panic_hook();
    });
  }
  return ready;
}

function handleFor(fileId: number): EvtxHandle {
  const h = handles.get(fileId);
  if (!h) throw new Error("EVTX not loaded");
  return h;
}

self.onmessage = async (e: MessageEvent<Incoming>) => {
  const msg = e.data;
  try {
    if (msg.type === "sigma_validate") {
      const { rules, errors } = parseCustom([msg.text]);
      self.postMessage({
        id: msg.id,
        type: "sigma_validated",
        rules: rules.map(({ detection: _d, ...m }) => (void _d, m)),
        errors,
      });
      return;
    }
    await ensureInit();
    if (msg.type === "sigma_run") {
      const run = ++sigmaRun;
      const bundle = await loadSigmaBundle();
      const sources = msg.fileIds.map((fileId, i) => {
        const h = handleFor(fileId);
        return {
          offset: msg.offsets[i],
          count: Number(h.count()),
          rows: (start: number, len: number) =>
            h.get_chunk(BigInt(start), BigInt(len)) as EventRow[],
          pairs: (start: number, len: number) => {
            const idx = new Uint32Array(len);
            for (let k = 0; k < len; k++) idx[k] = start + k;
            return h.get_event_data_batch(idx) as [string, string][][];
          },
        };
      });
      let last = 0;
      try {
        const result = await runSigma({
          bundle,
          customTexts: msg.custom,
          sources,
          aborted: () => run !== sigmaRun,
          pause: yieldToQueue,
          onProgress: (done, total) => {
            const now = Date.now();
            if (now - last < 100 && done < total) return;
            last = now;
            self.postMessage({ id: msg.id, type: "progress", done, total });
          },
        });
        self.postMessage({ id: msg.id, type: "sigma_result", result });
      } catch (err) {
        if (err instanceof SigmaAborted) {
          self.postMessage({ id: msg.id, type: "sigma_aborted" });
          return;
        }
        throw err;
      }
      return;
    }
    if (msg.type === "load") {
      handles.get(msg.fileId)?.free();
      const handle = new EvtxHandle(new Uint8Array(msg.buffer));
      handles.set(msg.fileId, handle);
      const count = Number(handle.count());
      const rows =
        count > 0
          ? (handle.get_chunk(BigInt(0), BigInt(count)) as EventRow[])
          : [];
      const topEventIds = handle.event_id_counts() as Array<[number, number]>;
      self.postMessage({
        id: msg.id,
        type: "loaded",
        count,
        rows,
        topEventIds: topEventIds.slice(0, 50),
      });
    } else if (msg.type === "xml") {
      const xml = handleFor(msg.fileId).get_xml(BigInt(msg.index));
      self.postMessage({ id: msg.id, type: "xml", xml });
    } else if (msg.type === "xml_batch") {
      const h = handleFor(msg.fileId);
      const xmls = msg.indices.map((i) => {
        try {
          return h.get_xml(BigInt(i));
        } catch {
          return "";
        }
      });
      self.postMessage({ id: msg.id, type: "xml_batch", xmls });
    } else if (msg.type === "event_data") {
      const pairs = handleFor(msg.fileId).get_event_data(BigInt(msg.index)) as [
        string,
        string,
      ][];
      self.postMessage({ id: msg.id, type: "event_data", pairs });
    } else if (msg.type === "event_data_batch") {
      const arr = Uint32Array.from(msg.indices);
      const pairs = handleFor(msg.fileId).get_event_data_batch(arr) as [
        string,
        string,
      ][][];
      self.postMessage({ id: msg.id, type: "event_data_batch", pairs });
    } else if (msg.type === "free") {
      handles.get(msg.fileId)?.free();
      handles.delete(msg.fileId);
      self.postMessage({ id: msg.id, type: "freed" });
    }
  } catch (err) {
    self.postMessage({
      id: msg.id,
      type: "error",
      message: err instanceof Error ? err.message : String(err),
    });
  }
};
