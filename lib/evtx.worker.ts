/// <reference lib="webworker" />

import init, {
  EvtxHandle,
  init_panic_hook,
} from "@/lib/evtx-wasm/evtx_wasm.js";

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
type Incoming =
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
    await ensureInit();
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
