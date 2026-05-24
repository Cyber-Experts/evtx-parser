/// <reference lib="webworker" />

import init, {
  EvtxHandle,
  init_panic_hook,
} from "@/lib/evtx-wasm/evtx_wasm.js";

type LoadMsg = { id: number; type: "load"; buffer: ArrayBuffer };
type XmlMsg = { id: number; type: "xml"; index: number };
type XmlBatchMsg = { id: number; type: "xml_batch"; indices: number[] };
type EventDataMsg = { id: number; type: "event_data"; index: number };
type EventDataBatchMsg = {
  id: number;
  type: "event_data_batch";
  indices: number[];
};
type Incoming =
  | LoadMsg
  | XmlMsg
  | XmlBatchMsg
  | EventDataMsg
  | EventDataBatchMsg;

type EventRow = {
  record_id: number | bigint;
  timestamp: string;
  level: number | null;
  event_id: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
};

let handle: EvtxHandle | null = null;
let ready: Promise<void> | null = null;

function ensureInit(): Promise<void> {
  if (!ready) {
    ready = init({ module_or_path: "/evtx_wasm_bg.wasm" }).then(() => {
      init_panic_hook();
    });
  }
  return ready;
}

self.onmessage = async (e: MessageEvent<Incoming>) => {
  const msg = e.data;
  try {
    await ensureInit();
    if (msg.type === "load") {
      handle?.free();
      handle = new EvtxHandle(new Uint8Array(msg.buffer));
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
      if (!handle) throw new Error("EVTX not loaded");
      const xml = handle.get_xml(BigInt(msg.index));
      self.postMessage({ id: msg.id, type: "xml", xml });
    } else if (msg.type === "xml_batch") {
      if (!handle) throw new Error("EVTX not loaded");
      const h = handle;
      const xmls = msg.indices.map((i) => {
        try {
          return h.get_xml(BigInt(i));
        } catch {
          return "";
        }
      });
      self.postMessage({ id: msg.id, type: "xml_batch", xmls });
    } else if (msg.type === "event_data") {
      if (!handle) throw new Error("EVTX not loaded");
      const pairs = handle.get_event_data(BigInt(msg.index)) as [
        string,
        string,
      ][];
      self.postMessage({ id: msg.id, type: "event_data", pairs });
    } else if (msg.type === "event_data_batch") {
      if (!handle) throw new Error("EVTX not loaded");
      const arr = Uint32Array.from(msg.indices);
      const pairs = handle.get_event_data_batch(arr) as [string, string][][];
      self.postMessage({ id: msg.id, type: "event_data_batch", pairs });
    }
  } catch (err) {
    self.postMessage({
      id: msg.id,
      type: "error",
      message: err instanceof Error ? err.message : String(err),
    });
  }
};
