export type EventRow = {
  record_id: number | bigint;
  timestamp: string;
  level: number | null;
  event_id: number | null;
  provider: string | null;
  channel: string | null;
  computer: string | null;
};

export type EventIdCount = [eventId: number, count: number];

type Pending = {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
};

export class EvtxClient {
  private worker: Worker;
  private nextId = 1;
  private pending = new Map<number, Pending>();

  constructor() {
    this.worker = new Worker(
      new URL("./evtx.worker.ts", import.meta.url),
      { type: "module" },
    );
    this.worker.onmessage = (e) => {
      const { id, type, ...rest } = e.data;
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      if (type === "error") {
        p.reject(new Error(rest.message));
      } else {
        p.resolve(rest);
      }
    };
  }

  private send<T>(msg: object, transfer?: Transferable[]): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.worker.postMessage({ id, ...msg }, transfer ?? []);
    });
  }

  // Each parsed file is addressed by a caller-chosen `fileId` so a single
  // worker can hold several loaded EVTX files at once (multi-file import).
  load(
    fileId: number,
    buffer: ArrayBuffer,
  ): Promise<{ count: number; rows: EventRow[]; topEventIds: EventIdCount[] }> {
    return this.send({ type: "load", fileId, buffer }, [buffer]);
  }

  xml(fileId: number, index: number): Promise<{ xml: string }> {
    return this.send({ type: "xml", fileId, index });
  }

  xmlBatch(fileId: number, indices: number[]): Promise<{ xmls: string[] }> {
    return this.send({ type: "xml_batch", fileId, indices });
  }

  eventData(
    fileId: number,
    index: number,
  ): Promise<{ pairs: [string, string][] }> {
    return this.send({ type: "event_data", fileId, index });
  }

  eventDataBatch(
    fileId: number,
    indices: number[],
  ): Promise<{ pairs: [string, string][][] }> {
    return this.send({ type: "event_data_batch", fileId, indices });
  }

  // Release a single file's handle when the user removes it from the session.
  free(fileId: number): Promise<unknown> {
    return this.send({ type: "free", fileId });
  }

  terminate() {
    this.worker.terminate();
  }
}
