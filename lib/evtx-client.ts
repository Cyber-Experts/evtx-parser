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

  load(
    buffer: ArrayBuffer,
  ): Promise<{ count: number; rows: EventRow[]; topEventIds: EventIdCount[] }> {
    return this.send({ type: "load", buffer }, [buffer]);
  }

  xml(index: number): Promise<{ xml: string }> {
    return this.send({ type: "xml", index });
  }

  xmlBatch(indices: number[]): Promise<{ xmls: string[] }> {
    return this.send({ type: "xml_batch", indices });
  }

  eventData(index: number): Promise<{ pairs: [string, string][] }> {
    return this.send({ type: "event_data", index });
  }

  eventDataBatch(
    indices: number[],
  ): Promise<{ pairs: [string, string][][] }> {
    return this.send({ type: "event_data_batch", indices });
  }

  terminate() {
    this.worker.terminate();
  }
}
