import { readFileSync } from "node:fs";
import { join } from "node:path";

import { EvtxHandle, initSync } from "@/lib/evtx-wasm/evtx_wasm.js";
import type { EventRow } from "@/lib/evtx-client";
import { haystackFor } from "@/lib/search-query";

const ROOT = join(__dirname, "..");
const FIXTURES = join(ROOT, "tests/fixtures/evtx");

let wasmReady = false;
function ensureWasm() {
  if (wasmReady) return;
  initSync({ module: readFileSync(join(ROOT, "lib/evtx-wasm/evtx_wasm_bg.wasm")) });
  wasmReady = true;
}

export const FIXTURE_FILES = [
  "security.evtx",
  "application.evtx",
  "system.evtx",
  "setup.evtx",
  "hardware-events.evtx",
  "internet-explorer.evtx",
  "key-management-service.evtx",
] as const;
export type FixtureName = (typeof FIXTURE_FILES)[number];

/** Row shape the app builds (IndexedRow minus worker bookkeeping). */
export type Row = EventRow & { _g: number; _file: string };

export type Dataset = {
  rows: Row[];
  pairs: [string, string][][];
  handles: Map<string, EvtxHandle>;
};

const cache = new Map<string, Dataset>();

/**
 * Parse fixtures with the same WASM build the site ships, merged the way
 * EvtxUploader merges multiple files (global index `_g`).
 */
export function loadFixtures(...names: FixtureName[]): Dataset {
  const key = names.join("|");
  const hit = cache.get(key);
  if (hit) return hit;
  ensureWasm();
  const rows: Row[] = [];
  const pairs: [string, string][][] = [];
  const handles = new Map<string, EvtxHandle>();
  for (const name of names) {
    const handle = new EvtxHandle(new Uint8Array(readFileSync(join(FIXTURES, name))));
    handles.set(name, handle);
    const n = Number(handle.count());
    if (n === 0) continue;
    const chunk = handle.get_chunk(BigInt(0), BigInt(n)) as EventRow[];
    const data = handle.get_event_data_batch(
      Uint32Array.from({ length: n }, (_, i) => i),
    ) as [string, string][][];
    for (let i = 0; i < n; i++) {
      rows.push({ ...chunk[i], _g: rows.length, _file: name });
      pairs.push(data[i]);
    }
  }
  const ds = { rows, pairs, handles };
  cache.set(key, ds);
  return ds;
}

/** Haystack accessor matching the app's lazy per-row cache. */
export function haystackGetter(ds: Dataset) {
  const memo: string[] = [];
  return (r: Row) => (memo[r._g] ??= haystackFor(r, ds.pairs[r._g] ?? []));
}

/** Synthetic row for rule tests. */
export function fakeRow(eventId: number, provider: string): Row {
  return {
    record_id: 1,
    timestamp: "2026-01-01T00:00:00.000000+00:00",
    level: 4,
    event_id: eventId,
    provider,
    channel: "x",
    computer: "host",
    _g: 0,
    _file: "f.evtx",
  };
}
