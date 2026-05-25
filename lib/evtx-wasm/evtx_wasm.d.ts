/* tslint:disable */
/* eslint-disable */

export class EvtxHandle {
    free(): void;
    [Symbol.dispose](): void;
    count(): bigint;
    event_id_counts(): any;
    get_chunk(start: bigint, len: bigint): any;
    get_event_data(index: bigint): any;
    get_event_data_batch(indices: Uint32Array): any;
    get_xml(index: bigint): string;
    constructor(buffer: Uint8Array);
}

export function init_panic_hook(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_evtxhandle_free: (a: number, b: number) => void;
    readonly evtxhandle_count: (a: number) => bigint;
    readonly evtxhandle_event_id_counts: (a: number) => [number, number, number];
    readonly evtxhandle_get_chunk: (a: number, b: bigint, c: bigint) => [number, number, number];
    readonly evtxhandle_get_event_data: (a: number, b: bigint) => [number, number, number];
    readonly evtxhandle_get_event_data_batch: (a: number, b: number, c: number) => [number, number, number];
    readonly evtxhandle_get_xml: (a: number, b: bigint) => [number, number, number, number];
    readonly evtxhandle_new: (a: number, b: number) => [number, number, number];
    readonly init_panic_hook: () => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
