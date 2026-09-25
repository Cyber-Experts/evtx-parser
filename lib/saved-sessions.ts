// Save / restore an analysis session in this browser only (IndexedDB): the
// original .evtx files as Blobs plus the viewer state (search, filters,
// bookmarks, notes…). Nothing is sent anywhere — it's the same trust model as
// parsing: the evidence never leaves the machine.

const DB_NAME = "evtx-parser-sessions";
const DB_VERSION = 1;
const META = "meta";
const STATE = "state";
const BLOBS = "blobs";

export type SavedFileMeta = { name: string; size: number; lastModified: number };

export type SavedSessionMeta = {
  id: string;
  name: string;
  savedAt: number;
  files: SavedFileMeta[];
  totalSize: number;
  events: number;
};

/** Viewer state captured with a session. Kept loose: it is app-owned JSON. */
export type SessionSnapshot = {
  filter: string;
  regexMode: boolean;
  levels: number[];
  timeRange: [number, number] | null;
  query: unknown;
  bookmarks: number[];
  notes: Record<number, string>;
  sortField: string;
  sortDir: "asc" | "desc";
  view: "events" | "sessions";
  showFacets: boolean;
};

export class StorageFullError extends Error {}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(META)) db.createObjectStore(META, { keyPath: "id" });
      if (!db.objectStoreNames.contains(STATE)) db.createObjectStore(STATE);
      if (!db.objectStoreNames.contains(BLOBS)) db.createObjectStore(BLOBS);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () =>
      reject(
        tx.error?.name === "QuotaExceededError"
          ? new StorageFullError(tx.error.message)
          : (tx.error ?? new Error("IndexedDB transaction aborted")),
      );
    tx.onerror = () => reject(tx.error);
  });
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function sessionStorageAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}

export async function listSavedSessions(): Promise<SavedSessionMeta[]> {
  if (!sessionStorageAvailable()) return [];
  const db = await open();
  try {
    const all = await request(db.transaction(META).objectStore(META).getAll());
    return (all as SavedSessionMeta[]).sort((a, b) => b.savedAt - a.savedAt);
  } finally {
    db.close();
  }
}

const sameFiles = (a: SavedFileMeta[], files: File[]) =>
  a.length === files.length &&
  a.every(
    (m, i) =>
      m.name === files[i].name &&
      m.size === files[i].size &&
      m.lastModified === files[i].lastModified,
  );

/**
 * Save (or update) a session. Blobs are rewritten only when the file set
 * changed, so re-saving a large case after adding notes is instant.
 */
export async function saveSession(opts: {
  id?: string;
  files: File[];
  snapshot: SessionSnapshot;
  events: number;
}): Promise<SavedSessionMeta> {
  const id = opts.id ?? crypto.randomUUID();
  const totalSize = opts.files.reduce((s, f) => s + f.size, 0);

  // Ask for persistent storage so the browser doesn't evict a case under
  // pressure, and fail early when the files obviously won't fit.
  try {
    await navigator.storage?.persist?.();
    const est = await navigator.storage?.estimate?.();
    if (est?.quota != null && est.usage != null && est.quota - est.usage < totalSize) {
      throw new StorageFullError("quota");
    }
  } catch (err) {
    if (err instanceof StorageFullError) throw err;
  }

  const db = await open();
  try {
    const previous = (await request(db.transaction(META).objectStore(META).get(id))) as
      | SavedSessionMeta
      | undefined;
    const rewriteBlobs = !previous || !sameFiles(previous.files, opts.files);

    const meta: SavedSessionMeta = {
      id,
      name:
        opts.files.length > 1
          ? `${opts.files[0].name} +${opts.files.length - 1}`
          : (opts.files[0]?.name ?? "session"),
      savedAt: Date.now(),
      files: opts.files.map((f) => ({ name: f.name, size: f.size, lastModified: f.lastModified })),
      totalSize,
      events: opts.events,
    };

    const tx = db.transaction([META, STATE, BLOBS], "readwrite");
    tx.objectStore(META).put(meta);
    tx.objectStore(STATE).put(opts.snapshot, id);
    if (rewriteBlobs) {
      const blobs = tx.objectStore(BLOBS);
      for (let i = 0; i < (previous?.files.length ?? 0); i++) blobs.delete(`${id}/${i}`);
      opts.files.forEach((f, i) => blobs.put(f, `${id}/${i}`));
    }
    await done(tx);
    return meta;
  } finally {
    db.close();
  }
}

export async function loadSession(
  id: string,
): Promise<{ meta: SavedSessionMeta; files: File[]; snapshot: SessionSnapshot }> {
  const db = await open();
  try {
    const meta = (await request(db.transaction(META).objectStore(META).get(id))) as
      | SavedSessionMeta
      | undefined;
    if (!meta) throw new Error("Saved session not found");
    // Issue every read in one go: a transaction auto-commits as soon as it
    // has no pending request, so awaiting them one by one is not safe.
    const tx = db.transaction([STATE, BLOBS]);
    const [snapshot, ...blobs] = await Promise.all([
      request(tx.objectStore(STATE).get(id)),
      ...meta.files.map((_, i) => request(tx.objectStore(BLOBS).get(`${id}/${i}`))),
    ]);
    const files = meta.files.map((m, i) => {
      const blob = blobs[i] as Blob;
      return blob instanceof File
        ? blob
        : new File([blob], m.name, { lastModified: m.lastModified });
    });
    return { meta, files, snapshot: snapshot as SessionSnapshot };
  } finally {
    db.close();
  }
}

export async function deleteSession(id: string): Promise<void> {
  const db = await open();
  try {
    const meta = (await request(db.transaction(META).objectStore(META).get(id))) as
      | SavedSessionMeta
      | undefined;
    const tx = db.transaction([META, STATE, BLOBS], "readwrite");
    tx.objectStore(META).delete(id);
    tx.objectStore(STATE).delete(id);
    for (let i = 0; i < (meta?.files.length ?? 0); i++) tx.objectStore(BLOBS).delete(`${id}/${i}`);
    await done(tx);
  } finally {
    db.close();
  }
}
