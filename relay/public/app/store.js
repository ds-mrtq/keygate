// IndexedDB 'keygate' / object store 'kv'. Private keys are non-extractable CryptoKeys (structured-cloned as-is).
// Keys: vault, pin, dev, label, edKey, xWrapKey+xSealed (or xRaw; legacy xKey), edPub, xPub, phase ("pairing" | "paired"), code, words, sel.

const DB_NAME = "keygate";
const STORE = "kv";

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

let dbp = null;
function db() {
  dbp ??= open();
  return dbp;
}

async function tx(mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(STORE, mode);
    const r = fn(t.objectStore(STORE));
    t.oncomplete = () => resolve(r?.result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export const get = (k) => tx("readonly", (s) => s.get(k));
export const set = (k, v) => tx("readwrite", (s) => s.put(v, k));
export const del = (k) => tx("readwrite", (s) => s.delete(k));
export const clear = () => tx("readwrite", (s) => s.clear());

export async function setMany(obj) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(STORE, "readwrite");
    const s = t.objectStore(STORE);
    for (const [k, v] of Object.entries(obj)) s.put(v, k);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

export async function getAll() {
  const d = await db();
  return new Promise((resolve, reject) => {
    const out = {};
    const t = d.transaction(STORE, "readonly");
    const req = t.objectStore(STORE).openCursor();
    req.onsuccess = () => {
      const c = req.result;
      if (c) {
        out[c.key] = c.value;
        c.continue();
      }
    };
    t.oncomplete = () => resolve(out);
    t.onerror = () => reject(t.error);
  });
}
