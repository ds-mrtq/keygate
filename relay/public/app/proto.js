// KeyGate PWA protocol: pure functions (browser and Node). Mirrors internal/remote and internal/members.
import { WORDS } from "./words.js";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
const subtle = globalThis.crypto.subtle;

export const LABEL_MSG = "kg/v1/msg\0";
export const LABEL_MSG_KEY = "kg/v1/msg-key\0";
export const LABEL_APPROVAL_REQ = "kg/v1/approval-req\0";
export const LABEL_RELAY_REQ = "kg/v1/relay-req\0";
export const LABEL_MEMBER = "kg/v1/member\0";

// ---- bytes ----

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
const toBytes = (x) => (typeof x === "string" ? enc.encode(x) : x);

/** lp(x): uint32 big-endian length then bytes (strings as UTF-8). */
export function lp(x) {
  const b = toBytes(x);
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length);
  out.set(b, 4);
  return out;
}

/** u64(n): big-endian 8 bytes. */
export function u64(n) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

export function hex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
export function unhex(s) {
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

/** base64 standard, with padding. */
export function b64(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
export function unb64(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error("base64");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/** base64 raw-URL, no padding. */
export function b64url(b) {
  return b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("base64url");
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return unb64(t + "=".repeat((4 - (t.length % 4)) % 4));
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/** base32 standard alphabet, no padding. */
export function base32(b) {
  let bits = 0, val = 0, out = "";
  for (const x of b) {
    val = (val << 8) | x;
    bits += 8;
    while (bits >= 5) {
      out += B32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
    val &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
export function unbase32(s) {
  const out = [];
  let bits = 0, val = 0;
  for (const c of s.toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error("base32");
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 255);
      bits -= 8;
      val &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(out);
}

export async function sha256(b) {
  return new Uint8Array(await subtle.digest("SHA-256", toBytes(b)));
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Random 22-char message / request id. */
export function newId() {
  return b64url(randomBytes(16));
}

/** Time string used by relay headers and envelopes: UTC, millisecond, "Z". */
export function isoMs(ms) {
  return new Date(ms).toISOString();
}

// ---- key import helpers ----

const ED_PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
const X_PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

/** Import raw 32-byte seed/private scalar (used by tests and vectors only; app keys are generated non-extractable). */
export function importEdPrivate(seed, extractable = false) {
  return subtle.importKey("pkcs8", concat(ED_PKCS8, seed), { name: "Ed25519" }, extractable, ["sign"]);
}
export function importXPrivate(raw, extractable = false) {
  return subtle.importKey("pkcs8", concat(X_PKCS8, raw), { name: "X25519" }, extractable, ["deriveBits"]);
}
export function importEdPublic(raw) {
  return subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
}
export function importXPublic(raw) {
  return subtle.importKey("raw", raw, { name: "X25519" }, true, []);
}
/** Raw public key of a (possibly non-extractable) private key pair's public half. */
export async function rawPublic(pubKey) {
  return new Uint8Array(await subtle.exportKey("raw", pubKey));
}
/** X25519 public key (raw) for a private scalar. */
export async function xPublicOf(privRaw) {
  const k = await importXPrivate(privRaw, true);
  const jwk = await subtle.exportKey("jwk", k);
  return unb64url(jwk.x);
}

// ---- relay request signing ----

/** Bytes signed for a relay request (internal/transport/relay.Canonical). */
export async function canonicalRelay(method, pathQuery, time, body) {
  const bodyBytes = body == null ? new Uint8Array(0) : toBytes(body);
  return concat(enc.encode(LABEL_RELAY_REQ), lp(method), lp(pathQuery), lp(time), lp(hex(await sha256(bodyBytes))));
}

/** Headers for one signed relay request. */
export async function signRelay(edPriv, dev, method, pathQuery, time, body) {
  const sig = new Uint8Array(await subtle.sign("Ed25519", edPriv, await canonicalRelay(method, pathQuery, time, body)));
  return { "KG-Device": dev, "KG-Time": time, "KG-Sig": b64(sig) };
}

// ---- envelopes ----

const ENV_KEYS = ["v", "from", "to", "id", "time", "eph", "nonce", "ct", "sig"];

function msgInfo(vault, from, to, id, ephPub, toXPub) {
  return concat(enc.encode(LABEL_MSG_KEY), lp(vault), lp(from), lp(to), lp(id), lp(ephPub), lp(toXPub));
}
function sigInput(vault, from, to, id, time, eph, nonce, ct) {
  return concat(enc.encode(LABEL_MSG), u64(1), lp(vault), lp(from), lp(to), lp(id), lp(time), lp(eph), lp(nonce), lp(ct));
}
async function msgKey(sharedBits, info) {
  const k = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/**
 * Seal plaintext (bytes or string) for `to`; returns the JSON line (same field order as Go's json.Marshal).
 * from = {dev, edPriv: CryptoKey}. toXPub = raw 32 bytes. fixed = {ephPriv: raw32, nonce: 12 bytes, id} for test vectors.
 */
export async function sealEnvelope(vault, from, to, toXPub, plaintext, nowMs, fixed) {
  let ephPriv, ephPub;
  if (fixed?.ephPriv) {
    ephPriv = await importXPrivate(fixed.ephPriv);
    ephPub = await xPublicOf(fixed.ephPriv);
  } else {
    const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    ephPriv = kp.privateKey;
    ephPub = await rawPublic(kp.publicKey);
  }
  const nonce = fixed?.nonce ?? randomBytes(12);
  const id = fixed?.id ?? newId();
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: await importXPublic(toXPub) }, ephPriv, 256));
  if (shared.every((x) => x === 0)) throw new Error("x25519: zero shared secret");
  const info = msgInfo(vault, from.dev, to, id, ephPub, toXPub);
  const key = await msgKey(shared, info);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: info, tagLength: 128 }, key, toBytes(plaintext)));
  const time = isoMs(nowMs);
  const sig = new Uint8Array(await subtle.sign("Ed25519", from.edPriv, sigInput(vault, from.dev, to, id, time, ephPub, nonce, ct)));
  return JSON.stringify({ v: 1, from: from.dev, to, id, time, eph: b64(ephPub), nonce: b64(nonce), ct: b64(ct), sig: b64(sig) });
}

/**
 * Verify and decrypt one envelope line. self = {dev, xPriv: CryptoKey, xPub: raw32}.
 * senderEd(dev) returns the raw Ed25519 public key of an allowed sender, or null.
 * Returns {from, time (ms), plaintext: Uint8Array}; throws Error("bad envelope: …") otherwise.
 */
export async function openEnvelope(vault, self, line, senderEd) {
  const bad = (m) => new Error("bad envelope: " + m);
  let e;
  try {
    e = JSON.parse(line);
  } catch {
    throw bad("json");
  }
  if (e === null || typeof e !== "object" || Array.isArray(e)) throw bad("json");
  const keys = Object.keys(e);
  if (keys.length !== ENV_KEYS.length || !ENV_KEYS.every((k) => keys.includes(k))) throw bad("fields");
  if (e.v !== 1) throw bad("version");
  for (const k of ENV_KEYS.slice(1)) if (typeof e[k] !== "string") throw bad("field type");
  if (e.to !== self.dev) throw bad("not addressed to this device");
  const pub = senderEd ? senderEd(e.from) : null;
  if (!pub || pub.length !== 32) throw bad("unknown sender");
  let eph, nonce, ct, sig;
  try {
    eph = unb64(e.eph);
    nonce = unb64(e.nonce);
    ct = unb64(e.ct);
    sig = unb64(e.sig);
  } catch {
    throw bad("field encoding");
  }
  if (eph.length !== 32 || nonce.length !== 12 || sig.length !== 64) throw bad("field encoding");
  if (e.id.length !== 22 || ct.length < 16) throw bad("field size");
  const ms = Date.parse(e.time);
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(e.time) || Number.isNaN(ms) || isoMs(ms) !== e.time) throw bad("time");
  const ok = await subtle.verify("Ed25519", await importEdPublic(pub), sig, sigInput(vault, e.from, e.to, e.id, e.time, eph, nonce, ct));
  if (!ok) throw bad("signature");
  let shared;
  try {
    shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: await importXPublic(eph) }, self.xPriv, 256));
  } catch {
    throw bad("x25519");
  }
  if (shared.every((x) => x === 0)) throw bad("x25519");
  const info = msgInfo(vault, e.from, e.to, e.id, eph, self.xPub);
  let pt;
  try {
    pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: info, tagLength: 128 }, await msgKey(shared, info), ct));
  } catch {
    throw bad("decrypt");
  }
  return { from: e.from, time: ms, plaintext: pt };
}

/** Decrypted plaintext as parsed JSON. */
export function parsePlain(plaintext) {
  return JSON.parse(dec.decode(plaintext));
}

// ---- members ----

/** Genesis pin: first 15 bytes of sha256(genesis hash bytes || vault), base32, groups of 4 joined by '-'. */
export async function genesisPin(vault, genesisHash) {
  const raw = unhex(genesisHash.replace(/^sha256:/, ""));
  const sum = await sha256(concat(raw, enc.encode(vault)));
  return base32(sum.subarray(0, 15)).match(/.{1,4}/g).join("-");
}
export const normPin = (p) => String(p).replace(/[-\s]/g, "").toUpperCase();

const MEMBER_KEYS = ["v", "vault", "n", "prev", "type", "body", "sig"];

/**
 * Verify members.kgl lines (strings) from genesis: prev chain, owner signatures (revoke-approver:
 * signature of the active key-holder device named in body.by), and genesis pin.
 * Returns {pin, genesisHash, head, count, ownerPub, devices: [{dev,label,edPub,xPub,role,revoked}]}.
 */
export async function verifyMembers(lines, vault, pin) {
  const fail = (m) => new Error("members: " + m);
  let ownerPub = null, prevHash = null, genesisHash = "";
  const hashes = [];
  const devices = new Map();
  for (let i = 0; i < lines.length; i++) {
    let e;
    try {
      e = JSON.parse(lines[i]);
    } catch {
      throw fail(`event ${i} json`);
    }
    if (e === null || typeof e !== "object" || Object.keys(e).join() !== MEMBER_KEYS.join()) throw fail(`event ${i} fields`);
    if (e.v !== 1 || e.vault !== vault || e.n !== i) throw fail(`event ${i} header`);
    if ((i === 0) !== (e.prev === null) || (e.prev !== null && typeof e.prev !== "string")) throw fail(`event ${i} prev`);
    if (JSON.stringify(e) !== lines[i]) throw fail(`event ${i} non-canonical`);
    if (i > 0 && e.prev !== prevHash) throw fail(`event ${i} chain`);
    const body = unb64(e.body);
    const sig = unb64(e.sig);
    if (sig.length !== 64) throw fail(`event ${i} sig`);
    const canonical = concat(enc.encode(LABEL_MEMBER), u64(1), lp(vault), u64(e.n), lp(e.prev ?? ""), lp(e.type), lp(body));
    let b;
    try {
      b = JSON.parse(dec.decode(body));
    } catch {
      throw fail(`event ${i} body`);
    }
    if (e.type === "genesis") {
      if (i !== 0) throw fail(`event ${i} genesis`);
      ownerPub = unb64(b.owner_pub);
      if (ownerPub.length !== 32) throw fail("owner key");
    } else if (i === 0) {
      throw fail("first event must be genesis");
    }
    if (e.type === "revoke-approver") {
      const by = devices.get(b.by), d = devices.get(b.dev);
      if (!by || by.revoked || by.role !== "") throw fail(`event ${i} revoke-approver signer`);
      if (!d || d.revoked || d.role !== "approver") throw fail(`event ${i} revoke-approver target`);
      if (!(await subtle.verify("Ed25519", await importEdPublic(by.edPub), sig, canonical))) throw fail(`event ${i} device signature`);
    } else if (!(await subtle.verify("Ed25519", await importEdPublic(ownerPub), sig, canonical))) {
      throw fail(`event ${i} owner signature`);
    }
    prevHash = "sha256:" + hex(await sha256(concat(canonical, sig)));
    hashes.push(prevHash);
    if (i === 0) {
      genesisHash = prevHash;
      if (pin && normPin(pin) !== normPin(await genesisPin(vault, genesisHash))) throw new Error("pin mismatch");
    } else if (e.type === "add") {
      const edPub = unb64(b.ed_pub), xPub = unb64(b.x_pub);
      if (edPub.length !== 32 || xPub.length !== 32 || typeof b.dev !== "string") throw fail(`event ${i} add`);
      if (b.role !== undefined && b.role !== "approver") throw fail(`event ${i} role`);
      devices.set(b.dev, { dev: b.dev, label: b.label, edPub, xPub, role: b.role ?? "", revoked: false });
    } else if (e.type === "revoke" || e.type === "revoke-approver") {
      const d = devices.get(b.dev);
      if (d) d.revoked = true;
    }
  }
  if (!ownerPub) throw fail("empty");
  return { pin: await genesisPin(vault, genesisHash), genesisHash, head: prevHash, count: lines.length, hashes, ownerPub, devices: [...devices.values()] };
}

// ---- pairing ----

// Go's json.Marshal escapes <, >, & and U+2028/9; match it so the code is byte-identical.
function goJSONString(s) {
  return JSON.stringify(s).replace(/[<>&\u2028\u2029]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}

/** Registration code: base32 (std, no padding) of the add-body JSON in field order dev,label,ed_pub,x_pub,role. */
export function registrationCode(add) {
  let j = `{"dev":${goJSONString(add.dev)},"label":${goJSONString(add.label)},"ed_pub":${goJSONString(add.ed_pub)},"x_pub":${goJSONString(add.x_pub)}`;
  if (add.role) j += `,"role":${goJSONString(add.role)}`;
  return base32(enc.encode(j + "}"));
}

/** Phone pairing words: sha256("kg/v1/pair-words\0" + lp(nonce) + lp(code)) indexes the word list (Go store.PairWords). */
export async function pairWords(code, nonce) {
  const norm = code.split(/\s+/).join("").toUpperCase();
  const sum = await sha256(concat(enc.encode("kg/v1/pair-words\0"), lp(enc.encode(nonce)), lp(enc.encode(norm))));
  return Array.from(sum.subarray(0, 6), (x) => WORDS[x]).join(" ");
}

// ---- pending digest ----

/** "sha256:"+hex(sha256(LabelApprovalReq + lp(rid)+lp(op)+u64(n)+lp(s_i)…+lp(command)+lp(detail)+lp(bind)+u64(exp))). */
export async function pendingDigest(p) {
  const parts = [enc.encode(LABEL_APPROVAL_REQ), lp(p.rid), lp(p.op), u64(p.secrets.length)];
  for (const s of p.secrets) parts.push(lp(s));
  parts.push(lp(p.command), lp(p.detail), lp(p.bind), u64(p.exp));
  return "sha256:" + hex(await sha256(concat(...parts)));
}

export const ROLLBACK_MSG = "Danh sách thiết bị trên máy chủ bị quay lui";

/**
 * Anti-rollback: compare a freshly verified members state with the last accepted {count, head}.
 * Throws Error(ROLLBACK_MSG) when the relay shows a shorter chain, a different head at the same
 * length, or a longer chain that does not contain the saved head. saved = null accepts anything.
 */
export function checkRollback(state, saved) {
  if (!saved || !saved.count) return;
  const bad = () => new Error(ROLLBACK_MSG);
  if (state.count < saved.count) throw bad();
  if (state.hashes[saved.count - 1] !== saved.head) throw bad();
}
