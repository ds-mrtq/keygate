// KeyGate relay (DESIGN.md section 8).
// The relay is an untrusted store of signed, encrypted lines. It verifies
// request signatures and the owner signature + prev chain of member events to
// keep junk out; clients verify everything themselves.

import { DurableObject } from "cloudflare:workers";

export interface Env {
  VAULT: DurableObjectNamespace<VaultDO>;
  /** Comma-separated vault IDs this relay serves. Empty = serve nothing. */
  ALLOWED_VAULTS?: string;
  /** Web Push (VAPID) public key, base64url uncompressed P-256 point. Empty = push disabled. */
  VAPID_PUBLIC?: string;
  /** Web Push private key as an ECDSA P-256 JWK (wrangler secret). */
  VAPID_PRIVATE_JWK?: string;
}

const VAULT_RE = /^[A-Za-z0-9_-]{4,64}$/;
const DEV_RE = /^[A-Za-z0-9_]{1,64}$/;
const NUM_RE = /^(0|[1-9][0-9]{0,14})$/; // <= 15 digits, always exact in a double
const MAX_BODY = 64 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const CODE_RE = /^[A-Z2-7]{8}$/;
const MSG_TTL_MS = 600_000;
const MAX_MSGS = 50;
const MAX_PAIRS = 50;
const PUSH_MIN_GAP_MS = 10_000;
const PUSH_HOSTS = new Set(["web.push.apple.com", "fcm.googleapis.com", "updates.push.services.mozilla.com"]);
const PUSH_HOST_SUFFIX = ".notify.windows.com";
const MAX_SKEW_MS = 5 * 60 * 1000;
const MAX_ROWS = 200_000;
const MAX_BYTES = 200 * 1024 * 1024;
const PAGE_LINES = 2000;
const enc = new TextEncoder();
const dec = new TextDecoder();

type Route =
  | "put-log" | "put-member" | "put-checkpoint" | "get-log" | "get-members" | "get-checkpoints" | "ws"
  | "put-msg" | "get-msgs" | "del-msg" | "put-view" | "get-views" | "put-push" | "del-push" | "put-pair" | "get-pair"
  | "get-devices";

function routeOf(method: string, parts: string[]): Route | null {
  if (parts[0] !== "v") return null;
  const kind = parts[2];
  const n = parts.length;
  if (method === "PUT" && kind === "log" && n === 5) return "put-log";
  if (method === "PUT" && kind === "members" && n === 4) return "put-member";
  if (method === "PUT" && kind === "checkpoint" && n === 4) return "put-checkpoint";
  if (method === "GET" && kind === "log" && n === 3) return "get-log";
  if (method === "GET" && kind === "members" && n === 3) return "get-members";
  if (method === "GET" && kind === "checkpoints" && n === 3) return "get-checkpoints";
  if (method === "GET" && kind === "ws" && n === 3) return "ws";
  if (method === "PUT" && kind === "msg" && n === 5) return "put-msg";
  if (method === "GET" && kind === "msg" && n === 4) return "get-msgs";
  if (method === "DELETE" && kind === "msg" && n === 5) return "del-msg";
  if (method === "PUT" && kind === "view" && n === 4) return "put-view";
  if (method === "GET" && kind === "view" && n === 4) return "get-views";
  if (method === "PUT" && kind === "push" && n === 4) return "put-push";
  if (method === "DELETE" && kind === "push" && n === 4) return "del-push";
  if (method === "PUT" && kind === "pair" && n === 4) return "put-pair";
  if (method === "GET" && kind === "pair" && n === 4) return "get-pair";
  if (method === "GET" && kind === "devices" && n === 3) return "get-devices";
  return null;
}

/** Body size cap per route (enforced at the stateless gate and again inside the DO). */
function bodyLimit(route: Route): number {
  switch (route) {
    case "put-view":
      return 256 * 1024;
    case "put-msg":
      return 16 * 1024;
    case "put-pair":
      return 1024;
    default:
      return MAX_BODY;
  }
}

export default {
  // Stateless gate: everything rejectable without storage is rejected here,
  // before a Durable Object is instantiated.
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/push-key" && request.method === "GET") {
      return env.VAPID_PUBLIC ? text(env.VAPID_PUBLIC, 200) : text("not found", 404);
    }
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 3 || parts[0] !== "v" || !VAULT_RE.test(parts[1])) return text("not found", 404);
    const allowed = (env.ALLOWED_VAULTS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!allowed.includes(parts[1])) return text("forbidden", 403);
    const route = routeOf(request.method, parts);
    if (!route) return text("not found", 404);
    if (request.method === "PUT") {
      const cl = request.headers.get("content-length");
      if (cl === null) return text("length required", 411);
      if (!/^[0-9]{1,10}$/.test(cl)) return text("bad request", 400);
      if (Number(cl) > bodyLimit(route)) return text("too large", 413);
    }
    if (route !== "put-pair") {
      // Pairing requests come from a device that has no key yet: no signature.
      const h = checkHeaders(request);
      if (h instanceof Response) return h;
    }
    // Network origin as Cloudflare sees it (IP, location, network, User-Agent), for the owner's
    // device list. Set here so a client cannot supply it; base64 because cities are not ASCII.
    const fwd = new Request(request, { headers: new Headers(request.headers) });
    fwd.headers.set(ORIGIN_HEADER, originOf(request));
    return env.VAULT.get(env.VAULT.idFromName(parts[1])).fetch(fwd);
  },
};

const ORIGIN_HEADER = "KG-Origin";

/** base64(JSON {ip, country, city, org, ua}) of the request; display only, never trusted. */
function originOf(request: Request): string {
  const cf = (request as Request & { cf?: Record<string, unknown> }).cf ?? {};
  const str = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");
  const o = {
    ip: str(request.headers.get("CF-Connecting-IP"), 64),
    country: str(cf.country, 8),
    city: str(cf.city, 64),
    org: str(cf.asOrganization, 96),
    ua: str(request.headers.get("User-Agent"), 256),
  };
  return b64encode(enc.encode(JSON.stringify(o)));
}

/** The origin set by the gate, as a JSON string ("" when missing or malformed). */
function originJSON(request: Request): string {
  const h = request.headers.get(ORIGIN_HEADER);
  if (!h) return "";
  const raw = b64decode(h);
  if (!raw || raw.length > 1024) return "";
  try {
    const o = JSON.parse(dec.decode(raw));
    return o && typeof o === "object" ? JSON.stringify(o) : "";
  } catch {
    return "";
  }
}

const MEMBER_KEYS = "v,vault,n,prev,type,body,sig";

function text(s: string, status: number): Response {
  return new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
}

function json(v: unknown): Response {
  return new Response(JSON.stringify(v), { headers: { "content-type": "application/json" } });
}

function lp(s: string | Uint8Array): Uint8Array {
  const b = typeof s === "string" ? enc.encode(s) : s;
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false);
  out.set(b, 4);
  return out;
}

function u64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64encode(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

function b64decode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

async function verifyEd25519(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch {
    return false;
  }
}

interface Headers3 {
  dev: string;
  time: string;
  tms: number;
  sig: Uint8Array;
}

/** Cheap, storage-free request header checks (format and clock skew). */
function checkHeaders(request: Request): Headers3 | Response {
  const dev = request.headers.get("KG-Device") ?? "";
  const time = request.headers.get("KG-Time") ?? "";
  const sigB64 = request.headers.get("KG-Sig") ?? "";
  if (!DEV_RE.test(dev) || !time || !sigB64) return text("unauthorized", 401);
  const tms = Date.parse(time);
  if (!Number.isFinite(tms) || Math.abs(Date.now() - tms) > MAX_SKEW_MS) return text("unauthorized", 401);
  const sig = b64decode(sigB64);
  if (!sig || sig.length !== 64) return text("unauthorized", 401);
  return { dev, time, tms, sig };
}

interface MemberLine {
  v?: number;
  vault?: string;
  n?: number;
  prev?: string | null;
  type?: string;
  body?: string;
  sig?: string;
}

function parseBody(b64: string): Record<string, unknown> | null {
  const raw = b64decode(b64);
  if (!raw) return null;
  try {
    const o = JSON.parse(dec.decode(raw));
    return o && typeof o === "object" && !Array.isArray(o) ? (o as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function pub32(v: unknown): Uint8Array | null {
  if (typeof v !== "string") return null;
  const b = b64decode(v);
  return b && b.length === 32 ? b : null;
}

interface Auth {
  dev: string;
  tms: number;
  genesis: boolean;
  /** "approver" for phone devices, "" for key holders / owner. */
  role: string;
}

export class VaultDO extends DurableObject<Env> {
  private sql: SqlStorage;
  // Tables exist only after an accepted genesis (see putMember).
  private ready: boolean;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ready =
      this.sql.exec(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'members'`).toArray().length > 0;
    if (this.ready) {
      this.ensureV2();
      this.ensureV3();
    }
  }

  /** Schema v3 (device origin): pair.meta and the last-seen table. Idempotent; one transaction. */
  private ensureV3(): void {
    if (this.sql.exec(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'seen'`).toArray().length > 0) return;
    this.ctx.storage.transactionSync(() => this.createV3());
  }

  private createV3(): void {
    this.sql.exec(`ALTER TABLE pair ADD COLUMN meta TEXT`);
    this.sql.exec(`CREATE TABLE seen(dev TEXT PRIMARY KEY, t INTEGER NOT NULL, meta TEXT NOT NULL)`);
  }

  /** Schema v2 (approver role, mailbox, view, push, pair). Idempotent; one transaction. */
  private ensureV2(): void {
    if (this.sql.exec(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'msg'`).toArray().length > 0) return;
    this.ctx.storage.transactionSync(() => this.createV2());
  }

  private createV2(): void {
    this.sql.exec(`ALTER TABLE members ADD COLUMN role TEXT`);
    this.sql.exec(
      `CREATE TABLE msg(to_dev TEXT NOT NULL, id TEXT NOT NULL, from_dev TEXT NOT NULL, body TEXT NOT NULL, exp INTEGER NOT NULL, PRIMARY KEY(to_dev, id))`,
    );
    this.sql.exec(
      `CREATE TABLE view(to_dev TEXT NOT NULL, from_dev TEXT NOT NULL, ver INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(to_dev, from_dev))`,
    );
    this.sql.exec(`CREATE TABLE push(dev TEXT PRIMARY KEY, endpoint TEXT NOT NULL, last INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE pair(code TEXT PRIMARY KEY, body TEXT NOT NULL, exp INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
  }

  private createTables(): void {
    this.sql.exec(
      `CREATE TABLE members(
         n INTEGER PRIMARY KEY, body TEXT NOT NULL, type TEXT NOT NULL, hash TEXT NOT NULL,
         dev_id TEXT, dev_pub_ed TEXT, target TEXT)`,
    );
    this.sql.exec(
      `CREATE TABLE log(dev TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(dev, seq))`,
    );
    this.sql.exec(`CREATE TABLE checkpoints(dev TEXT PRIMARY KEY, body TEXT NOT NULL)`);
    this.sql.exec(`CREATE TABLE devtime(dev TEXT PRIMARY KEY, t INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE stats(id INTEGER PRIMARY KEY CHECK (id = 1), rows INTEGER NOT NULL, bytes INTEGER NOT NULL)`);
    this.sql.exec(`INSERT INTO stats(id, rows, bytes) VALUES (1, 0, 0)`);
    this.createV2();
    this.createV3();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // v, vault, kind, ...
    const route = routeOf(request.method, parts);
    if (!route) return text("not found", 404);
    const vault = parts[1];

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > bodyLimit(route)) return text("too large", 413);

    const auth = await this.authenticate(request, url, body, route, parts);
    if (auth instanceof Response) return auth;

    switch (route) {
      case "put-log":
        return this.putLog(parts[3], parts[4], body, auth.dev);
      case "put-member":
        return this.putMember(vault, parts[3], body, auth);
      case "put-checkpoint":
        return this.putCheckpoint(parts[3], body, auth.dev);
      case "get-log":
        return this.getLog(url.searchParams.get("since") ?? "");
      case "get-members":
        return this.getMembers(url.searchParams.get("since") ?? "0");
      case "get-checkpoints":
        return this.getCheckpoints();
      case "ws":
        return this.upgrade(request);
      case "put-msg":
        return this.putMsg(parts[3], parts[4], body, auth.dev);
      case "get-msgs":
        return this.getMsgs(parts[3], auth.dev);
      case "del-msg":
        return this.delMsg(parts[3], parts[4], auth.dev);
      case "put-view":
        return this.putView(parts[3], body, auth, request.headers.get("KG-Push") === "1", url.host);
      case "get-views":
        return this.getViews(parts[3], auth.dev, url.searchParams.get("have") ?? "");
      case "put-push":
        return this.putPush(parts[3], body, auth.dev);
      case "del-push":
        return this.delPush(parts[3], auth.dev);
      case "put-pair":
        return this.putPair(parts[3], body, originJSON(request));
      case "get-pair":
        return this.getPair(parts[3], auth);
      case "get-devices":
        return this.getDevices(auth);
    }
  }

  // ---- auth ----

  private lookup(dev: string): { pub: Uint8Array; role: string } | null {
    // Active member device (add event without a later revoke) or the owner key.
    const rows = this.sql
      .exec(
        `SELECT dev_pub_ed, role FROM members m WHERE dev_id = ?
           AND NOT EXISTS (SELECT 1 FROM members r WHERE r.type IN ('revoke', 'revoke-approver') AND r.target = m.dev_id)
         LIMIT 1`,
        dev,
      )
      .toArray();
    if (rows.length === 0) return null;
    const pub = b64decode(rows[0].dev_pub_ed as string);
    return pub ? { pub, role: (rows[0].role as string | null) ?? "" } : null;
  }

  /** Role of an active `add`-ed device: "" (key holder), "approver", or null (not active / owner). */
  private activeRole(dev: string): string | null {
    const rows = this.sql
      .exec(
        `SELECT role FROM members m WHERE dev_id = ? AND type = 'add'
           AND NOT EXISTS (SELECT 1 FROM members r WHERE r.type IN ('revoke', 'revoke-approver') AND r.target = m.dev_id)
         LIMIT 1`,
        dev,
      )
      .toArray();
    return rows.length ? ((rows[0].role as string | null) ?? "") : null;
  }

  private async authenticate(
    request: Request,
    url: URL,
    body: Uint8Array,
    route: Route,
    parts: string[],
  ): Promise<Auth | Response> {
    if (route === "put-pair") {
      // Unsigned by design: the pairing code is public, integrity comes from the 6-word check.
      if (!this.ready) return text("not found", 404);
      return { dev: "", tms: 0, genesis: false, role: "" };
    }
    const h = checkHeaders(request);
    if (h instanceof Response) return h;
    const { dev, time, tms, sig } = h;

    const digest = await crypto.subtle.digest("SHA-256", body);
    const canonical = concat(
      enc.encode("kg/v1/relay-req\x00"),
      lp(request.method),
      lp(url.pathname + url.search),
      lp(time),
      lp(hex(digest)),
    );

    if (!this.ready) {
      // Genesis bootstrap: PUT members/0, request signed by owner_pub inside the genesis.
      if (route !== "put-member" || parts[3] !== "0") return text("not found", 404);
      let ownerPub: Uint8Array | null = null;
      try {
        const line = JSON.parse(dec.decode(body)) as MemberLine;
        if (line.type === "genesis" && typeof line.body === "string") ownerPub = pub32(parseBody(line.body)?.owner_pub);
      } catch {
        /* fallthrough */
      }
      if (dev !== "owner" || !ownerPub || !(await verifyEd25519(ownerPub, sig, canonical))) {
        return text("unauthorized", 401);
      }
      return { dev, tms, genesis: true, role: "" };
    }

    const found = this.lookup(dev);
    if (!found || !(await verifyEd25519(found.pub, sig, canonical))) return text("unauthorized", 401);
    // Devices may only write their own log/checkpoint. "owner" may write members only.
    if ((route === "put-log" || route === "put-checkpoint") && (dev === "owner" || parts[3] !== dev)) {
      return text("forbidden", 403);
    }
    // Approvers never write the log or checkpoints.
    if ((route === "put-log" || route === "put-checkpoint") && found.role === "approver") {
      return text("forbidden", 403);
    }
    // Per-device strictly increasing KG-Time defeats replay of captured requests.
    // (Check and update run in one synchronous section.)
    const last = this.sql.exec(`SELECT t FROM devtime WHERE dev = ?`, dev).toArray();
    if (last.length && tms <= (last[0].t as number)) return text("unauthorized", 401);
    this.sql.exec(`INSERT INTO devtime(dev, t) VALUES (?, ?) ON CONFLICT(dev) DO UPDATE SET t = excluded.t`, dev, tms);
    if (dev !== "owner") {
      this.sql.exec(
        `INSERT INTO seen(dev, t, meta) VALUES (?, ?, ?) ON CONFLICT(dev) DO UPDATE SET t = excluded.t, meta = excluded.meta`,
        dev,
        Date.now(),
        originJSON(request),
      );
    }
    return { dev, tms, genesis: false, role: found.role };
  }

  private memberCount(): number {
    return this.sql.exec(`SELECT COUNT(*) AS c FROM members`).one().c as number;
  }

  /** Reserve capacity for a write; false when the per-vault caps would be exceeded. */
  private charge(rows: number, bytes: number): boolean {
    const s = this.sql.exec(`SELECT rows, bytes FROM stats WHERE id = 1`).one();
    if ((s.rows as number) + rows > MAX_ROWS || (s.bytes as number) + bytes > MAX_BYTES) return false;
    this.sql.exec(`UPDATE stats SET rows = rows + ?, bytes = bytes + ? WHERE id = 1`, rows, bytes);
    return true;
  }

  // ---- writes ----

  private putLog(dev: string, seqStr: string, body: Uint8Array, authDev: string): Response {
    if (!DEV_RE.test(dev) || dev !== authDev || !NUM_RE.test(seqStr) || seqStr === "0") {
      return text("bad request", 400);
    }
    const line = dec.decode(body);
    if (!line || /[\r\n]/.test(line)) return text("bad request", 400);
    const seq = Number(seqStr);
    const last = (this.sql.exec(`SELECT MAX(seq) AS m FROM log WHERE dev = ?`, dev).one().m as number | null) ?? 0;
    if (seq <= last) return text("exists", 409);
    if (seq !== last + 1) return text("gap", 400);
    if (!this.charge(1, body.length)) return text("vault full", 507);
    this.sql.exec(`INSERT INTO log(dev, seq, body) VALUES (?, ?, ?)`, dev, seq, line);
    this.broadcast();
    return text("ok", 201);
  }

  private async putMember(vault: string, nStr: string, body: Uint8Array, auth: Auth): Promise<Response> {
    if (!NUM_RE.test(nStr)) return text("bad request", 400);
    const n = Number(nStr);
    if (this.ready && this.sql.exec(`SELECT 1 FROM members WHERE n = ?`, n).toArray().length) {
      return text("exists", 409);
    }
    const lineStr = dec.decode(body);
    let line: MemberLine;
    try {
      line = JSON.parse(lineStr) as MemberLine;
    } catch {
      return text("bad request", 400);
    }
    if (
      /[\r\n]/.test(lineStr) ||
      !line || typeof line !== "object" ||
      line.v !== 1 ||
      line.vault !== vault ||
      line.n !== n ||
      typeof line.type !== "string" ||
      typeof line.body !== "string" ||
      typeof line.sig !== "string" ||
      (line.prev !== null && line.prev !== undefined && typeof line.prev !== "string")
    ) {
      return text("bad request", 400);
    }
    const prev = line.prev ?? null;
    const bodyRaw = b64decode(line.body);
    const sigRaw = b64decode(line.sig);
    const b = parseBody(line.body);
    if (!bodyRaw || !sigRaw || sigRaw.length !== 64 || !b) return text("bad request", 400);

    // Owner key: from the genesis itself, otherwise from the stored genesis row.
    let ownerPubB64: string;
    if (auth.genesis) {
      if (line.type !== "genesis" || n !== 0 || prev !== null || !pub32(b.owner_pub)) return text("bad request", 400);
      ownerPubB64 = b.owner_pub as string;
    } else {
      if (line.type === "genesis") return text("bad request", 400);
      ownerPubB64 = this.sql.exec(`SELECT dev_pub_ed FROM members WHERE n = 0`).one().dev_pub_ed as string;
    }
    const canonical = concat(
      enc.encode("kg/v1/member\x00"),
      u64(1),
      lp(vault),
      u64(n),
      lp(prev ?? ""),
      lp(line.type),
      lp(bodyRaw),
    );
    // revoke-approver is signed by an active key-holder device (body.by), not the owner: an approver
    // never held the vault key, so a key holder may remove it without the owner keys (DESIGN 4.2).
    let signerPubB64 = ownerPubB64;
    if (line.type === "revoke-approver") {
      // Same strictness as the Go parser (canonical line, exact body keys): a line the relay accepts
      // but the laptops reject would wedge the member chain for good.
      if (Object.keys(line).join() !== MEMBER_KEYS || JSON.stringify(line) !== lineStr) return text("bad request", 400);
      if (Object.keys(b).join() !== "dev,by,reason" || JSON.stringify(b) !== dec.decode(bodyRaw)) return text("bad request", 400);
      const by = b.by, id = b.dev, reason = b.reason;
      if (typeof by !== "string" || !DEV_RE.test(by) || typeof id !== "string" || !DEV_RE.test(id)) return text("bad request", 400);
      if (typeof reason !== "string" || enc.encode(reason).length > 256) return text("bad request", 400);
      if (this.activeRole(by) !== "" || this.activeRole(id) !== "approver") return text("bad request", 400);
      signerPubB64 = this.sql
        .exec(`SELECT dev_pub_ed FROM members WHERE dev_id = ? AND type = 'add' LIMIT 1`, by)
        .one().dev_pub_ed as string;
    }
    if (!(await verifyEd25519(b64decode(signerPubB64)!, sigRaw, canonical))) return text("bad request", 400);
    const hash = "sha256:" + hex(await crypto.subtle.digest("SHA-256", concat(canonical, sigRaw)));

    let devId: string | null = null;
    let devPub: string | null = null;
    let target: string | null = null;
    let role: string | null = null;
    if (line.type === "genesis") {
      devId = "owner";
      devPub = ownerPubB64;
    } else if (line.type === "add") {
      const id = b.dev;
      if (typeof id !== "string" || !DEV_RE.test(id) || id === "owner" || !pub32(b.ed_pub)) {
        return text("bad request", 400);
      }
      if (b.role !== undefined && b.role !== "approver") return text("bad request", 400);
      devId = id;
      devPub = b.ed_pub as string;
      role = b.role === "approver" ? "approver" : null;
    } else if (line.type === "revoke" || line.type === "revoke-approver") {
      const id = b.dev;
      if (typeof id !== "string" || !DEV_RE.test(id) || id === "owner") return text("bad request", 400);
      target = id;
    } else if (line.type !== "epoch") {
      return text("bad request", 400);
    }

    // Synchronous section from here: state checks and insert cannot interleave.
    if (this.ready) {
      if (this.sql.exec(`SELECT 1 FROM members WHERE n = ?`, n).toArray().length) return text("exists", 409);
      const count = this.memberCount();
      if (n !== count) return text("gap", 400);
      const lastHash = this.sql.exec(`SELECT hash FROM members WHERE n = ?`, n - 1).one().hash as string;
      if (prev !== lastHash) return text("bad prev", 400);
      if (line.type === "revoke-approver") {
        // Re-checked after the await: roles, and no revoke awaiting its epoch (Go rejects that order).
        const lastType = this.sql.exec(`SELECT type FROM members WHERE n = ?`, n - 1).one().type as string;
        if (lastType === "revoke" || this.activeRole(b.by as string) !== "" || this.activeRole(b.dev as string) !== "approver") {
          return text("bad request", 400);
        }
      }
      if (!this.charge(1, body.length)) return text("vault full", 507);
    }
    let genesisDone = false;
    this.ctx.storage.transactionSync(() => {
      if (!this.ready) {
        this.createTables();
        this.sql.exec(`INSERT INTO devtime(dev, t) VALUES ('owner', ?)`, auth.tms);
        this.charge(1, body.length);
        genesisDone = true;
      }
      this.sql.exec(
        `INSERT INTO members(n, body, type, hash, dev_id, dev_pub_ed, target, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        n,
        lineStr,
        line.type,
        hash,
        devId,
        devPub,
        target,
        role,
      );
    });
    if (genesisDone) this.ready = true;
    this.broadcast();
    return text("ok", 201);
  }

  private putCheckpoint(dev: string, body: Uint8Array, authDev: string): Response {
    if (!DEV_RE.test(dev) || dev !== authDev) return text("bad request", 400);
    const line = dec.decode(body);
    const cp = parseCheckpoint(line);
    if (!cp) return text("bad request", 400);
    const old = this.sql
      .exec(`SELECT body, length(CAST(body AS BLOB)) AS len FROM checkpoints WHERE dev = ?`, dev)
      .toArray();
    if (old.length) {
      const prev = parseCheckpoint(old[0].body as string);
      if (prev) {
        if (cp.membersN < prev.membersN) return text("checkpoint regressed", 422);
        for (const [d, s] of Object.entries(prev.seen)) {
          if ((cp.seen[d] ?? -1) < s) return text("checkpoint regressed", 422);
        }
      }
    }
    const oldLen = old.length ? (old[0].len as number) : 0;
    if (!this.charge(old.length ? 0 : 1, body.length - oldLen)) return text("vault full", 507);
    this.sql.exec(
      `INSERT INTO checkpoints(dev, body) VALUES (?, ?)
       ON CONFLICT(dev) DO UPDATE SET body = excluded.body`,
      dev,
      line,
    );
    this.broadcast();
    return text("ok", 200);
  }

  // ---- mailbox / view / push / pair (schema v2) ----

  private putMsg(to: string, id: string, body: Uint8Array, from: string): Response {
    if (!DEV_RE.test(to) || !ID_RE.test(id)) return text("bad request", 400);
    const role = this.activeRole(to);
    if (role === null || role === "approver") return text("bad request", 400);
    const line = dec.decode(body);
    if (!line) return text("bad request", 400);
    const now = Date.now();
    this.sql.exec(`DELETE FROM msg WHERE exp <= ?`, now);
    if (this.sql.exec(`SELECT 1 FROM msg WHERE to_dev = ? AND id = ?`, to, id).toArray().length) return text("exists", 409);
    if ((this.sql.exec(`SELECT COUNT(*) AS c FROM msg WHERE to_dev = ?`, to).one().c as number) >= MAX_MSGS) {
      return text("too many messages", 429);
    }
    this.sql.exec(`INSERT INTO msg(to_dev, id, from_dev, body, exp) VALUES (?, ?, ?, ?, ?)`, to, id, from, line, now + MSG_TTL_MS);
    return text("ok", 201);
  }

  private getMsgs(dev: string, authDev: string): Response {
    if (dev !== authDev) return text("forbidden", 403);
    this.sql.exec(`DELETE FROM msg WHERE exp <= ?`, Date.now());
    const rows = this.sql.exec(`SELECT id, from_dev, body FROM msg WHERE to_dev = ? ORDER BY rowid`, dev).toArray();
    return json({ msgs: rows.map((r) => ({ id: r.id as string, from: r.from_dev as string, body: r.body as string })) });
  }

  private delMsg(dev: string, id: string, authDev: string): Response {
    if (dev !== authDev) return text("forbidden", 403);
    this.sql.exec(`DELETE FROM msg WHERE to_dev = ? AND id = ?`, dev, id);
    return new Response(null, { status: 204 });
  }

  private putView(to: string, body: Uint8Array, auth: Auth, wantPush: boolean, host: string): Response {
    if (auth.role === "approver" || auth.dev === "owner") return text("forbidden", 403);
    if (!DEV_RE.test(to) || this.activeRole(to) !== "approver") return text("bad request", 400);
    const line = dec.decode(body);
    if (!line) return text("bad request", 400);
    this.sql.exec(
      `INSERT INTO view(to_dev, from_dev, ver, body) VALUES (?, ?, 1, ?)
       ON CONFLICT(to_dev, from_dev) DO UPDATE SET ver = ver + 1, body = excluded.body`,
      to,
      auth.dev,
      line,
    );
    if (wantPush) this.maybePush(to, host);
    return text("ok", 200);
  }

  private getViews(dev: string, authDev: string, haveStr: string): Response {
    if (dev !== authDev) return text("forbidden", 403);
    const have = new Map<string, number>();
    for (const kv of haveStr.split(",")) {
      if (!kv) continue;
      const i = kv.lastIndexOf(":");
      const d = kv.slice(0, i);
      const s = kv.slice(i + 1);
      if (i <= 0 || !DEV_RE.test(d) || !NUM_RE.test(s)) return text("bad request", 400);
      have.set(d, Number(s));
    }
    const rows = this.sql.exec(`SELECT from_dev, ver, body FROM view WHERE to_dev = ? ORDER BY from_dev`, dev).toArray();
    const views = rows
      .filter((r) => have.get(r.from_dev as string) !== (r.ver as number))
      .map((r) => ({ from: r.from_dev as string, ver: r.ver as number, body: r.body as string }));
    return json({ views });
  }

  private async putPush(dev: string, body: Uint8Array, authDev: string): Promise<Response> {
    if (dev !== authDev) return text("forbidden", 403);
    let endpoint: unknown;
    try {
      endpoint = JSON.parse(dec.decode(body))?.endpoint;
    } catch {
      return text("bad request", 400);
    }
    if (typeof endpoint !== "string") return text("bad request", 400);
    let u: URL;
    try {
      u = new URL(endpoint);
    } catch {
      return text("bad request", 400);
    }
    // Only known push services: the relay will POST to this URL (SSRF guard).
    if (u.protocol !== "https:" || u.port !== "" || u.username || u.password ||
      !(PUSH_HOSTS.has(u.hostname) || u.hostname.endsWith(PUSH_HOST_SUFFIX))) {
      return text("bad request", 400);
    }
    this.sql.exec(
      `INSERT INTO push(dev, endpoint, last) VALUES (?, ?, 0)
       ON CONFLICT(dev) DO UPDATE SET endpoint = excluded.endpoint`,
      dev,
      u.toString(),
    );
    return text("ok", 200);
  }

  private delPush(dev: string, authDev: string): Response {
    if (dev !== authDev) return text("forbidden", 403);
    this.sql.exec(`DELETE FROM push WHERE dev = ?`, dev);
    return new Response(null, { status: 204 });
  }

  private putPair(code: string, body: Uint8Array, meta: string): Response {
    if (!CODE_RE.test(code)) return text("bad request", 400);
    const line = dec.decode(body);
    if (!line) return text("bad request", 400);
    const now = Date.now();
    this.sql.exec(`DELETE FROM pair WHERE exp <= ?`, now);
    if (this.sql.exec(`SELECT 1 FROM pair WHERE code = ?`, code).toArray().length) return text("exists", 409);
    if ((this.sql.exec(`SELECT COUNT(*) AS c FROM pair`).one().c as number) >= MAX_PAIRS) {
      return text("too many pairings", 429);
    }
    this.sql.exec(`INSERT INTO pair(code, body, exp, meta) VALUES (?, ?, ?, ?)`, code, line, now + MSG_TTL_MS, meta);
    return text("ok", 201);
  }

  private getPair(code: string, auth: Auth): Response {
    if (auth.role === "approver") return text("forbidden", 403);
    if (!CODE_RE.test(code)) return text("bad request", 400);
    this.sql.exec(`DELETE FROM pair WHERE exp <= ?`, Date.now());
    const rows = this.sql.exec(`SELECT body, meta FROM pair WHERE code = ?`, code).toArray();
    if (!rows.length) return text("not found", 404);
    this.sql.exec(`DELETE FROM pair WHERE code = ?`, code);
    const res = text(rows[0].body as string, 200);
    const meta = (rows[0].meta as string | null) ?? "";
    if (meta) res.headers.set("KG-Pair-Origin", b64encode(enc.encode(meta)));
    return res;
  }

  /** Last request time and network origin of every device (key holders only). */
  private getDevices(auth: Auth): Response {
    if (auth.role === "approver" || auth.dev === "owner") return text("forbidden", 403);
    const rows = this.sql.exec(`SELECT dev, t, meta FROM seen ORDER BY dev`).toArray();
    return json({
      devices: rows.map((r) => {
        let o: Record<string, unknown> = {};
        try {
          o = JSON.parse(r.meta as string);
        } catch {
          /* empty */
        }
        return { ...o, dev: r.dev as string, t: r.t as number };
      }),
    });
  }

  // ---- Web Push (no payload, VAPID ES256) ----

  private maybePush(to: string, host: string): void {
    const env = this.env;
    if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE_JWK) return;
    const rows = this.sql.exec(`SELECT endpoint, last FROM push WHERE dev = ?`, to).toArray();
    if (!rows.length) return;
    const now = Date.now();
    if (now - (rows[0].last as number) < PUSH_MIN_GAP_MS) return;
    this.sql.exec(`UPDATE push SET last = ? WHERE dev = ?`, now, to);
    this.ctx.waitUntil(this.sendPush(to, rows[0].endpoint as string, host).catch(() => undefined));
  }

  private async vapidJwt(aud: string, host: string): Promise<string> {
    const env = this.env;
    const now = Math.floor(Date.now() / 1000);
    const cached = this.sql.exec(`SELECT v FROM kv WHERE k = ?`, "jwt:" + aud).toArray();
    if (cached.length) {
      const c = JSON.parse(cached[0].v as string) as { jwt: string; exp: number };
      if (c.exp - now >= 3600) return c.jwt;
    }
    const exp = now + 12 * 3600;
    const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
    const claims = b64u(enc.encode(JSON.stringify({ aud, exp, sub: `https://${host}/app/` })));
    const key = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(env.VAPID_PRIVATE_JWK as string),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${head}.${claims}`)));
    const jwt = `${head}.${claims}.${b64u(sig)}`;
    this.sql.exec(`INSERT INTO kv(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, "jwt:" + aud, JSON.stringify({ jwt, exp }));
    return jwt;
  }

  private async sendPush(dev: string, endpoint: string, host: string): Promise<void> {
    const env = this.env;
    const aud = new URL(endpoint).origin;
    const jwt = await this.vapidJwt(aud, host);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC}`,
        TTL: "300",
        Urgency: "high",
        Topic: "kg-pending",
      },
    });
    if (res.status === 404 || res.status === 410) this.sql.exec(`DELETE FROM push WHERE dev = ?`, dev);
  }

  // ---- reads ----

  private getLog(since: string): Response {
    const have = new Map<string, number>();
    for (const kv of since.split(",")) {
      if (!kv) continue;
      const i = kv.lastIndexOf(":");
      const d = kv.slice(0, i);
      const s = kv.slice(i + 1);
      if (i <= 0 || !DEV_RE.test(d) || !NUM_RE.test(s)) return text("bad request", 400);
      have.set(d, Number(s));
    }
    const logs: Record<string, { seq: number; line: string }[]> = {};
    let remaining = PAGE_LINES;
    let more = false;
    const devs = this.sql.exec(`SELECT DISTINCT dev FROM log ORDER BY dev`).toArray();
    for (const r of devs) {
      const dev = r.dev as string;
      const rows = this.sql
        .exec(`SELECT seq, body FROM log WHERE dev = ? AND seq > ? ORDER BY seq LIMIT ?`, dev, have.get(dev) ?? 0, remaining + 1)
        .toArray();
      if (rows.length > remaining) {
        more = true;
        rows.length = remaining;
      }
      if (rows.length) {
        logs[dev] = rows.map((x) => ({ seq: x.seq as number, line: x.body as string }));
        remaining -= rows.length;
      }
      if (more) break;
    }
    return json({ logs, more });
  }

  private getMembers(since: string): Response {
    if (!NUM_RE.test(since)) return text("bad request", 400);
    const rows = this.sql.exec(`SELECT n, body FROM members WHERE n >= ? ORDER BY n`, Number(since)).toArray();
    return json({ members: rows.map((x) => ({ n: x.n as number, line: x.body as string })) });
  }

  private getCheckpoints(): Response {
    const checkpoints: Record<string, string> = {};
    for (const r of this.sql.exec(`SELECT dev, body FROM checkpoints`).toArray()) {
      checkpoints[r.dev as string] = r.body as string;
    }
    return json({ checkpoints });
  }

  // ---- websocket (hibernatable) ----

  private upgrade(request: Request): Response {
    if (request.headers.get("Upgrade") !== "websocket") return text("expected websocket", 426);
    const pair = new WebSocketPair();
    this.ctx.acceptWebSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  private broadcast(): void {
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.send("new");
      } catch {
        /* closed socket */
      }
    }
  }

  webSocketMessage(): void {
    // Clients send nothing meaningful; ignore.
  }

  webSocketClose(ws: WebSocket, code: number): void {
    try {
      ws.close(code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000);
    } catch {
      /* already closed */
    }
  }
}

function parseCheckpoint(s: string): { membersN: number; seen: Record<string, number> } | null {
  try {
    const o = JSON.parse(s);
    if (!o || typeof o !== "object") return null;
    const mn = o.members_n;
    const seen = o.seen;
    if (!Number.isSafeInteger(mn) || mn < 0 || !seen || typeof seen !== "object" || Array.isArray(seen)) return null;
    for (const v of Object.values(seen)) if (!Number.isSafeInteger(v) || (v as number) < 0) return null;
    return { membersN: mn, seen: seen as Record<string, number> };
  } catch {
    return null;
  }
}
