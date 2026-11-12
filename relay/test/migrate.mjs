// Durable Object migration test: run the NEW relay on the state left by the OLD relay's smoke test.
//   1. old relay (git worktree at e5afec9) with --persist-to <dir>; run its test/smoke.mjs with
//      KG_SMOKE_KEYS=<file> (the old smoke needs the 4-line key dump from the new smoke.mjs)
//   2. stop it, start the new relay with the same --persist-to
//   3. KG_SMOKE_KEYS=<file> node test/migrate.mjs [baseUrl]
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const BASE = process.argv[2] ?? process.env.KG_RELAY ?? "http://127.0.0.1:8787";
const vault = process.env.KG_SMOKE_VAULT ?? "vlt_smoke_local";
const keyFile = process.env.KG_SMOKE_KEYS;
if (!keyFile) throw new Error("KG_SMOKE_KEYS=<owner key file written by the old smoke run> is required");
const ownerPriv = createPrivateKey(readFileSync(keyFile));

const lp = (b) => {
  const buf = Buffer.isBuffer(b) ? b : Buffer.from(b);
  const n = Buffer.alloc(4);
  n.writeUInt32BE(buf.length);
  return Buffer.concat([n, buf]);
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
let last = 0;
async function call(method, pathQuery, body = "") {
  last = Math.max(Date.now(), last + 1);
  const time = new Date(last).toISOString();
  const canonical = Buffer.concat([
    Buffer.from("kg/v1/relay-req\0"), lp(method), lp(pathQuery), lp(time),
    lp(createHash("sha256").update(Buffer.from(body)).digest("hex")),
  ]);
  const res = await fetch(BASE + pathQuery, {
    method,
    headers: { "KG-Device": "owner", "KG-Time": time, "KG-Sig": sign(null, canonical, ownerPriv).toString("base64") },
    body: method === "GET" ? undefined : body,
  });
  return { status: res.status, text: await res.text() };
}
function memberCanonical(l) {
  return Buffer.concat([
    Buffer.from("kg/v1/member\0"), u64(1), lp(l.vault), u64(l.n), lp(l.prev ?? ""), lp(l.type), lp(Buffer.from(l.body, "base64")),
  ]);
}
const hashOf = (l) => "sha256:" + createHash("sha256").update(Buffer.concat([memberCanonical(l), Buffer.from(l.sig, "base64")])).digest("hex");

let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log("ok   " + name);
  } catch (e) {
    console.log("FAIL " + name + ": " + e.message);
    process.exitCode = 1;
  }
}
const expect = async (p, status) => {
  const r = await p;
  assert.equal(r.status, status, `expected ${status}, got ${r.status}: ${r.text}`);
  return r;
};

const V = "/v/" + vault;
let members = [];
await check("old data: GET members", async () => {
  members = JSON.parse((await expect(call("GET", V + "/members?since=0"), 200)).text).members;
  assert.ok(members.length >= 5, "members: " + members.length);
});
await check("old data: GET log has the old device lines", async () => {
  const j = JSON.parse((await expect(call("GET", V + "/log"), 200)).text);
  assert.ok(Object.values(j.logs).some((l) => l.length > 0));
});
await check("old data: GET checkpoints", () => expect(call("GET", V + "/checkpoints"), 200));
await check("schema v3: old pair rows readable, new pair keeps its origin", async () => {
  // the old smoke left 50 pending codes (the cap): consuming two old v2 rows (meta NULL) frees room
  assert.equal((await expect(call("GET", V + "/pair/AAAAAAAA"), 200)).text, "REGCODE");
  assert.equal((await expect(call("GET", V + "/pair/AAAAAAAB"), 200)).text, "REGCODE");
  await expect(fetch(BASE + V + "/pair/MIGRATE3", { method: "PUT", body: "y", headers: { "User-Agent": "kg-mig" } }).then(async (r) => ({ status: r.status, text: await r.text() })), 201);
  assert.equal((await expect(call("GET", V + "/pair/MIGRATE3"), 200)).text, "y");
});
await check("PUT pair (unsigned) after migration -> 201", async () => {
  await expect(fetch(BASE + V + "/pair/MIGRATE2", { method: "PUT", body: "x" }).then(async (r) => ({ status: r.status, text: await r.text() })), 201);
});
await check("add approver after migration -> 201", async () => {
  const tail = JSON.parse(members[members.length - 1].line);
  const pub = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const body = Buffer.from(JSON.stringify({ dev: "dev_migphone01", label: "m", ed_pub: pub.toString("base64"), x_pub: "AAAA", role: "approver" }));
  const l = { v: 1, vault, n: tail.n + 1, prev: hashOf(tail), type: "add", body: body.toString("base64") };
  const sig = sign(null, memberCanonical(l), ownerPriv);
  const line = JSON.stringify({ ...l, sig: sig.toString("base64") });
  await expect(call("PUT", V + `/members/${l.n}`, line), 201);
});
await check("old members and new approver readable", async () => {
  const m = JSON.parse((await expect(call("GET", V + "/members?since=0"), 200)).text).members;
  assert.equal(m.length, members.length + 1);
});

console.log(`\n${passed} checks passed` + (process.exitCode ? ", some FAILED" : ""));
