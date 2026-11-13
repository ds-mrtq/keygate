// Smoke test for the KeyGate relay.
//   rm -rf .wrangler/state && npx wrangler dev --port 8787 --var ALLOWED_VAULTS:vlt_smoke_local
//   node test/smoke.mjs [baseUrl]
// The vault must be empty (fresh .wrangler/state) and listed in ALLOWED_VAULTS.
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import assert from "node:assert/strict";

const BASE = process.argv[2] ?? process.env.KG_RELAY ?? "http://127.0.0.1:8787";
const vault = process.env.KG_SMOKE_VAULT ?? "vlt_smoke_local";

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { priv: privateKey, pub: publicKey.export({ format: "der", type: "spki" }).subarray(-32) };
}
const owner = newKey();
const dev = newKey();
const stranger = newKey();
const DEV = "dev_smoketest1";
// Optional: KG_SMOKE_KEYS=<file> saves the owner key so test/migrate.mjs can continue on this state.
if (process.env.KG_SMOKE_KEYS) {
  const { writeFileSync } = await import("node:fs");
  writeFileSync(process.env.KG_SMOKE_KEYS, owner.priv.export({ format: "pem", type: "pkcs8" }));
}

function lp(b) {
  const buf = Buffer.isBuffer(b) ? b : Buffer.from(b);
  const n = Buffer.alloc(4);
  n.writeUInt32BE(buf.length);
  return Buffer.concat([n, buf]);
}
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};

// Strictly increasing KG-Time per device id (the relay rejects replays).
const lastT = new Map();
function nextTime(id) {
  const t = Math.max(Date.now(), (lastT.get(id) ?? 0) + 1);
  lastT.set(id, t);
  return new Date(t).toISOString();
}

function headers(method, pathQuery, body, id, key, time) {
  const canonical = Buffer.concat([
    Buffer.from("kg/v1/relay-req\0"),
    lp(method),
    lp(pathQuery),
    lp(time),
    lp(createHash("sha256").update(body).digest("hex")),
  ]);
  return { "KG-Device": id, "KG-Time": time, "KG-Sig": sign(null, canonical, key.priv).toString("base64") };
}

async function call(method, pathQuery, body, id, key, time, base = BASE) {
  const b = body ?? "";
  const res = await fetch(base + pathQuery, {
    method,
    headers: headers(method, pathQuery, Buffer.from(b), id, key, time ?? nextTime(id)),
    body: method === "GET" ? undefined : b,
  });
  return { status: res.status, text: await res.text() };
}

// Builds a member event signed by `signKey` (owner for valid events).
function member(n, prev, type, body, signKey = owner, vaultId = vault) {
  const bodyRaw = Buffer.from(JSON.stringify(body));
  const canonical = Buffer.concat([
    Buffer.from("kg/v1/member\0"), u64(1), lp(vaultId), u64(n), lp(prev ?? ""), lp(type), lp(bodyRaw),
  ]);
  const sig = sign(null, canonical, signKey.priv);
  const hash = "sha256:" + createHash("sha256").update(Buffer.concat([canonical, sig])).digest("hex");
  return {
    hash,
    line: JSON.stringify({ v: 1, vault: vaultId, n, prev, type, body: bodyRaw.toString("base64"), sig: sig.toString("base64") }),
  };
}

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
const g = member(0, null, "genesis", { owner_pub: owner.pub.toString("base64"), created: "2026-11-10" });
const addBody = { dev: DEV, label: "smoke", ed_pub: dev.pub.toString("base64"), x_pub: "AAAA" };
const add = member(1, g.hash, "add", addBody);
const epoch = member(2, add.hash, "epoch", { epoch: 1, wraps: [] });

await check("unknown vault -> 403 (before any DO)", () =>
  expect(call("GET", "/v/vlt_not_allowed/checkpoints", "", "owner", owner), 403));
await check("no auth headers -> 401", async () => {
  assert.equal((await fetch(BASE + V + "/checkpoints")).status, 401);
});
await check("empty vault: read before genesis -> 404", () => expect(call("GET", V + "/log", "", "owner", owner), 404));
await check("oversize body (70 KiB) -> 413", () =>
  expect(call("PUT", V + `/log/${DEV}/1`, "x".repeat(70 * 1024), DEV, dev), 413));
await check("genesis request signed by wrong key -> 401", () =>
  expect(call("PUT", V + "/members/0", g.line, "owner", stranger), 401));
await check("genesis with forged event signature -> 400", async () => {
  // Request is signed by owner_pub, but the event itself is signed by someone else.
  const forged = member(0, null, "genesis", { owner_pub: owner.pub.toString("base64") }, stranger);
  await expect(call("PUT", V + "/members/0", forged.line, "owner", owner), 400);
});
await check("genesis signed by owner -> 201", async () => {
  const r = await call("PUT", V + "/members/0", g.line, "owner", owner);
  assert.equal(r.status, 201, r.status === 409 ? "vault not empty: rm -rf .wrangler/state" : r.text);
});
await check("duplicate genesis -> 409", () => expect(call("PUT", V + "/members/0", g.line, "owner", owner), 409));
await check("forged member signature -> 400", () =>
  expect(call("PUT", V + "/members/1", member(1, g.hash, "add", addBody, stranger).line, "owner", owner), 400));
await check("bad prev hash -> 400", () =>
  expect(call("PUT", V + "/members/1", member(1, "sha256:" + "0".repeat(64), "add", addBody).line, "owner", owner), 400));
await check("add device (owner-signed request) -> 201", () => expect(call("PUT", V + "/members/1", add.line, "owner", owner), 201));
await check("member gap -> 400", () =>
  expect(call("PUT", V + "/members/5", member(5, epoch.hash, "epoch", { epoch: 1 }).line, DEV, dev), 400));
await check("epoch member, request signed by device -> 201", () =>
  expect(call("PUT", V + "/members/2", epoch.line, DEV, dev), 201));

await check("log seq 1,2 -> 201", async () => {
  await expect(call("PUT", V + `/log/${DEV}/1`, '{"seq":1,"ct":"x"}', DEV, dev), 201);
  await expect(call("PUT", V + `/log/${DEV}/2`, '{"seq":2,"ct":"y"}', DEV, dev), 201);
});
await check("duplicate log seq -> 409", () => expect(call("PUT", V + `/log/${DEV}/2`, '{"seq":2,"ct":"z"}', DEV, dev), 409));
await check("log seq gap -> 400", () => expect(call("PUT", V + `/log/${DEV}/9`, "{}", DEV, dev), 400));
await check("write another device's log -> 403", () => expect(call("PUT", V + `/log/dev_other/1`, "{}", DEV, dev), 403));
await check("bad signature -> 401", () => expect(call("PUT", V + `/log/${DEV}/3`, "{}", DEV, owner), 401));
await check("stale time (-10 min) -> 401", () =>
  expect(call("PUT", V + `/log/${DEV}/3`, "{}", DEV, dev, new Date(Date.now() - 600000).toISOString()), 401));
await check("unknown device -> 401", () => expect(call("PUT", V + `/log/dev_nobody/1`, "{}", "dev_nobody", dev), 401));
await check("time replay (same KG-Time twice) -> 401", async () => {
  const t = nextTime(DEV);
  await expect(call("GET", V + "/checkpoints", "", DEV, dev, t), 200);
  await expect(call("GET", V + "/checkpoints", "", DEV, dev, t), 401);
});

await check("GET log?since", async () => {
  const r = await expect(call("GET", V + `/log?since=${DEV}:1`, "", DEV, dev), 200);
  const j = JSON.parse(r.text);
  assert.deepEqual(j.logs[DEV].map((x) => x.seq), [2]);
  assert.equal(j.logs[DEV][0].line, '{"seq":2,"ct":"y"}');
  assert.equal(j.more, false);
});
await check("GET members?since=1", async () => {
  const j = JSON.parse((await expect(call("GET", V + "/members?since=1", "", DEV, dev), 200)).text);
  assert.deepEqual(j.members.map((m) => m.n), [1, 2]);
});
await check("owner key can GET members/log/checkpoints (recovery)", async () => {
  const m = JSON.parse((await expect(call("GET", V + "/members?since=0", "", "owner", owner), 200)).text);
  assert.equal(m.members.length, 3);
  await expect(call("GET", V + "/log", "", "owner", owner), 200);
  await expect(call("GET", V + "/checkpoints", "", "owner", owner), 200);
});
await check("owner cannot write log -> 403", () => expect(call("PUT", V + `/log/owner/1`, "{}", "owner", owner), 403));

const cp = (n, seen) => JSON.stringify({ v: 1, vault, dev: DEV, time: "t", members_n: n, seen, sig: "AAAA" });
await check("checkpoint overwrite + GET", async () => {
  await expect(call("PUT", V + `/checkpoint/${DEV}`, cp(3, { [DEV]: 2 }), DEV, dev), 200);
  await expect(call("PUT", V + `/checkpoint/${DEV}`, cp(3, { [DEV]: 2, dev_x: 1 }), DEV, dev), 200);
  const j = JSON.parse((await expect(call("GET", V + "/checkpoints", "", DEV, dev), 200)).text);
  assert.equal(JSON.parse(j.checkpoints[DEV]).seen.dev_x, 1);
});
await check("checkpoint regression (members_n / seen) -> 422", async () => {
  await expect(call("PUT", V + `/checkpoint/${DEV}`, cp(2, { [DEV]: 2, dev_x: 1 }), DEV, dev), 422);
  await expect(call("PUT", V + `/checkpoint/${DEV}`, cp(3, { [DEV]: 1, dev_x: 1 }), DEV, dev), 422);
  await expect(call("PUT", V + `/checkpoint/${DEV}`, cp(3, { [DEV]: 2 }), DEV, dev), 422);
});

await check("websocket receives 'new' on write", async () => {
  const path = V + "/ws";
  const url = BASE.replace(/^http/, "ws") + path;
  const ws = new WebSocket(url, { headers: headers("GET", path, Buffer.alloc(0), DEV, dev, nextTime(DEV)) });
  const got = new Promise((resolve, reject) => {
    ws.onmessage = (e) => resolve(String(e.data));
    setTimeout(() => reject(new Error("ws timeout")), 5000);
  });
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error("ws open failed"));
  });
  await expect(call("PUT", V + `/log/${DEV}/3`, '{"seq":3}', DEV, dev), 201);
  assert.equal(await got, "new");
  ws.close();
});

await check("log pagination: 2100 lines -> more:true, then rest", async () => {
  for (let s = 4; s <= 2100; s++) await expect(call("PUT", V + `/log/${DEV}/${s}`, `{"seq":${s}}`, DEV, dev), 201);
  const p1 = JSON.parse((await expect(call("GET", V + "/log", "", DEV, dev), 200)).text);
  assert.equal(p1.more, true);
  assert.equal(p1.logs[DEV].length, 2000);
  const p2 = JSON.parse((await expect(call("GET", V + "/log?since=" + `${DEV}:2000`, "", DEV, dev), 200)).text);
  assert.equal(p2.more, false);
  assert.equal(p2.logs[DEV].length, 100);
});

// ---- C3: approver role, mailbox, view, push, pair ----
const apr = newKey();
const APR = "dev_phone00001";
const aprAdd = member(3, epoch.hash, "add", { dev: APR, label: "phone", ed_pub: apr.pub.toString("base64"), x_pub: "AAAA", role: "approver" });
const MID = "A".repeat(22);
const MID2 = "B".repeat(22);
const pairPut = (code, body = "REGCODE") => fetch(BASE + V + "/pair/" + code, { method: "PUT", body }).then(async (r) => ({ status: r.status, text: await r.text() }));

await check("unknown role -> 400", () =>
  expect(call("PUT", V + "/members/3", member(3, epoch.hash, "add", { dev: APR, label: "p", ed_pub: apr.pub.toString("base64"), x_pub: "AAAA", role: "evil" }).line, "owner", owner), 400));
await check("add approver -> 201", () => expect(call("PUT", V + "/members/3", aprAdd.line, "owner", owner), 201));
await check("approver PUT log -> 403", () => expect(call("PUT", V + `/log/${APR}/1`, "{}", APR, apr), 403));
await check("approver PUT checkpoint -> 403", () => expect(call("PUT", V + `/checkpoint/${APR}`, cp(3, {}), APR, apr), 403));
await check("msg put/get/delete + duplicate 409", async () => {
  await expect(call("PUT", V + `/msg/${DEV}/${MID}`, "hello", APR, apr), 201);
  await expect(call("PUT", V + `/msg/${DEV}/${MID}`, "hello", APR, apr), 409);
  await expect(call("PUT", V + `/msg/${DEV}/${MID2}`, "second", APR, apr), 201);
  const j = JSON.parse((await expect(call("GET", V + `/msg/${DEV}`, "", DEV, dev), 200)).text);
  assert.deepEqual(j.msgs, [{ id: MID, from: APR, body: "hello" }, { id: MID2, from: APR, body: "second" }]);
  await expect(call("DELETE", V + `/msg/${DEV}/${MID}`, "", DEV, dev), 204);
  await expect(call("DELETE", V + `/msg/${DEV}/${MID}`, "", DEV, dev), 204);
  const j2 = JSON.parse((await expect(call("GET", V + `/msg/${DEV}`, "", DEV, dev), 200)).text);
  assert.equal(j2.msgs.length, 1);
});
await check("msg: other device mailbox -> 403, to approver -> 400, bad id -> 400", async () => {
  await expect(call("GET", V + `/msg/${DEV}`, "", APR, apr), 403);
  await expect(call("DELETE", V + `/msg/${DEV}/${MID2}`, "", APR, apr), 403);
  await expect(call("PUT", V + `/msg/${APR}/${MID}`, "x", DEV, dev), 400);
  await expect(call("PUT", V + `/msg/${DEV}/short`, "x", APR, apr), 400);
});
await check("msg: 17 KiB -> 413, 51st pending -> 429", async () => {
  await expect(call("PUT", V + `/msg/${DEV}/${"C".repeat(22)}`, "x".repeat(17 * 1024), APR, apr), 413);
  for (let i = 0; i < 49; i++) await expect(call("PUT", V + `/msg/${DEV}/m${String(i).padStart(21, "0")}`, "x", APR, apr), 201);
  await expect(call("PUT", V + `/msg/${DEV}/${"D".repeat(22)}`, "x", APR, apr), 429);
});
await check("view put/get, have filter, 200 KiB body", async () => {
  await expect(call("PUT", V + `/view/${APR}`, "v1", DEV, dev), 200);
  let j = JSON.parse((await expect(call("GET", V + `/view/${APR}`, "", APR, apr), 200)).text);
  assert.deepEqual(j.views, [{ from: DEV, ver: 1, body: "v1" }]);
  j = JSON.parse((await expect(call("GET", V + `/view/${APR}?have=${DEV}:1`, "", APR, apr), 200)).text);
  assert.deepEqual(j.views, []);
  await expect(call("PUT", V + `/view/${APR}`, "x".repeat(200 * 1024), DEV, dev, undefined), 200);
  j = JSON.parse((await expect(call("GET", V + `/view/${APR}?have=${DEV}:1`, "", APR, apr), 200)).text);
  assert.equal(j.views[0].ver, 2);
  await expect(call("GET", V + `/view/${APR}`, "", DEV, dev), 403);
  await expect(call("PUT", V + `/view/${DEV}`, "v", DEV, dev), 400);
});
await check("approver writes view -> 403", () => expect(call("PUT", V + `/view/${APR}`, "v", APR, apr), 403));
await check("view body 300 KiB -> 413", () => expect(call("PUT", V + `/view/${APR}`, "x".repeat(300 * 1024), DEV, dev), 413));
const pairOpen = (code, id = DEV, key = dev) => call("PUT", V + "/pair-open/" + code, "", id, key);
const pairGet = (code, id = DEV, key = dev) => call("GET", V + "/pair/" + code, "", id, key);
await check("pair: unsigned put without an open slot -> 404", async () => {
  await expect(pairPut("ABCDEFGHABCDEFGH"), 404);
  await expect(pairPut("ABCDEFGH"), 400);
});
await check("pair-open: approver/owner -> 403, bad code -> 400, unsigned -> 401", async () => {
  await expect(pairOpen("ABCDEFGHABCDEFGH", APR, apr), 403);
  await expect(pairOpen("ABCDEFGHABCDEFGH", "owner", owner), 403);
  await expect(pairOpen("ABCDEFG1ABCDEFGH"), 400);
  assert.equal((await fetch(BASE + V + "/pair-open/ABCDEFGHABCDEFGH", { method: "PUT", body: "" })).status, 401);
});
await check("pair: open, get before fill 204, fill 201, refill 409, get 200 then 404", async () => {
  await expect(pairOpen("ABCDEFGHABCDEFGH"), 201);
  await expect(pairGet("ABCDEFGHABCDEFGH"), 204);
  await expect(call("GET", V + "/pair/ABCDEFGHABCDEFGH", "", APR, apr), 403);
  await expect(pairPut("ABCDEFGHABCDEFGH", "x".repeat(2048)), 413);
  await expect(pairPut("ABCDEFGHABCDEFGH"), 201);
  await expect(pairPut("ABCDEFGHABCDEFGH", "OTHER"), 409);
  const r = await expect(pairGet("ABCDEFGHABCDEFGH"), 200);
  assert.equal(r.text, "REGCODE");
  await expect(pairGet("ABCDEFGHABCDEFGH"), 404);
  await expect(pairPut("ABCDEFGHABCDEFGH"), 404);
});
await check("pair-open: second open by the same device replaces the first; code collision 409", async () => {
  await expect(pairOpen("AAAAAAAAAAAAAAAA"), 201);
  await expect(pairOpen("BBBBBBBBBBBBBBBB"), 201);
  await expect(pairPut("AAAAAAAAAAAAAAAA"), 404);
  await expect(pairGet("AAAAAAAAAAAAAAAA"), 404);
  await expect(pairPut("BBBBBBBBBBBBBBBB"), 201);
  await expect(pairGet("BBBBBBBBBBBBBBBB"), 200);
});
await check("origin: pair keeps the gate's origin (client header ignored), devices list for key holders", async () => {
  await expect(pairOpen("ORIGINAAORIGINAA"), 201);
  const spoof = Buffer.from(JSON.stringify({ ip: "6.6.6.6", ua: "spoof" })).toString("base64");
  const put = await fetch(BASE + V + "/pair/ORIGINAAORIGINAA", { method: "PUT", body: "REG", headers: { "KG-Origin": spoof, "User-Agent": "kg-smoke-phone" } });
  assert.equal(put.status, 201);
  const path = V + "/pair/ORIGINAAORIGINAA";
  const res = await fetch(BASE + path, { headers: headers("GET", path, Buffer.from(""), DEV, dev, nextTime(DEV)) });
  assert.equal(res.status, 200);
  const o = JSON.parse(Buffer.from(res.headers.get("KG-Pair-Origin"), "base64").toString());
  assert.equal(o.ua, "kg-smoke-phone");
  assert.notEqual(o.ip, "6.6.6.6");
  const j = JSON.parse((await expect(call("GET", V + "/devices", "", DEV, dev), 200)).text);
  const me = j.devices.find((d) => d.dev === DEV);
  assert.ok(me && me.t > 0 && typeof me.ip === "string");
  await expect(call("GET", V + "/devices", "", APR, apr), 403);
});
await check("push: foreign host -> 400, apple host -> 200, other dev -> 403, delete 204", async () => {
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "https://evil.example.com/x" }), APR, apr), 400);
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "http://web.push.apple.com/x" }), APR, apr), 400);
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "https://evil.googleapis.com/x" }), APR, apr), 400);
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "https://web.push.apple.com:444/x" }), APR, apr), 400);
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "https://web.push.apple.com/abc" }), APR, apr), 200);
  await expect(call("PUT", V + `/push/${APR}`, JSON.stringify({ endpoint: "https://web.push.apple.com/abc" }), DEV, dev), 403);
  await expect(call("DELETE", V + `/push/${APR}`, "", APR, apr), 204);
});
await check("/push-key without VAPID_PUBLIC -> 404", async () => {
  assert.equal((await fetch(BASE + "/push-key")).status, 404);
});

const revAp = member(4, aprAdd.hash, "revoke-approver", { dev: APR, by: DEV, reason: "smoke" }, dev);
await check("revoke-approver: wrong signer / approver as signer -> 400, key holder -> 201, phone rejected", async () => {
  const forged = member(4, aprAdd.hash, "revoke-approver", { dev: APR, by: DEV, reason: "smoke" }, apr);
  await expect(call("PUT", V + "/members/4", forged.line, DEV, dev), 400);
  const self = member(4, aprAdd.hash, "revoke-approver", { dev: APR, by: APR, reason: "smoke" }, apr);
  await expect(call("PUT", V + "/members/4", self.line, APR, apr), 400);
  const holder = member(4, aprAdd.hash, "revoke-approver", { dev: DEV, by: DEV, reason: "smoke" }, dev);
  await expect(call("PUT", V + "/members/4", holder.line, DEV, dev), 400);
  const long = member(4, aprAdd.hash, "revoke-approver", { dev: APR, by: DEV, reason: "x".repeat(300) }, dev);
  await expect(call("PUT", V + "/members/4", long.line, DEV, dev), 400);
  const caseKey = member(4, aprAdd.hash, "revoke-approver", { dev: APR, by: DEV, reason: "", Dev: DEV }, dev);
  await expect(call("PUT", V + "/members/4", caseKey.line, DEV, dev), 400);
  const spaced = revAp.line.replace('"n":4', '"n": 4');
  await expect(call("PUT", V + "/members/4", spaced, DEV, dev), 400);
  await expect(call("PUT", V + "/members/4", revAp.line, DEV, dev), 201);
  await expect(call("GET", V + `/msg/${APR}`, "", APR, apr), 401);
});

let tail = revAp;
await check("revoke-approver between a revoke and its epoch -> 400", async () => {
  const k2 = newKey(), k3 = newKey();
  const a2 = member(5, revAp.hash, "add", { dev: "dev_phone00002", label: "p2", ed_pub: k2.pub.toString("base64"), x_pub: "AAAA", role: "approver" });
  await expect(call("PUT", V + "/members/5", a2.line, "owner", owner), 201);
  const a3 = member(6, a2.hash, "add", { dev: "dev_phone00003", label: "p3", ed_pub: k3.pub.toString("base64"), x_pub: "AAAA", role: "approver" });
  await expect(call("PUT", V + "/members/6", a3.line, "owner", owner), 201);
  const r2 = member(7, a3.hash, "revoke", { dev: "dev_phone00002", reason: "x", last_seq: 0, last_hash: "" });
  await expect(call("PUT", V + "/members/7", r2.line, "owner", owner), 201);
  const wedge = member(8, r2.hash, "revoke-approver", { dev: "dev_phone00003", by: DEV, reason: "" }, dev);
  await expect(call("PUT", V + "/members/8", wedge.line, DEV, dev), 400);
  const e2 = member(8, r2.hash, "epoch", { epoch: 2, wraps: [] });
  await expect(call("PUT", V + "/members/8", e2.line, "owner", owner), 201);
  tail = e2;
});

await check("revoke: revoked device is rejected, owner still works", async () => {
  const rev = member(9, tail.hash, "revoke", { dev: DEV, reason: "smoke", last_seq: 2100 });
  await expect(call("PUT", V + "/members/9", rev.line, "owner", owner), 201);
  const ep2 = member(10, rev.hash, "epoch", { epoch: 3, wraps: [] });
  await expect(call("PUT", V + "/members/10", ep2.line, "owner", owner), 201);
  tail = ep2;
  await expect(call("GET", V + "/checkpoints", "", DEV, dev), 401);
  await expect(call("GET", V + "/checkpoints", "", "owner", owner), 200);
});

await check("pair: another key-holder device cannot read the slot", async () => {
  const k2 = newKey(), k3 = newKey();
  const D2 = "dev_smoketest2", D3 = "dev_smoketest3";
  const a2 = member(11, tail.hash, "add", { dev: D2, label: "two", ed_pub: k2.pub.toString("base64"), x_pub: "AAAA" });
  await expect(call("PUT", V + "/members/11", a2.line, "owner", owner), 201);
  const a3 = member(12, a2.hash, "add", { dev: D3, label: "three", ed_pub: k3.pub.toString("base64"), x_pub: "AAAA" });
  await expect(call("PUT", V + "/members/12", a3.line, "owner", owner), 201);
  await expect(pairOpen("CCCCCCCCCCCCCCCC", D2, k2), 201);
  await expect(pairPut("CCCCCCCCCCCCCCCC"), 201);
  await expect(pairGet("CCCCCCCCCCCCCCCC", D3, k3), 404);
  const r = await expect(pairGet("CCCCCCCCCCCCCCCC", D2, k2), 200);
  assert.equal(r.text, "REGCODE");
});

console.log(`\n${passed} checks passed` + (process.exitCode ? ", some FAILED" : ""));
