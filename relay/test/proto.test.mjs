// Go <-> WebCrypto compatibility check for the PWA protocol, against testdata/vectors.json.
//   node test/proto.test.mjs
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as P from "../public/app/proto.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "testdata", "vectors.json"), "utf8"));
const vault = "vlt_abcdefghijklmnop";
const laptop = "dev_abcdefghij";
const ap = V.approver;
const unhex = P.unhex;

let n = 0;
async function check(name, fn) {
  await fn();
  n++;
  console.log("ok  " + name);
}

const laptopXPriv = unhex(V.inputs.device_x_priv);
const laptopXPub = await P.xPublicOf(laptopXPriv);
const laptopEdSeed = unhex(V.inputs.device_ed_seed);
const laptopEdPub = unhex(V.inputs.device_ed_pub);
const apEdPub = unhex(ap.ed_pub);
const apXPub = unhex(ap.x_pub);
const t0 = Date.parse(V.msg.time);

await check("x_pub derived from x_priv matches vectors", async () => {
  assert.deepEqual(await P.xPublicOf(unhex(ap.x_priv)), apXPub);
});

await check("open msg (approver -> laptop)", async () => {
  const self = { dev: laptop, xPriv: await P.importXPrivate(laptopXPriv), xPub: laptopXPub };
  const r = await P.openEnvelope(vault, self, V.msg.line, (d) => (d === ap.dev ? apEdPub : null));
  assert.equal(r.from, ap.dev);
  assert.equal(r.time, t0);
  assert.equal(new TextDecoder().decode(r.plaintext), V.msg.plaintext);
});

await check("seal msg with fixed eph/nonce reproduces line byte for byte", async () => {
  const line = await P.sealEnvelope(vault, { dev: ap.dev, edPriv: await P.importEdPrivate(unhex(ap.ed_seed)) }, laptop, laptopXPub, V.msg.plaintext, t0, {
    ephPriv: unhex(V.msg.eph_priv),
    nonce: unhex(V.msg.nonce),
    id: V.msg.id,
  });
  assert.equal(line, V.msg.line);
});

await check("open msg.reply (laptop -> approver) with approver x_priv", async () => {
  const r = V.msg.reply;
  const self = { dev: ap.dev, xPriv: await P.importXPrivate(unhex(ap.x_priv)), xPub: apXPub };
  const o = await P.openEnvelope(vault, self, r.line, (d) => (d === laptop ? laptopEdPub : null));
  assert.equal(o.from, laptop);
  assert.equal(new TextDecoder().decode(o.plaintext), r.plaintext);
});

await check("seal msg.reply reproduces line", async () => {
  const r = V.msg.reply;
  const line = await P.sealEnvelope(vault, { dev: laptop, edPriv: await P.importEdPrivate(laptopEdSeed) }, ap.dev, apXPub, r.plaintext, Date.parse(r.time), {
    ephPriv: unhex(r.eph_priv),
    nonce: unhex(r.nonce),
    id: r.id,
  });
  assert.equal(line, r.line);
});

await check("open rejects tampering, wrong recipient, unknown sender", async () => {
  const self = { dev: laptop, xPriv: await P.importXPrivate(laptopXPriv), xPub: laptopXPub };
  const known = (d) => (d === ap.dev ? apEdPub : null);
  const e = JSON.parse(V.msg.line);
  const flip = { ...e, ct: P.b64(Object.assign(P.unb64(e.ct), { 0: P.unb64(e.ct)[0] ^ 1 })) };
  await assert.rejects(P.openEnvelope(vault, self, JSON.stringify(flip), known), /bad envelope/);
  await assert.rejects(P.openEnvelope(vault, { ...self, dev: "dev_other00000" }, V.msg.line, known), /bad envelope/);
  await assert.rejects(P.openEnvelope(vault, self, V.msg.line, () => null), /bad envelope/);
  await assert.rejects(P.openEnvelope(vault, self, JSON.stringify({ ...e, extra: 1 }), known), /bad envelope/);
  await assert.rejects(P.openEnvelope("vlt_otherotherother", self, V.msg.line, known), /bad envelope/);
});

const memberLines = V.members.map((m) => m.line);

await check("verifyMembers: pin and approver role", async () => {
  const st = await P.verifyMembers(memberLines, vault, ap.genesis_pin);
  assert.equal(st.pin, ap.genesis_pin);
  assert.equal(st.count, 4);
  assert.equal(st.genesisHash, V.members[0].hash);
  assert.equal(st.head, V.members[3].hash);
  const d = st.devices.find((x) => x.dev === ap.dev);
  assert.equal(d.role, "approver");
  assert.equal(d.revoked, false);
  assert.deepEqual(d.edPub, apEdPub);
  assert.deepEqual(d.xPub, apXPub);
  assert.equal(d.label, "iphone");
  assert.equal(st.devices.find((x) => x.dev === laptop).role, "");
});

await check("verifyMembers rejects wrong pin, tampering, truncated chain gap", async () => {
  await assert.rejects(P.verifyMembers(memberLines, vault, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"), /pin mismatch/);
  const bad = memberLines.slice();
  const e = JSON.parse(bad[3]);
  e.sig = P.b64(new Uint8Array(64));
  bad[3] = JSON.stringify(e);
  await assert.rejects(P.verifyMembers(bad, vault, ap.genesis_pin), /owner signature/);
  await assert.rejects(P.verifyMembers([memberLines[0], memberLines[3]], vault, ap.genesis_pin), /event 1/);
});

await check("verifyMembers: revoke-approver signed by the laptop key", async () => {
  const lines = [...memberLines, V.revoke_approver.line];
  const st = await P.verifyMembers(lines, vault, ap.genesis_pin);
  assert.equal(st.count, 5);
  assert.equal(st.head, V.revoke_approver.hash);
  assert.equal(st.devices.find((x) => x.dev === ap.dev).revoked, true);
  assert.equal(st.devices.find((x) => x.dev === laptop).revoked, false);
  const bad = lines.slice();
  const e = JSON.parse(bad[4]);
  e.sig = P.b64(new Uint8Array(64));
  bad[4] = JSON.stringify(e);
  await assert.rejects(P.verifyMembers(bad, vault, ap.genesis_pin), /device signature/);
});

await check("checkRollback: shorter, forked head, forked history, honest growth", async () => {
  const full = await P.verifyMembers(memberLines, vault, ap.genesis_pin);
  const upTo = (n) => P.verifyMembers(memberLines.slice(0, n), vault, ap.genesis_pin);
  const mark = (st) => ({ count: st.count, head: st.head });
  P.checkRollback(full, null);
  P.checkRollback(full, mark(full)); // same
  P.checkRollback(full, mark(await upTo(2))); // grew from a prefix
  const short = await upTo(3); // relay dropped the last (e.g. revoke) event
  assert.throws(() => P.checkRollback(short, mark(full)), /quay lui/);
  assert.throws(() => P.checkRollback(full, { count: full.count, head: "sha256:" + "0".repeat(64) }), /quay lui/); // same length, other head
  assert.throws(() => P.checkRollback(full, { count: 2, head: "sha256:" + "0".repeat(64) }), /quay lui/); // longer, forked history
});

await check("registrationCode equals approver.code", async () => {
  assert.equal(P.registrationCode(JSON.parse(ap.add_body_json)), ap.code);
});

await check("codeWords equals approver.words", async () => {
  assert.equal(await P.codeWords(ap.code), ap.words);
});

await check("pendingDigest equals pending_digest.digest", async () => {
  assert.equal(await P.pendingDigest(V.pending_digest.pending), V.pending_digest.digest);
});

await check("canonicalRelay layout and base32/base64 helpers", async () => {
  const c = await P.canonicalRelay("GET", "/v/x/members?since=0", "2026-11-11T08:00:00.000Z", null);
  const want = Buffer.concat([
    Buffer.from("kg/v1/relay-req\0"),
    ...["GET", "/v/x/members?since=0", "2026-11-11T08:00:00.000Z", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"].map((s) => {
      const b = Buffer.from(s);
      const l = Buffer.alloc(4);
      l.writeUInt32BE(b.length);
      return Buffer.concat([l, b]);
    }),
  ]);
  assert.deepEqual(Buffer.from(c), want);
  for (const len of [0, 1, 2, 3, 4, 5, 15, 16, 31]) {
    const r = P.randomBytes(len);
    assert.deepEqual(P.unbase32(P.base32(r)), r);
    assert.deepEqual(P.unb64url(P.b64url(r)), r);
  }
  assert.equal(P.base32(new TextEncoder().encode("foobar")), "MZXW6YTBOI");
});

console.log(`${n} checks passed`);
