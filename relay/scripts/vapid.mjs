// Generates a VAPID key pair (ECDSA P-256).
//   node scripts/vapid.mjs --out .vapid-private.json
// Writes the private JWK to --out and prints the public key (base64url, uncompressed point).
import { writeFileSync } from "node:fs";

const i = process.argv.indexOf("--out");
const out = i > 0 ? process.argv[i + 1] : undefined;
if (!out) {
  console.error("usage: node scripts/vapid.mjs --out <file>");
  process.exit(2);
}
const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
writeFileSync(out, JSON.stringify(await crypto.subtle.exportKey("jwk", kp.privateKey)), { mode: 0o600 });
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
console.log(Buffer.from(raw).toString("base64url"));
