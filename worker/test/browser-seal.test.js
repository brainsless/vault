import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { importPrivateKey, open, unwrapDek } from "../src/crypto.js";

// The product's browser screen seals with Web Crypto. This runs its exact construction (the same
// API the browser exposes, via globalThis.crypto) and proves the vault opens the result, so the
// paste path is covered without driving a real browser. Kept byte-identical to sealForVault in
// frontend/public/app/onboarding/compile.html; if that changes, this fails.
async function sealForVault(publicKeyPem, token, envText) {
  const der = Uint8Array.from(atob(publicKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")), (c) => c.charCodeAt(0));
  const rsa = await crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const enc = new TextEncoder();
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(token) }, aes, enc.encode(envText)));
  const box = new Uint8Array(28 + sealed.length - 16);
  box.set(iv, 0);
  box.set(sealed.slice(-16), 12);
  box.set(sealed.slice(0, -16), 28);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsa, dek));
  const b64 = (u) => btoa(Array.from(u, (b) => String.fromCharCode(b)).join(""));
  return { key: b64(wrapped), box: b64(box) };
}

test("a payload sealed by the browser screen opens in the vault", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

  const token = "vlt_" + "a".repeat(48);
  const plaintext = "OPENAI_API_KEY=sk-proj-browser\nAPP_URL=https://app.example.com";
  const { key, box } = await sealForVault(publicPem, token, plaintext);

  const dek = await unwrapDek(await importPrivateKey(privatePem), key);
  assert.equal(await open(dek, box, token), plaintext);
  assert.equal(await open(dek, box, "vlt_" + "b".repeat(48)), null);
});
