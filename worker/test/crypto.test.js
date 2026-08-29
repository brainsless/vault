import assert from "node:assert/strict";
import { constants, createCipheriv, generateKeyPairSync, publicEncrypt, randomBytes } from "node:crypto";
import { test } from "node:test";
import { importPrivateKey, importPublicKey, keyId, open, seal, unwrapDek, wrapDek } from "../src/crypto.js";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

test("seal/open round-trips under the right AAD and fails closed under any other", async () => {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const box = await seal(dek, "OPENAI_API_KEY=sk-test", "token-1");
  assert.equal(await open(dek, box, "token-1"), "OPENAI_API_KEY=sk-test");
  assert.equal(await open(dek, box, "token-2"), null);
  assert.equal(await open(crypto.getRandomValues(new Uint8Array(32)), box, "token-1"), null);
});

test("a tampered box does not open", async () => {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const box = await seal(dek, "A=1", "aad");
  const raw = Buffer.from(box, "base64");
  raw[raw.length - 1] ^= 1;
  assert.equal(await open(dek, raw.toString("base64"), "aad"), null);
});

test("wrap/unwrap round-trips a 32-byte DEK and refuses anything else", async () => {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrapDek(await importPublicKey(publicPem), dek);
  const unwrapped = await unwrapDek(await importPrivateKey(privatePem), wrapped);
  assert.deepEqual([...unwrapped], [...dek]);
  const short = await wrapDek(await importPublicKey(publicPem), crypto.getRandomValues(new Uint8Array(16)));
  assert.equal(await unwrapDek(await importPrivateKey(privatePem), short), null);
  assert.equal(await unwrapDek(await importPrivateKey(privatePem), "not-base64!!"), null);
});

test("keyId is stable for a key and different across keys", async () => {
  const again = await keyId(publicPem);
  assert.equal(await keyId(publicPem), again);
  assert.match(again, /^[0-9a-f]{16}$/);
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 })
    .publicKey.export({ type: "spki", format: "pem" })
    .toString();
  assert.notEqual(await keyId(other), again);
});

// The CLI's exact sealing construction (node:crypto) must open under the Worker's Web Crypto:
// AES-256-GCM as iv|tag|body with the token as AAD, the DEK wrapped RSA-OAEP-SHA256.
test("a payload sealed the CLI's way opens here", async () => {
  const token = `vlt_${randomBytes(24).toString("hex")}`;
  const plaintext = "OPENAI_API_KEY=sk-test-123\nAPP_SECRET=deadbeefdeadbeef";
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(Buffer.from(token, "utf8"));
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const key = publicEncrypt(
    { key: publicPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
    dek,
  ).toString("base64");
  const box = Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64");

  const unwrapped = await unwrapDek(await importPrivateKey(privatePem), key);
  assert.equal(await open(unwrapped, box, token), plaintext);
});
