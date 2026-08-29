import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { after, before, test } from "node:test";
import worker from "../src/index.js";
import { importPublicKey, keyId, seal, wrapDek } from "../src/crypto.js";

// Key rotation is the branchiest fail-closed path in the Worker and the one that fails silently
// in production if it is wrong: a blob sealed under the previous key must stay readable until it
// is re-sealed, and a blob under an unknown key must never open. Driven through the real /env/facts
// endpoint against a two-key env; the control plane serves whichever blob the test stages.

const pair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
};

const current = pair();
const previous = pair();
const stranger = pair();

const env = {
  VAULT_PUBLIC_KEY: current.pub,
  VAULT_PRIVATE_KEY: current.priv,
  VAULT_PREV_PUBLIC_KEY: previous.pub,
  VAULT_PREV_PRIVATE_KEY: previous.priv,
  VAULT_BACKEND_KEY: "backend-shared-key",
  VAULT_BOOT_KEY: "boot-zone-key",
  BACKEND_URL: "https://backend.test",
  RUNNER_URL: "https://runner.test",
};

// Mirrors storageAad in src/index.js; a blob is bound to the identity it was sealed for.
const storageAad = (uid, scope) => `vault:env:v1:${uid}:${scope}`;

// A storage blob the way handoverPost builds one, but under a chosen public key.
async function blobUnder(pubPem, uid, scope, plaintext) {
  const dek = crypto.getRandomValues(new Uint8Array(32));
  return {
    v: 1,
    kid: await keyId(pubPem),
    key: await wrapDek(await importPublicKey(pubPem), dek),
    box: await seal(dek, plaintext, storageAad(uid, scope)),
  };
}

// The control plane serves whatever blob the current test staged.
let staged = null;
const realFetch = globalThis.fetch;
before(() => {
  globalThis.fetch = async (url) =>
    new URL(url).pathname === "/internal/vault/env"
      ? Response.json({ blob: staged })
      : Response.json({ error: "not found" }, { status: 404 });
});
after(() => {
  globalThis.fetch = realFetch;
});

const facts = () =>
  worker.fetch(
    new Request("https://vault.test/env/facts", {
      method: "POST",
      headers: { "content-type": "application/json", "x-vault-key": env.VAULT_BOOT_KEY },
      body: JSON.stringify({ uid: "user-1", scope: "staging" }),
    }),
    env,
  );

test("a blob sealed under the previous key still opens", async () => {
  staged = await blobUnder(previous.pub, "user-1", "staging", "OPENAI_API_KEY=sk-old");
  const res = await facts();
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).provided, ["OPENAI_API_KEY"]);
});

test("a blob sealed under the current key opens", async () => {
  staged = await blobUnder(current.pub, "user-1", "staging", "OPENAI_API_KEY=sk-new");
  assert.equal((await facts()).status, 200);
});

test("a blob sealed under an unknown key does not open", async () => {
  staged = await blobUnder(stranger.pub, "user-1", "staging", "OPENAI_API_KEY=sk-x");
  assert.equal((await facts()).status, 400);
});
