import assert from "node:assert/strict";
import { constants, createCipheriv, generateKeyPairSync, publicEncrypt, randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import worker from "../src/index.js";

// The whole journey against a faked control plane and runner: mint, seal the CLI's way, hand
// over, derive facts, inject. The one property every step is measured against: no plaintext
// value ever appears in anything sent to the control plane.

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const env = {
  VAULT_PUBLIC_KEY: publicKey.export({ type: "spki", format: "pem" }).toString(),
  VAULT_PRIVATE_KEY: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  VAULT_BACKEND_KEY: "backend-shared-key",
  VAULT_BOOT_KEY: "boot-zone-key",
  BACKEND_URL: "https://backend.test",
  RUNNER_URL: "https://runner.test",
  VAULT_VERSION: "test",
  VAULT_COMMIT: "test",
};

const TOKEN = `vlt_${randomBytes(24).toString("hex")}`;
const SECRET_VALUE = "sk-test-supersecret-value-1234";
const SANDBOX_ID = "run-" + "0f0e828c-2f21-4c96-8f4a-2f4d63f0a111";

// Everything the vault says to anyone else, kept for the leak assertion.
const outbound = [];
const stored = {};
const runnerCalls = [];

// The control plane serves the blob only to the identity that owns it -- keyed by uid, the way
// revealSecret is. A `serveBlobTo` override lets one test force a mismatched blob to prove the
// AAD binding still refuses it (defense in depth behind the identity-keyed fetch).
let serveBlobTo = "user-1";
let blobFetchStatus = 200;
const realFetch = globalThis.fetch;
before(() => {
  globalThis.fetch = async (url, init = {}) => {
    outbound.push({ url: String(url), body: init.body ?? "" });
    const { pathname } = new URL(url);
    if (pathname === `/internal/vault/handover/${TOKEN}`) {
      if (init.method === "GET") {
        return Response.json({ names: ["OPENAI_API_KEY", "MISSING_ONE"], uid: "user-1", scope: "staging:conn-1" });
      }
      Object.assign(stored, JSON.parse(init.body));
      return Response.json({ ok: true });
    }
    if (pathname === "/internal/vault/env") {
      if (blobFetchStatus !== 200) return Response.json({ error: "down" }, { status: blobFetchStatus });
      const { uid } = JSON.parse(init.body);
      return Response.json({ blob: uid === serveBlobTo ? stored.blob : null });
    }
    if (pathname.startsWith("/write/") || pathname.startsWith("/arm/")) {
      runnerCalls.push({ url: String(url), pathname, body: JSON.parse(init.body) });
      return Response.json({ success: true });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  };
});
after(() => {
  globalThis.fetch = realFetch;
});

const call = (method, path, body, headers = {}) =>
  worker.fetch(
    new Request(`https://vault.test${path}`, {
      method,
      headers: { "content-type": "application/json", ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    env,
  );

function sealLikeTheCli(publicPem, plaintext, aad) {
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return {
    key: publicEncrypt({ key: publicPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, dek).toString("base64"),
    box: Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64"),
  };
}

test("handover GET hands out the sealing key for a live token and 404s everything else", async () => {
  const res = await call("GET", `/${TOKEN}`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.names, ["OPENAI_API_KEY", "MISSING_ONE"]);
  assert.equal(body.publicKey, env.VAULT_PUBLIC_KEY);
  assert.match(body.kid, /^[0-9a-f]{16}$/);
  assert.equal((await call("GET", `/vlt_${"0".repeat(48)}`)).status, 404);
});

test("handover POST opens, classifies, and stores only ciphertext of only the accepted lines", async () => {
  const plaintext = [`OPENAI_API_KEY=${SECRET_VALUE}`, "STRIPE_KEY=sk_live_forbidden", "PORT=9999"].join("\n");
  const res = await call("POST", `/${TOKEN}`, {
    ...sealLikeTheCli(env.VAULT_PUBLIC_KEY, plaintext, TOKEN),
    refused: [{ name: "DATABASE_URL", reason: "the sandbox makes its own database, cache and queue" }],
  });
  assert.equal(res.status, 200);
  const report = await res.json();
  assert.deepEqual(report.accepted, ["OPENAI_API_KEY"]);
  assert.deepEqual(report.refused.map((r) => r.name).sort(), ["DATABASE_URL", "PORT", "STRIPE_KEY"]);
  assert.deepEqual(report.missing, ["MISSING_ONE"]);

  assert.equal(stored.blob.v, 1);
  assert.deepEqual(stored.report.accepted, ["OPENAI_API_KEY"]);
});

test("a payload sealed for one token does not open under another", async () => {
  const res = await call("POST", `/${TOKEN}`, sealLikeTheCli(env.VAULT_PUBLIC_KEY, "A=12345678", "vlt_other"));
  assert.equal(res.status, 400);
});

test("facts derives non-secret facts from the stored blob without leaking a value", async () => {
  // The boot zone names an identity and never sends the blob; the vault fetches it.
  const res = await call(
    "POST",
    "/env/facts",
    { uid: "user-1", scope: "staging:conn-1" },
    { "x-vault-key": env.VAULT_BOOT_KEY },
  );
  assert.equal(res.status, 200);
  const facts = await res.json();
  assert.deepEqual(facts.provided, ["OPENAI_API_KEY"]);
  assert.ok(!JSON.stringify(facts).includes(SECRET_VALUE));
});

test("facts is reachable only with the boot key, never the backend key", async () => {
  // The zone split: the control plane's own callback key cannot ask for a decrypt.
  const withBackendKey = await call(
    "POST",
    "/env/facts",
    { uid: "user-1", scope: "staging:conn-1" },
    { "x-vault-key": env.VAULT_BACKEND_KEY },
  );
  assert.equal(withBackendKey.status, 404);
  const unauthed = await call("POST", "/env/facts", { uid: "user-1", scope: "staging:conn-1" });
  assert.equal(unauthed.status, 404);
});

test("a foreign identity gets an empty environment, and a mismatched blob still fails the AAD", async () => {
  // The control plane serves user-2 their own (absent) environment: no leak, an empty result.
  const foreign = await call(
    "POST",
    "/env/facts",
    { uid: "user-2", scope: "staging:conn-1" },
    { "x-vault-key": env.VAULT_BOOT_KEY },
  );
  assert.equal(foreign.status, 200);
  assert.deepEqual((await foreign.json()).provided, []);

  // Defense in depth: even if the control plane were tricked into serving user-1's blob to a
  // user-2 request, the storage AAD binds it to user-1 and it fails to open.
  serveBlobTo = "user-2";
  const mismatched = await call(
    "POST",
    "/env/facts",
    { uid: "user-2", scope: "staging:conn-1" },
    { "x-vault-key": env.VAULT_BOOT_KEY },
  );
  serveBlobTo = "user-1";
  assert.equal(mismatched.status, 400);
});

test("a control-plane fault fails closed, never as an empty environment", async () => {
  // A 500/timeout on the blob fetch must not be mistaken for "this tenant has no env" -- that
  // would boot an app with its real secrets silently absent.
  blobFetchStatus = 503;
  const res = await call(
    "POST",
    "/env/facts",
    { uid: "user-1", scope: "staging:conn-1" },
    { "x-vault-key": env.VAULT_BOOT_KEY },
  );
  blobFetchStatus = 200;
  assert.equal(res.status, 400);
});

test("inject writes the merged env into the sandbox and arms the log mask", async () => {
  const res = await call(
    "POST",
    "/env/inject",
    {
      uid: "user-1",
      scope: "staging:conn-1",
      sandboxId: SANDBOX_ID,
      capability: "v1.cap.cap",
      path: "/workspace/repo/.env.standin",
      before: ["STANDIN_SECRET=standin-value"],
      after: ["PORT=4123", "HOST=0.0.0.0"],
    },
    { "x-vault-key": env.VAULT_BOOT_KEY },
  );
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { written: true, provided: ["OPENAI_API_KEY"], refused: [] });

  const write = runnerCalls.find((c) => c.pathname === `/write/${SANDBOX_ID}`);
  const written = Buffer.from(write.body.b64, "base64").toString("utf8");
  assert.equal(written, `STANDIN_SECRET='standin-value'\nOPENAI_API_KEY='${SECRET_VALUE}'\nPORT='4123'\nHOST='0.0.0.0'\n`);
  // The destination is the vault's own pinned RUNNER_URL, never a request field.
  assert.ok(write.url.startsWith(env.RUNNER_URL));

  const arm = runnerCalls.find((c) => c.pathname === `/arm/${SANDBOX_ID}`);
  assert.deepEqual(arm.body.pairs, [["OPENAI_API_KEY", SECRET_VALUE]]);
});

test("no plaintext value ever crossed to the control plane, and the vault self-fetched the blob", () => {
  const toBackend = outbound.filter((o) => o.url.startsWith(env.BACKEND_URL));
  assert.ok(toBackend.length >= 2);
  for (const { body } of toBackend) assert.ok(!String(body).includes(SECRET_VALUE));
  // The vault fetched the ciphertext itself (facts/inject named an identity; the blob came
  // from the control plane, not the boot zone's request).
  const fetches = outbound.filter((o) => o.url === `${env.BACKEND_URL}/internal/vault/env`);
  assert.ok(fetches.length >= 1, "the vault must fetch the blob from the control plane");
  for (const { body } of fetches) assert.ok(!String(body).includes(SECRET_VALUE) && !String(body).includes("box"));
});
