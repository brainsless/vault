// Opens sealed environments in isolate memory and forgets them. Holds the only decryption key;
// the control plane stores ciphertext it cannot read. No value is persisted, logged, or returned.

import { b64encode, credentialEquals, importPrivateKey, importPublicKey, keyId, open, seal, unwrapDek, wrapDek } from "./crypto.js";
import { classify, hostsOf, maskPairs, mergeEnv, originsOf, parseLines } from "./envline.js";
import { preflight } from "./preflight.js";

const TOKEN = /^vlt_[0-9a-f]{48}$/;
const SANDBOX = /^run-[0-9a-f-]{36}$/;
const SCOPE = /^[A-Za-z0-9_:-]{1,128}$/;
// Env files are kilobytes; anything near this cap is not an environment.
const MAX_BODY_CHARS = 1_048_576;

const BLOB_VERSION = 1;
const storageAad = (uid, scope) => `vault:env:v${BLOB_VERSION}:${uid}:${scope}`;

// One import per isolate. The cache key carries an explicit kind, never a function's .name: a
// minifier can rename functions, and a collision would hand back a decrypt key where a digest goes.
const keyCache = new Map();
function cachedKey(kind, pem, derive) {
  const cacheKey = `${kind}:${pem}`;
  let value = keyCache.get(cacheKey);
  if (!value) {
    value = derive(pem);
    keyCache.set(cacheKey, value);
  }
  return value;
}

const publicKeyOf = (pem) => cachedKey("pub", pem, importPublicKey);
const privateKeyOf = (pem) => cachedKey("priv", pem, importPrivateKey);
const kidOf = (pem) => cachedKey("kid", pem, keyId);

// The live keypair opens everything new; a rotation predecessor keeps old storage blobs
// readable until they are re-sealed. Selection is by the kid recorded when the blob was made.
async function privateKeyFor(env, kid) {
  const current = await kidOf(env.VAULT_PUBLIC_KEY);
  if (!kid || kid === current) return privateKeyOf(env.VAULT_PRIVATE_KEY);
  if (env.VAULT_PREV_PUBLIC_KEY && kid === (await kidOf(env.VAULT_PREV_PUBLIC_KEY))) {
    return privateKeyOf(env.VAULT_PREV_PRIVATE_KEY);
  }
  return null;
}

const json = (body, status = 200) => Response.json(body, { status });
const notFound = () => json({ error: "not found" }, 404);

async function readJson(request) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_CHARS) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// Backend internal API, the only party that knows whose token is whose. The vault never
// learns account identities beyond the opaque uid/scope strings it binds ciphertext to.
async function backend(env, method, path, body) {
  const res = await fetch(`${env.BACKEND_URL}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      "x-vault-key": env.VAULT_BACKEND_KEY,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) return null;
  return res.json().catch(() => null);
}

async function runner(url, capability, verb, id, body) {
  const res = await fetch(`${url}/${verb}/${id}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-runner-capability": capability },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`runner ${verb} answered ${res.status}`);
  return res.json();
}

// Fetch the ciphertext for an identity from the control plane and decrypt it. [] means no sealed
// env (boot on stand-ins); null means a failure -- unreachable backend, bad blob, or a decrypt
// that did not open -- so a fault never passes as an empty environment.
async function openEnv(env, uid, scope) {
  let fetched;
  try {
    const res = await fetch(`${env.BACKEND_URL}/internal/vault/env`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-vault-key": env.VAULT_BACKEND_KEY },
      body: JSON.stringify({ uid, scope }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    fetched = await res.json();
  } catch {
    return null;
  }
  if (fetched?.blob == null) return [];
  const blob = fetched.blob;
  if (blob.v !== BLOB_VERSION || typeof blob.key !== "string" || typeof blob.box !== "string") return null;
  const privateKey = await privateKeyFor(env, blob.kid);
  if (!privateKey) return null;
  const dek = await unwrapDek(privateKey, blob.key);
  if (!dek) return null;
  const text = await open(dek, blob.box, storageAad(uid, scope));
  return text === null ? null : parseLines(text);
}

// The handover: the CLI's two calls. GET hands out the sealing key; POST takes ciphertext,
// opens it here, refuses what policy refuses, and re-seals only the accepted lines for
// storage. Refused values die in this function's frame.
async function handoverGet(env, token) {
  const row = await backend(env, "GET", `/internal/vault/handover/${token}`);
  if (!row) return notFound();
  return json({
    names: row.names,
    publicKey: env.VAULT_PUBLIC_KEY,
    kid: await kidOf(env.VAULT_PUBLIC_KEY),
  });
}

async function handoverPost(env, token, request) {
  const row = await backend(env, "GET", `/internal/vault/handover/${token}`);
  if (!row) return notFound();
  const body = await readJson(request);
  if (!body || typeof body.key !== "string" || typeof body.box !== "string") {
    return json({ error: "invalid request" }, 400);
  }
  const clientRefused = Array.isArray(body.refused)
    ? body.refused.filter((r) => typeof r?.name === "string" && typeof r?.reason === "string").slice(0, 300)
    : [];

  const privateKey = await privateKeyFor(env, typeof body.kid === "string" ? body.kid : "");
  const dek = privateKey && (await unwrapDek(privateKey, body.key));
  const text = dek && (await open(dek, body.box, token));
  if (!text) return json({ error: "the payload did not open" }, 400);

  const { accepted, refused, missing } = classify(parseLines(text), row.names, clientRefused);
  if (accepted.length === 0) {
    return json({ error: "no variables to seal", accepted: [], refused, missing }, 400);
  }

  const storageDek = crypto.getRandomValues(new Uint8Array(32));
  const blob = {
    v: BLOB_VERSION,
    kid: await kidOf(env.VAULT_PUBLIC_KEY),
    key: await wrapDek(await publicKeyOf(env.VAULT_PUBLIC_KEY), storageDek),
    box: await seal(storageDek, accepted.map(([n, v]) => `${n}=${v}`).join("\n"), storageAad(row.uid, row.scope)),
  };

  const report = { accepted: accepted.map(([n]) => n), refused, missing };
  const stored = await backend(env, "POST", `/internal/vault/handover/${token}`, { blob, report });
  if (!stored?.ok) return json({ error: "the variables could not be sealed" }, 502);
  return json({ ok: true, ...report });
}

// Non-secret facts the boot engine needs before secrets enter the sandbox: which names are
// present, what was refused, the hostnames the values point at (for the egress lock), the
// browser origins the app expects, and whether the provider keys are alive.
async function factsPost(env, request) {
  const body = await readJson(request);
  if (!body || typeof body.uid !== "string" || !SCOPE.test(body.scope ?? "")) {
    return json({ error: "invalid request" }, 400);
  }
  const pairs = await openEnv(env, body.uid, body.scope);
  if (!pairs) return json({ error: "the environment did not open" }, 400);

  const { accepted, refused } = classify(pairs);
  return json({
    provided: accepted.map(([n]) => n),
    refused,
    hosts: hostsOf(accepted),
    origins: originsOf(accepted),
    preflight: await preflight(accepted),
  });
}

// Writes the opened env into the sandbox and arms the runner's log mask. Destination is
// env.RUNNER_URL, never a request field: the caller holds the ciphertext and the key, so a
// request-controlled target would make this a decryption oracle.
async function injectPost(env, request) {
  if (!env.RUNNER_URL) return json({ error: "runner not configured" }, 503);
  const body = await readJson(request);
  if (
    !body ||
    typeof body.uid !== "string" ||
    !SCOPE.test(body.scope ?? "") ||
    !SANDBOX.test(body.sandboxId ?? "") ||
    typeof body.capability !== "string" ||
    typeof body.path !== "string" ||
    !body.path.startsWith("/") ||
    !Array.isArray(body.before) ||
    !Array.isArray(body.after)
  ) {
    return json({ error: "invalid request" }, 400);
  }
  const pairs = await openEnv(env, body.uid, body.scope);
  if (!pairs) return json({ error: "the environment did not open" }, 400);

  // Classified again at the moment of use: a blob stored by an older policy still meets
  // today's refusals before anything reaches a sandbox.
  const { accepted, refused } = classify(pairs);
  const file = mergeEnv(
    body.before.filter((l) => typeof l === "string").slice(0, 500),
    accepted,
    body.after.filter((l) => typeof l === "string").slice(0, 500),
  );

  const masks = maskPairs(accepted);
  try {
    await runner(env.RUNNER_URL, body.capability, "write", body.sandboxId, {
      path: body.path,
      b64: b64encode(new TextEncoder().encode(file)),
    });
    if (masks.length) {
      await runner(env.RUNNER_URL, body.capability, "arm", body.sandboxId, { pairs: masks });
    }
  } catch (err) {
    // The runner's status, never the payload: an error path must not become a value leak.
    return json({ error: String(err?.message ?? "the write did not land") }, 502);
  }
  return json({ written: true, provided: accepted.map(([n]) => n), refused });
}

// The product's own screen seals in the browser and posts here cross-origin. One configured
// origin, exact match; the CLI has no Origin header and is unaffected.
function corsHeaders(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !env.ALLOWED_ORIGIN || origin !== env.ALLOWED_ORIGIN) return null;
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "600",
  };
}

const withHeaders = (response, headers) => {
  if (!headers) return response;
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(headers)) out.headers.set(name, value);
  return out;
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const [root, second, third] = url.pathname.split("/").filter(Boolean);

    // buildHash is the fingerprint of the deployed bundle; rebuild at `commit` and hash it
    // (verify.mjs) to prove this is the running code. It is a var, not part of the bundle.
    if (request.method === "GET" && root === "version" && !second) {
      return json({
        name: "brainsless-vault",
        version: env.VAULT_VERSION ?? "dev",
        commit: env.VAULT_COMMIT ?? "dev",
        buildHash: env.VAULT_BUILD_HASH ?? "unset",
      });
    }

    // Seal endpoint: the token is the whole path. Its charset can't collide with "version" or "env".
    if (TOKEN.test(root ?? "") && !second) {
      const cors = corsHeaders(request, env);
      if (request.method === "OPTIONS") {
        return cors ? new Response(null, { status: 204, headers: cors }) : notFound();
      }
      if (request.method === "GET") return withHeaders(await handoverGet(env, root), cors);
      if (request.method === "POST") return withHeaders(await handoverPost(env, root, request), cors);
      return notFound();
    }

    // The boot zone's door: decrypt (facts) or decrypt-and-write (inject) by naming an identity.
    // Gated by VAULT_BOOT_KEY, which the API zone does not hold. Two keys, two zones; see the README.
    if (root === "env" && (second === "facts" || second === "inject") && !third && request.method === "POST") {
      const presented = request.headers.get("x-vault-key") ?? "";
      if (!env.VAULT_BOOT_KEY || !credentialEquals(presented, env.VAULT_BOOT_KEY)) return notFound();
      return second === "facts" ? factsPost(env, request) : injectPost(env, request);
    }

    return notFound();
  },
};
