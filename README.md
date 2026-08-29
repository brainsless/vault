# Brainsless Vault

Brainsless runs your app in a sandbox to test it, and the sandbox needs your staging env vars to
boot. This repo is all the code that touches those values once they leave your machine. It's the
only thing that can decrypt them, and it's open so you can confirm that yourself instead of taking
our word for it.

## How it works

You seal your env vars on your own machine (the `connect` CLI, or the browser) against the vault's
public key. The values are AES-256-GCM encrypted; the key is wrapped with RSA to the vault. Only
ciphertext leaves your machine.

We store that ciphertext. We don't hold a key that opens it, and the ciphertext we store is itself
wrapped again at rest under a per-tenant key rooted in Google Cloud KMS (non-exportable, one KMS key
per environment). When your app compiles, the vault pulls the ciphertext back, decrypts it in memory,
and writes it straight into your sandbox. The API servers, the database, and the logs only ever see
ciphertext. If someone dumps our database or walks off with a backup, there's nothing readable in it,
and there's no key in it to make it readable.

The vault (`worker/`) is a Cloudflare Worker with no database, no storage, and no logging of
values. It exists for the milliseconds a decrypt takes and forgets everything after.

## What it refuses

The CLI drops a few things before it seals anything, so they never leave your machine, and the
vault rejects them again if they somehow arrive:

- Infrastructure: `DATABASE_URL`, `REDIS_URL`, `POSTGRES*`, and friends. The sandbox brings up its
  own database and cache; it must never be able to reach your real ones.
- Live payment keys (`sk_live_...`). A test run shouldn't be able to move money.
- Runtime vars the sandbox sets itself: `PORT`, `NODE_ENV`, `HOST`.

Refused values aren't sent. Their names are, so the screen can tell you a refusal happened rather
than pretending the var was just missing.

## Where the boundary is

At rest, your values are unreadable anywhere we keep them, databases, backups, logs, API servers.
That holds unconditionally. A leaked decrypt key on its own reaches nothing: the vault releases a
tenant's environment only while a compile is actually running, and writing values into a sandbox
requires a separate runner key.

Your application still runs with its environment during a compile, as any application must, so the
one service that drives that compile is held to the same controls as the rest of our infrastructure:
isolated, least-privilege, and monitored. The refusal policy keeps production infrastructure and
live-mode keys out of that path in the first place. Our full posture lives in the Trust Center at
[trust.brainsless.com](https://trust.brainsless.com).

## Layout

- `cli/connect.mjs`, the Node CLI (`npx @brainsless/connect`). One file, no dependencies.
- `python/`, the same thing for Python (`uvx brainsless-connect`).
- `worker/`, the vault. Web Crypto, no dependencies.
- `runner/mask.js`, scrubs the sealed values out of sandbox command output before any log leaves.

## Checking it

You can confirm that the service running at `vault.brainsless.com` is this code, and that this code
does what it says. Each deploy publishes the fingerprint (SHA-256) of the exact Worker bundle it
shipped, and the running service reports the same fingerprint at `GET /version`. The build is
reproducible, so you can recompute and compare:

```
npm --prefix worker ci && node verify.mjs https://vault.brainsless.com
```

A `MATCH` means the deployed code is the code you are reading. `VERIFY.md` covers this and the rest of
the chain in full; the deploy history is available on request. Report anything that looks off to
security@brainsless.com.

MIT.
