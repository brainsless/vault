# @brainsless/connect

Seals your repo's `.env` values and hands them to Brainsless so it can boot your app in a sandbox.
The values are encrypted on your machine first; only ciphertext goes over the wire.

```
npx @brainsless/connect <url from the Brainsless screen>
```

The URL is single-use and expires in 30 minutes. It points at the vault, the only service that
can decrypt what you send.

## What it does

Finds the `.env` files in your repo (including ones inside a monorepo), shows you every var it found
and where it came from, and asks before sending. When you confirm, it AES-256-GCM encrypts the
values under a fresh key, wraps that key with RSA against the vault's public key, and POSTs the
ciphertext. Nothing readable crosses the wire, so a TLS terminator or an access log has nothing to
catch.

## What it won't send

- `DATABASE_URL`, `POSTGRES*`, `REDIS*`, `MONGO*`, `MYSQL*`, `AMQP_URL`, `KAFKA*`, the sandbox
  makes its own.
- Anything with `sk_live_`, `pk_live_`, `rk_live_`, no moving real money from a test run.
- `NODE_ENV`, `PORT`, `HOST`, and the rest of the runtime, the sandbox sets those.

These are dropped before anything is encrypted. Their names get reported so the screen knows a
refusal happened, but the values never leave your machine.

## Running it without a prompt

With no terminal and no `--yes`, it prints what it would send and stops, so a script or an agent
gets a list to show a person instead of sending silently. Add `--yes` to seal without the prompt,
once someone who owns the secrets has seen the list.

## Reading it first

One file, under 200 lines, nothing beyond Node's own `crypto`, `fs`, `path`, and `readline`. Pin a
version and read exactly what you'll run:

```
npm view @brainsless/connect@2.0.0
```
