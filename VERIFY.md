# Verifying the vault

Brainsless is built to be checked, not taken on faith. The service that handles your environment
variables is open source, and the copy running in production is verifiably the copy in this
repository. This document shows how to confirm two things: that the running service is this code,
and that this code does what it says. Everything here is something you can run or read.

## 1. The running service is this code

Every production deploy publishes the fingerprint (the SHA-256 of the exact Worker bundle that
shipped) as a GitHub Release, and the running service reports that same fingerprint at
`GET /version`. The build is reproducible, so you recompute it and compare in one command:

```
git clone https://github.com/brainsless/vault && cd vault
npm --prefix worker ci
node verify.mjs https://vault.brainsless.com
```

`MATCH` means the code serving `vault.brainsless.com` is the code you are reading. Deploys happen
only through CI, each one tied to a public commit and its fingerprint; the full deploy history is
available on request.

## 2. The CLI you run is this repository

The command the screen gives you pins a version. Diff the published package against the tag:

```
npm pack @brainsless/connect@2.0.0 && tar -xzf brainsless-connect-2.0.0.tgz
diff package/connect.mjs cli/connect.mjs
```

For Python: `pip download brainsless-connect --no-deps`, then diff against `python/`.

## 3. The CLI sends only ciphertext

`cli/connect.mjs` is one file, standard library only. It makes two network calls, both to the URL
you pasted: a GET for the sealing key, and a POST carrying `key` (the wrapped data key), `box` (the
ciphertext), `kid`, and the *names* of anything it refused. There is no field for a value.
Infrastructure and live-mode keys are dropped before the plaintext is assembled. If you prefer to
watch rather than read, run it against a throwaway `.env` with a proxy recording the wire: two
requests, no values.

## 4. What the control plane stores, it cannot open

The handover URL addresses the vault, not our API. The vault talks to the control plane on exactly
three calls (resolve a token, store a ciphertext blob, fetch a ciphertext blob), each carrying
ciphertext and names only. Grep `worker/src/index.js` for `backend(` to see them. The control plane
holds no private key; this repository is the only code that imports one, and it returns a value in no
response. The blob it does hold is wrapped once more at rest, under a per-tenant key rooted in a
non-exportable Google Cloud KMS key, so the stored form is unreadable even to the control plane that
stores it. The two endpoints that decrypt, `/env/facts` and `/env/inject`, require a key the API zone
does not hold, and the control plane releases a blob only while a compile is running for that tenant.

## 5. The vault keeps nothing

`wrangler.jsonc` declares no KV, D1, R2, or Durable Object, so there is nowhere to persist a value.
There is no logging of values. Every response is names, refusal reasons, hostnames, or key-check
results. The one path plaintext takes is the write into your own sandbox, and its destination is
fixed in the Worker's configuration, never taken from a request.

## 6. The wire format

The box is `base64(iv[12] | tag[16] | ciphertext)`, AES-256-GCM, with the handover token as the AAD;
the wrapped key is `base64(RSA-OAEP-SHA256(dek))`. Stored blobs use the same shape with the AAD
`vault:env:v1:<uid>:<scope>`, so a blob cannot be replayed under another identity. The tests seal
with Node, browser, and Python crypto and open with the Worker's, so the formats are checked against
each other in CI.

## Beyond this repository

This repository is one piece of a broader security program. Our full posture (compliance, policies, sub-processors, and our SOC 2 work) lives in the Trust Center at **https://trust.brainsless.com**,
where detailed documentation and a security questionnaire are available on request. Anything here
that looks off is a report we want: security@brainsless.com.
