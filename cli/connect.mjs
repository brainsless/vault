#!/usr/bin/env node
// Seals every environment file in a repo against the vault's public key; only ciphertext leaves.
// Run from the repo root with the one-line command the screen showed:
//   node connect.mjs https://vault.brainsless.com/vlt_...
// Installs nothing, touches nothing, keeps nothing.

import { constants, createCipheriv, publicEncrypt, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createInterface } from 'node:readline';

// A terminal is asked, --yes sends unattended, and a tool with neither dry-runs. No terminal is not
// consent: without this a pasted command sealed a repository's secrets with no prompt to anybody.
const argv = process.argv.slice(2);
const explicitYes = argv.includes('--yes') || argv.includes('-y');
const interactive = Boolean(process.stdin.isTTY);
const url = argv.find((a) => a.startsWith('http'));
if (!url || !/^https?:\/\/[^/]+\/vlt_[0-9a-f]{48}$/.test(url)) {
  console.error('usage: node connect.mjs [--yes] <handover url from the Brainsless screen>');
  process.exit(1);
}

// The host is the trust anchor: the sealing key is fetched from it, so a wrong host seals to the
// wrong key. Pin to brainsless.com; loopback for local testing; anything else is refused.
const { protocol, hostname } = new URL(url);
const trusted =
  (protocol === 'https:' && (hostname === 'brainsless.com' || hostname.endsWith('.brainsless.com'))) ||
  ((protocol === 'https:' || protocol === 'http:') && (hostname === 'localhost' || hostname === '127.0.0.1'));
if (!trusted) {
  console.error(`refusing: ${protocol}//${hostname} is not a Brainsless handover host. Expected an https brainsless.com URL from the screen.`);
  process.exit(1);
}

// Said before anything is read: this is usually started by an agent handed the command and nothing
// else, and it should be able to see the intent before it acts.
console.log(`brainsless: encrypting your .env locally, sending only ciphertext to ${new URL(url).host}. Infra and live keys are refused; nothing is installed.`);

// The same rules the server enforces, applied here so the refusal happens in front of you. The
// reasons are a closed set the server validates.
const INFRA_NAME = /^(DATABASE_URL|POSTGRES\w*|PG(HOST|PORT|USER|PASSWORD|DATABASE)|MYSQL\w*|MONGO\w*|REDIS\w*|AMQP_URL|KAFKA\w*)$/i;
const LIVE_VALUE = /\b(sk|rk|pk)_live_/;
// The sandbox owns its own runtime: your PORT would hide the server we find by watching for its
// socket, and your NODE_ENV would boot a production build with none of production behind it.
const RUNTIME_NAME = /^(NODE_ENV|PORT|HOST|HOSTNAME|PATH|HOME|PWD|SHELL|USER|TMPDIR|NODE_OPTIONS)$/i;
// Canonical wording, identical to the vault's worker/src/envline.js REASONS and the Python
// CLI. A sealed report must never carry two spellings of the same refusal; policy-parity.test.js
// asserts these three surfaces agree, string for string and pattern for pattern.
const INFRA_REASON = 'the sandbox makes its own database, cache and queue';
const LIVE_REASON = 'live payment key; a test run must not be able to move money';
const RUNTIME_REASON = 'the sandbox provides this one itself';
const refusal = (name, value) =>
  INFRA_NAME.test(name) ? INFRA_REASON
  : LIVE_VALUE.test(value) ? LIVE_REASON
  : RUNTIME_NAME.test(name) ? RUNTIME_REASON
  : null;

// A dependency's own env is never the customer's, and node_modules would be the slowest walk here.
const SKIP_DIR = /^(node_modules|\.git|dist|build|out|coverage|vendor|venv|env|target|tmp|\.next|\.nuxt|\.turbo|\.cache|\.venv|__pycache__|\.terraform)$/;
// Files whose values are real. `.env.production` is never opened.
const VALUE_FILE = /^\.env(\.(local|staging|stage|development|dev|test))?$/;
// Names only: a placeholder value is worse than an absent one, since a presence guard will parse it.
const NAMES_ONLY = /^\.env\.(example|sample|template|defaults|dist)$/;

// Within one directory, a more specific file wins. Across directories the deeper file wins: in a
// monorepo the service's own env is the operative one and the root holds shared defaults.
const RANK = { '.env.staging': 4, '.env.stage': 4, '.env.local': 3, '.env.development': 2, '.env.dev': 2, '.env': 1, '.env.test': 0 };

function envFiles(root, maxDepth = 4) {
  const found = [];
  const walk = (dir, depth) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIR.test(entry.name)) walk(join(dir, entry.name), depth + 1);
      } else if (VALUE_FILE.test(entry.name)) {
        found.push({ file: join(dir, entry.name), depth, rank: RANK[entry.name] ?? 1, values: true });
      } else if (NAMES_ONLY.test(entry.name)) {
        found.push({ file: join(dir, entry.name), depth, rank: 0, values: false });
      }
    }
  };
  walk(root, 0);
  return found;
}

const parse = (text) => {
  const out = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    out.push([m[1], m[2].trim().replace(/^(["'])([\s\S]*)\1$/, '$2')]);
  }
  return out;
};

// Plenty of repositories keep production in a plain `backend/.env`, so the filename rule misses it.
// Flagged, never skipped: a customer whose only environment is production still has to be able to
// onboard, and the list below is where they decide.
const DECLARES_PRODUCTION = /^\s*(?:export\s+)?NODE_ENV\s*=\s*["']?production["']?\s*$/im;

const root = process.cwd();
const files = envFiles(root);
if (files.length === 0) {
  console.error('no environment file anywhere under this directory. Run this from the root of the repo Brainsless read.');
  process.exit(1);
}

// One entry per variable; the source file is printed beside it so the choice is checkable.
const vars = new Map();
const declared = new Set();
const read = [];
const flagged = [];
for (const source of files.sort((a, b) => a.depth * 1000 + a.rank - (b.depth * 1000 + b.rank))) {
  let text;
  try { text = readFileSync(source.file, 'utf8'); } catch { continue; }
  const where = relative(root, source.file) || source.file;
  if (source.values && DECLARES_PRODUCTION.test(text)) flagged.push(where);
  read.push(where);
  for (const [name, value] of parse(text)) {
    declared.add(name);
    if (!source.values || !value) continue;
    vars.set(name, { value, where });
  }
}

const ask = await fetch(url);
if (!ask.ok) {
  console.error('this handover has expired or was already used. Refresh the Brainsless screen for a fresh command.');
  process.exit(1);
}
const { names, publicKey, kid } = await ask.json();

// The names the read found report what is missing; they never narrow what is sent. A variable the
// scanner missed is exactly the one whose absence breaks the boot an hour later.
const send = [];
const refused = [];
for (const [name, { value }] of vars) {
  const why = refusal(name, value);
  if (why) refused.push({ name, reason: why });
  else send.push(name);
}
const expected = new Set(names);
const missing = [...new Set([...expected, ...declared])].filter((n) => !vars.has(n));
const unreferenced = send.filter((n) => expected.size > 0 && !expected.has(n)).length;

for (const { name, reason } of refused) console.log(`  skipped ${name}: ${reason}`);
if (send.length === 0) { console.error('nothing to seal here.'); process.exit(1); }

if (!explicitYes) {
  if (interactive) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((res) => rl.question(`Seal ${send.length} variable${send.length === 1 ? '' : 's'}? [y/N] `, res));
    rl.close();
    if (!/^y(es)?$/i.test(answer.trim())) { console.log('nothing sent.'); process.exit(0); }
  } else {
    console.log(`${send.length} variable${send.length === 1 ? '' : 's'} ready. Re-run with --yes to send.`);
    process.exit(0);
  }
}

// AES-256-GCM under a fresh data key, that key RSA-OAEP-wrapped, the token as AAD so the payload
// fits only this handover. Refused NAMES ride outside the box; their values never leave.
const token = url.slice(url.lastIndexOf('/') + 1);
const plaintext = send.map((n) => `${n}=${vars.get(n).value}`).join('\n');
const dek = randomBytes(32);
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', dek, iv);
cipher.setAAD(Buffer.from(token, 'utf8'));
const body = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
const payload = {
  key: publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, dek).toString('base64'),
  box: Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64'),
  // Which of the vault's keys sealed this, so a rotation never strands a payload in flight.
  ...(kid ? { kid } : {}),
  refused,
};

const res = await fetch(url, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(payload),
});
const out = await res.json().catch(() => ({}));
if (!res.ok) {
  console.error(`\nthat did not take (${out.error ?? res.status}). Nothing was stored; refresh the screen and try again.`);
  process.exit(1);
}
console.log(`Sealed ${out.accepted.length} variable${out.accepted.length === 1 ? '' : 's'}. Return to the browser.`);
