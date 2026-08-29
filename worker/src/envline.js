// Env-line policy: parsing, refusal, merge, and the non-secret facts derived from values.
// Everything here is pure. This module and crypto.js are the only code in the system that
// touches plaintext environment values outside the customer's machine and their sandbox.

// The refusal policy, enforced here and mirrored by both CLIs and the browser screen so the
// refusal happens on the customer's machine. policy-parity.test.js asserts the surfaces agree.

// Infrastructure is provisioned inside the sandbox; a value pointing at real infrastructure
// is refused so a test run can never reach it.
export const INFRA_NAME =
  /^(DATABASE_URL|POSTGRES\w*|PG(HOST|PORT|USER|PASSWORD|DATABASE)|MYSQL\w*|MONGO\w*|REDIS\w*|AMQP_URL|KAFKA\w*)$/i;
// Stripe-convention keys carry their mode in the prefix; live-mode keys can move money.
export const LIVE_VALUE = /\b(sk|rk|pk)_live_/;
// The sandbox owns its runtime identity; a customer PORT or NODE_ENV would subvert discovery.
export const RUNTIME_NAME = /^(NODE_ENV|PORT|HOST|HOSTNAME|PATH|HOME|PWD|SHELL|USER|TMPDIR|NODE_OPTIONS)$/i;

export const REASONS = {
  infra: "the sandbox makes its own database, cache and queue",
  live: "live payment key; a test run must not be able to move money",
  runtime: "the sandbox provides this one itself",
  unrequested: "not requested by this repository's AI path",
};

export function refusalReason(name, value) {
  if (INFRA_NAME.test(name)) return REASONS.infra;
  if (LIVE_VALUE.test(value)) return REASONS.live;
  if (RUNTIME_NAME.test(name)) return REASONS.runtime;
  return null;
}

// `NAME=value` and `export NAME=value`, one matching quote pair stripped.
export function parseLines(text) {
  const pairs = [];
  for (const line of String(text ?? "").split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    const value = m[2].trim().replace(/^(["'])([\s\S]*)\1$/, "$2");
    if (value) pairs.push([m[1], value]);
  }
  return pairs;
}

// Partition pairs into accepted and refused. `expected` non-empty additionally refuses names
// the repository's AI path never reads. `clientRefused` is folded in name-only: the CLI refused
// those values on the customer's machine, so they never arrived here.
export function classify(pairs, expected = [], clientRefused = []) {
  const accepted = [];
  const refused = clientRefused.map(({ name, reason }) => ({ name, reason }));
  const seen = new Set(refused.map((r) => r.name));
  const wanted = new Set(expected);
  for (const [name, value] of pairs) {
    seen.add(name);
    const reason =
      expected.length > 0 && !wanted.has(name) ? REASONS.unrequested : refusalReason(name, value);
    if (reason) refused.push({ name, reason });
    else accepted.push([name, value]);
  }
  const missing = expected.filter((n) => !seen.has(n));
  return { accepted, refused, missing };
}

// Single quotes are the only shell-safe carrier for an arbitrary value: nothing inside them is
// special except the quote itself, which is closed, escaped, and reopened. The .env this feeds
// is shell-sourced (`set -a; . ./.env`), so unquoted values would lose characters or execute.
export const shellQuote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

// Stand-ins first, customer values quoted in the middle so they win, platform overrides last.
// Every value is shell-quoted and every line must be a plain NAME=value: the file is shell-sourced
// and `before`/`after` come from the control plane, so an unquoted `X=$(...)` would execute. A line
// that is not a clean assignment is dropped.
const ASSIGNMENT = /^\s*([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/;
const quoteLine = (line) => {
  const m = ASSIGNMENT.exec(line);
  return m ? `${m[1]}=${shellQuote(m[2])}` : null;
};

export function mergeEnv(before, accepted, after) {
  const lines = [
    ...before.map(quoteLine),
    ...accepted.map(([name, value]) => `${name}=${shellQuote(value)}`),
    ...after.map(quoteLine),
  ].filter((line) => line !== null);
  return `${lines.join("\n")}\n`;
}

// Hostnames of URL-shaped values, for the sandbox egress allowlist. Parsed with URL, not a
// pattern: a credentialed URL (a DSN) puts userinfo where a pattern expects the host.
export function hostsOf(accepted) {
  const hosts = new Set();
  for (const [, value] of accepted) {
    for (const m of value.matchAll(/https?:\/\/[^\s"'`,;]+/g)) {
      let host;
      try {
        host = new URL(m[0]).hostname;
      } catch {
        continue;
      }
      if (host && !/^(localhost|127\.|0\.0\.0\.0|\[)/.test(host)) hosts.add(host);
    }
  }
  return [...hosts];
}

// Browser-origin config the boot engine presents when probing guest routes. Origins are public
// by definition; returning them to the control plane reveals no secret.
const ORIGIN_VAR =
  /^(ALLOWED_ORIGINS|ALLOWED_EXTRA_ORIGINS|CORS_ORIGINS?|CORS_ALLOWED_ORIGINS|\w*_ORIGIN_HOSTS|APP_URL|PUBLIC_URL|SITE_URL|FRONTEND_URL|CLIENT_URL|WEB_URL|NEXT_PUBLIC_(APP|SITE)_URL)$/i;

// The first origin-shaped value, as a single-element list or empty: the boot engine presents one
// origin when probing guest routes, and the lab-path twin (boot.mjs originsFromEnv) stops at the
// first match too. Returned as a list so the caller's `[0]` reads the same on both paths.
export function originsOf(accepted) {
  for (const [name, value] of accepted) {
    if (!ORIGIN_VAR.test(name)) continue;
    const first = value.split(",")[0].trim().replace(/^["']|["']$/g, "").replace(/\/+$/, "");
    if (!first || first === "*") continue;
    return [/^https?:\/\//.test(first) ? first : `https://${first}`];
  }
  return [];
}

// Name-value pairs worth scrubbing from sandbox logs. Both spellings of embedded newlines: a
// .env holds `\n` escaped and the running app prints it real. Values under 8 characters are
// left alone -- masking a port number turns a diagnostic into a puzzle.
export function maskPairs(accepted) {
  const pairs = [];
  for (const [name, value] of accepted) {
    if (value.length >= 8) pairs.push([name, value]);
    const real = value.replaceAll("\\n", "\n");
    if (real !== value && real.length >= 8) pairs.push([name, real]);
  }
  return pairs;
}
