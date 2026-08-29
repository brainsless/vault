import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { INFRA_NAME, LIVE_VALUE, REASONS, RUNTIME_NAME, refusalReason } from "../src/envline.js";

// The refusal policy is copied onto three surfaces that can't share a module (each CLI is a single
// auditable file): the Worker enforcer, the Node CLI, the Python CLI. This asserts every pattern
// and reason string appears verbatim in all three, against the enforcer as source of truth.

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const surfaces = {
  "Node CLI": read("../../cli/connect.mjs"),
  "Python CLI": read("../../python/brainsless_connect/__init__.py"),
};

test("every surface carries the enforcer's exact patterns", () => {
  for (const pattern of [INFRA_NAME, LIVE_VALUE, RUNTIME_NAME]) {
    for (const [name, text] of Object.entries(surfaces)) {
      assert.ok(text.includes(pattern.source), `${name} is missing pattern /${pattern.source}/`);
    }
  }
});

test("every surface carries the enforcer's exact reason strings", () => {
  for (const reason of [REASONS.infra, REASONS.live, REASONS.runtime]) {
    for (const [name, text] of Object.entries(surfaces)) {
      assert.ok(text.includes(reason), `${name} is missing reason "${reason}"`);
    }
  }
});

// The behavioural half: the patterns compile to the refusals the strings promise.
test("refusalReason maps each category to its canonical reason", () => {
  assert.equal(refusalReason("DATABASE_URL", "x"), REASONS.infra);
  assert.equal(refusalReason("POSTGRES_HOST", "x"), REASONS.infra);
  assert.equal(refusalReason("STRIPE_KEY", "sk_live_abc"), REASONS.live);
  assert.equal(refusalReason("PORT", "3000"), REASONS.runtime);
  assert.equal(refusalReason("NODE_ENV", "production"), REASONS.runtime);
  assert.equal(refusalReason("OPENAI_API_KEY", "sk-test"), null);
  assert.equal(refusalReason("STRIPE_KEY", "sk_test_abc"), null);
});
