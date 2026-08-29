#!/usr/bin/env node
// Fingerprint this repo's Worker bundle, and optionally compare it to a live service:
//   node verify.mjs                          print this repo's fingerprint
//   node verify.mjs https://vault...         compare it against the live /version
// Reproducible build: same source, same fingerprint. See VERIFY.md.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const out = mkdtempSync(join(tmpdir(), "vault-verify-"));

try {
  // Build exactly as `wrangler deploy` does, without deploying, and hash the emitted bundle.
  execFileSync("npx", ["wrangler", "deploy", "--dry-run", "--outdir", out], {
    cwd: join(root, "worker"),
    stdio: "ignore",
  });
  const fingerprint = createHash("sha256").update(readFileSync(join(out, "index.js"))).digest("hex");
  console.log(`repo fingerprint  ${fingerprint}`);

  const url = process.argv[2];
  if (!url) process.exit(0);

  const res = await fetch(`${url.replace(/\/+$/, "")}/version`, { signal: AbortSignal.timeout(15_000) });
  const { buildHash, commit } = await res.json();
  console.log(`live  fingerprint  ${buildHash}   (commit ${commit})`);

  if (buildHash === fingerprint) {
    console.log("\nMATCH, the running service is this code.");
  } else {
    console.error("\nMISMATCH, the running service is NOT built from this repo at this commit.");
    console.error("Check out the commit /version reports and run this again, or report it.");
    process.exit(1);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}
