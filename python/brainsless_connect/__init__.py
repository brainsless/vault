"""The handover CLI, for machines that have Python and uv rather than Node.

    uvx brainsless-connect https://vault.brainsless.com/vlt_...

Same job as the Node package and byte-for-byte the same wire format: it finds every environment
file in the repository (monorepo services included), refuses anything that belongs to production,
and seals the rest against the vault's public key so only ciphertext crosses the wire. Nothing is
installed, nothing in the repo is touched, nothing is kept here.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# The same rules the server enforces, applied here so the refusal happens in front of you.
INFRA_NAME = re.compile(r"^(DATABASE_URL|POSTGRES\w*|PG(HOST|PORT|USER|PASSWORD|DATABASE)|MYSQL\w*|MONGO\w*|REDIS\w*|AMQP_URL|KAFKA\w*)$", re.I)
LIVE_VALUE = re.compile(r"\b(sk|rk|pk)_live_")
RUNTIME_NAME = re.compile(r"^(NODE_ENV|PORT|HOST|HOSTNAME|PATH|HOME|PWD|SHELL|USER|TMPDIR|NODE_OPTIONS)$", re.I)
# Canonical wording, identical to the vault's worker/src/envline.js REASONS and the Node CLI.
# policy-parity.test.js asserts these three surfaces agree, string for string and pattern for pattern.
INFRA_REASON = "the sandbox makes its own database, cache and queue"
LIVE_REASON = "live payment key; a test run must not be able to move money"
RUNTIME_REASON = "the sandbox provides this one itself"

SKIP_DIR = re.compile(r"^(node_modules|\.git|dist|build|out|coverage|vendor|venv|env|target|tmp|\.next|\.nuxt|\.turbo|\.cache|\.venv|__pycache__|\.terraform)$")
VALUE_FILE = re.compile(r"^\.env(\.(local|staging|stage|development|dev|test))?$")
NAMES_ONLY = re.compile(r"^\.env\.(example|sample|template|defaults|dist)$")
RANK = {".env.staging": 4, ".env.stage": 4, ".env.local": 3, ".env.development": 2, ".env.dev": 2, ".env": 1, ".env.test": 0}
URL_RE = re.compile(r"^https?://[^/]+/vlt_[0-9a-f]{48}$")
LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def refusal(name: str, value: str):
    if INFRA_NAME.match(name):
        return INFRA_REASON
    if LIVE_VALUE.search(value):
        return LIVE_REASON
    if RUNTIME_NAME.match(name):
        return RUNTIME_REASON
    return None


def env_files(root: Path, max_depth: int = 4):
    found = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).resolve().relative_to(root).parts)
        dirnames[:] = [] if depth >= max_depth else [d for d in dirnames if not SKIP_DIR.match(d)]
        for name in filenames:
            if VALUE_FILE.match(name):
                found.append((Path(dirpath) / name, depth, RANK.get(name, 1), True))
            elif NAMES_ONLY.match(name):
                found.append((Path(dirpath) / name, depth, 0, False))
    return found


def parse(text: str):
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        value = m.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out.append((m.group(1), value))
    return out


def main() -> None:
    argv = sys.argv[1:]
    explicit_yes = "--yes" in argv or "-y" in argv
    interactive = sys.stdin.isatty()
    url = next((a for a in argv if a.startswith("http")), None)
    if not url or not URL_RE.match(url):
        sys.exit("usage: brainsless-connect [--yes] <handover url from the Brainsless screen>")

    # The public key your secrets are sealed to is fetched from this URL's host, so the host is the
    # trust anchor. Pin it: https on brainsless.com, or loopback for local testing. Anything else is
    # refused rather than trusted for looking plausible.
    parsed = urllib.parse.urlparse(url)
    trusted = (
        parsed.scheme == "https" and (parsed.hostname == "brainsless.com" or (parsed.hostname or "").endswith(".brainsless.com"))
    ) or (parsed.scheme in ("https", "http") and parsed.hostname in ("localhost", "127.0.0.1"))
    if not trusted:
        sys.exit(f"refusing: {parsed.scheme}://{parsed.hostname} is not a Brainsless handover host. Expected an https brainsless.com URL from the screen.")

    host = parsed.netloc
    print(f"brainsless: encrypting your .env locally, sending only ciphertext to {host}. Infra and live keys are refused; nothing is installed.")

    root = Path.cwd()
    files = env_files(root)
    if not files:
        sys.exit("no environment file anywhere under this directory. Run this from the root of the repo Brainsless read.")

    variables: dict[str, str] = {}
    for path, depth, rank, has_values in sorted(files, key=lambda f: f[1] * 1000 + f[2]):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for name, value in parse(text):
            if has_values and value:
                variables[name] = value

    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - https handover URL
        info = json.load(resp)
    public_key = serialization.load_pem_public_key(info["publicKey"].encode())
    kid = info.get("kid")

    send, refused = [], []
    for name, value in variables.items():
        why = refusal(name, value)
        (refused.append({"name": name, "reason": why}) if why else send.append(name))

    for r in refused:
        print(f"  skipped {r['name']}: {r['reason']}")
    if not send:
        sys.exit("nothing to seal here.")

    if not explicit_yes:
        if interactive:
            answer = input(f"Seal {len(send)} variable{'' if len(send) == 1 else 's'}? [y/N] ").strip()
            if not re.match(r"^y(es)?$", answer, re.I):
                print("nothing sent.")
                return
        else:
            print(f"{len(send)} variable{'' if len(send) == 1 else 's'} ready. Re-run with --yes to send.")
            return

    # Byte-for-byte the wire format the server opens: AES-256-GCM as iv|tag|body base64 under a fresh
    # key, that key RSA-OAEP-SHA256 wrapped, the handover token as the AAD.
    token = url.rsplit("/", 1)[-1]
    plaintext = "\n".join(f"{n}={variables[n]}" for n in send).encode()
    dek = os.urandom(32)
    iv = os.urandom(12)
    ct = AESGCM(dek).encrypt(iv, plaintext, token.encode())  # body || tag
    box = base64.b64encode(iv + ct[-16:] + ct[:-16]).decode()
    key = base64.b64encode(
        public_key.encrypt(dek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    ).decode()

    # kid: which of the vault's keys sealed this, so a rotation never strands a payload.
    payload = json.dumps({"key": key, "box": box, "refused": refused, **({"kid": kid} if kid else {})}).encode()
    req = urllib.request.Request(url, data=payload, headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        sys.exit(f"that did not take ({e.code}). Nothing was stored; refresh the screen and try again.\n{body}")
    n = len(out.get("accepted", []))
    print(f"Sealed {n} variable{'' if n == 1 else 's'}. Return to the browser.")
