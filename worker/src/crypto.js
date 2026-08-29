// Envelope crypto over Web Crypto, compatible byte-for-byte with the Node and Python CLIs:
// AES-256-GCM as base64(iv[12] | tag[16] | ciphertext), the data key wrapped with
// RSA-OAEP-SHA256. AAD binds a box to the exact context it was sealed for, so ciphertext
// lifted from one handover or tenant fails to open anywhere else.

const IV_BYTES = 12;
const TAG_BYTES = 16;

const enc = new TextEncoder();

export const b64decode = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
export const b64encode = (bytes) => {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return btoa(out);
};

const pemToDer = (pem, label) => {
  const body = pem.replace(`-----BEGIN ${label}-----`, "").replace(`-----END ${label}-----`, "").replace(/\s/g, "");
  return b64decode(body);
};

export const importPrivateKey = (pem) =>
  crypto.subtle.importKey(
    "pkcs8",
    pemToDer(pem, "PRIVATE KEY"),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );

export const importPublicKey = (pem) =>
  crypto.subtle.importKey(
    "spki",
    pemToDer(pem, "PUBLIC KEY"),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );

// Key id: first eight bytes of SHA-256 over the public key's DER. Stable across PEM
// re-wrapping, sufficient to select among a live key and its rotation predecessors.
export async function keyId(publicPem) {
  const digest = await crypto.subtle.digest("SHA-256", pemToDer(publicPem, "PUBLIC KEY"));
  return [...new Uint8Array(digest).slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function wrapDek(publicKey, dek) {
  return b64encode(new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dek)));
}

export async function unwrapDek(privateKey, wrapped) {
  try {
    const dek = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, b64decode(wrapped)));
    return dek.length === 32 ? dek : null;
  } catch {
    return null;
  }
}

export async function seal(dek, plaintext, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  // Web Crypto returns ciphertext || tag; the wire format wants iv | tag | ciphertext.
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, enc.encode(plaintext)),
  );
  const body = sealed.slice(0, sealed.length - TAG_BYTES);
  const tag = sealed.slice(sealed.length - TAG_BYTES);
  const out = new Uint8Array(IV_BYTES + TAG_BYTES + body.length);
  out.set(iv, 0);
  out.set(tag, IV_BYTES);
  out.set(body, IV_BYTES + TAG_BYTES);
  return b64encode(out);
}

// Wrong key, wrong AAD, and a tampered box are one answer: null. Callers fail closed on it.
export async function open(dek, box, aad) {
  try {
    const raw = b64decode(box);
    if (raw.length <= IV_BYTES + TAG_BYTES) return null;
    const iv = raw.slice(0, IV_BYTES);
    const tag = raw.slice(IV_BYTES, IV_BYTES + TAG_BYTES);
    const body = raw.slice(IV_BYTES + TAG_BYTES);
    const joined = new Uint8Array(body.length + TAG_BYTES);
    joined.set(body, 0);
    joined.set(tag, body.length);
    const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(aad) },
      key,
      joined,
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

// Constant-time equality for bearer credentials. Length is not secret; contents are.
export function credentialEquals(presented, expected) {
  const a = enc.encode(presented);
  const b = enc.encode(expected);
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
