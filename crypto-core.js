const ITERATIONS = 250000;
const MAX_PLAIN_CHARS = 1000;
const LONG_URL_THRESHOLD = 7800;
const OBFUSCATED_PREFIX = "p2.";
const OBFUSCATION_LABEL = "encrypted-share-page/url-payload-obfuscation/v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getCrypto() {
  return globalThis.crypto;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (typeof value !== "string") {
    throw new Error("这个加密数据格式不支持。");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  getCrypto().getRandomValues(bytes);
  return bytes;
}

function concatBytes(...arrays) {
  const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
  const joined = new Uint8Array(totalLength);
  let offset = 0;

  arrays.forEach((array) => {
    joined.set(array, offset);
    offset += array.length;
  });

  return joined;
}

function xorBytes(bytes, mask) {
  return bytes.map((byte, index) => byte ^ mask[index]);
}

async function makeObfuscationMask(salt, length) {
  const label = encoder.encode(OBFUSCATION_LABEL);
  const mask = new Uint8Array(length);
  let offset = 0;
  let counter = 0;

  while (offset < length) {
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, false);
    const digest = new Uint8Array(
      await getCrypto().subtle.digest("SHA-256", concatBytes(label, salt, counterBytes)),
    );
    mask.set(digest.slice(0, Math.min(digest.length, length - offset)), offset);
    offset += digest.length;
    counter += 1;
  }

  return mask;
}

async function deriveKey(password, salt, iterations) {
  const subtle = getCrypto().subtle;
  const sourceKey = await subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    sourceKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptText(plainText, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(password, salt, ITERATIONS);
  const encrypted = await getCrypto().subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plainText),
  );

  return {
    v: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iter: ITERATIONS,
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
    ct: bytesToBase64Url(new Uint8Array(encrypted)),
  };
}

async function decryptPayload(payload, password) {
  if (
    !payload ||
    payload.v !== 1 ||
    payload.alg !== "AES-GCM" ||
    (payload.kdf !== undefined && payload.kdf !== "PBKDF2-SHA256") ||
    typeof payload.salt !== "string" ||
    typeof payload.iv !== "string" ||
    typeof payload.ct !== "string" ||
    (payload.iter !== undefined && (!Number.isInteger(payload.iter) || payload.iter <= 0))
  ) {
    throw new Error("这个加密数据格式不支持。");
  }

  const salt = base64UrlToBytes(payload.salt);
  const iv = base64UrlToBytes(payload.iv);
  const encrypted = base64UrlToBytes(payload.ct);
  const key = await deriveKey(password, salt, payload.iter || ITERATIONS);
  const decrypted = await getCrypto().subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
  return decoder.decode(decrypted);
}

async function encodePayload(payload) {
  const salt = randomBytes(16);
  const jsonBytes = encoder.encode(JSON.stringify(payload));
  const mask = await makeObfuscationMask(salt, jsonBytes.length);
  const obfuscated = xorBytes(jsonBytes, mask);
  const packed = concatBytes(Uint8Array.of(2), salt, obfuscated);
  return `${OBFUSCATED_PREFIX}${bytesToBase64Url(packed)}`;
}

async function decodePayload(encoded) {
  if (typeof encoded !== "string" || !encoded) {
    throw new Error("这个加密数据格式不支持。");
  }

  if (encoded.startsWith(OBFUSCATED_PREFIX)) {
    const packed = base64UrlToBytes(encoded.slice(OBFUSCATED_PREFIX.length));
    if (packed.length < 18 || packed[0] !== 2) {
      throw new Error("这个加密数据格式不支持。");
    }

    const salt = packed.slice(1, 17);
    const obfuscated = packed.slice(17);
    const mask = await makeObfuscationMask(salt, obfuscated.length);
    const json = decoder.decode(xorBytes(obfuscated, mask));
    return JSON.parse(json);
  }

  const json = decoder.decode(base64UrlToBytes(encoded));
  return JSON.parse(json);
}

function getPayloadFromHash(hashValue = typeof window !== "undefined" ? window.location.hash : "") {
  const hash = hashValue.startsWith("#") ? hashValue.slice(1) : hashValue;
  const params = new URLSearchParams(hash);
  return params.get("payload");
}

function extractPayload(value) {
  if (typeof value !== "string") {
    return "";
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  try {
    const asUrl = new URL(trimmed);
    const hash = asUrl.hash.startsWith("#") ? asUrl.hash.slice(1) : asUrl.hash;
    return new URLSearchParams(hash).get("payload") || trimmed;
  } catch {
    return trimmed.startsWith("#payload=")
      ? new URLSearchParams(trimmed.slice(1)).get("payload") || ""
      : trimmed;
  }
}

function buildShareUrl(encodedPayload, baseUrl = typeof window !== "undefined" ? window.location.href : "") {
  const url = new URL(baseUrl);
  url.hash = `payload=${encodedPayload}`;
  return url.toString();
}

function countPlainChars(value) {
  return Array.from(value).length;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    ITERATIONS,
    MAX_PLAIN_CHARS,
    LONG_URL_THRESHOLD,
    OBFUSCATED_PREFIX,
    OBFUSCATION_LABEL,
    bytesToBase64Url,
    base64UrlToBytes,
    randomBytes,
    concatBytes,
    xorBytes,
    makeObfuscationMask,
    deriveKey,
    encryptText,
    decryptPayload,
    encodePayload,
    decodePayload,
    getPayloadFromHash,
    extractPayload,
    buildShareUrl,
    countPlainChars,
  };
}
