const ITERATIONS = 250000;
const MAX_PLAIN_CHARS = 1000;
const OBFUSCATED_PREFIX = "p2.";
const OBFUSCATION_LABEL = "encrypted-share-page/url-payload-obfuscation/v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const els = {
  encryptForm: document.querySelector("#encrypt-form"),
  decryptForm: document.querySelector("#decrypt-form"),
  plainText: document.querySelector("#plain-text"),
  plainCounter: document.querySelector("#plain-counter"),
  encryptPassword: document.querySelector("#encrypt-password"),
  shareOutput: document.querySelector("#share-output"),
  shareUrl: document.querySelector("#share-url"),
  copyLink: document.querySelector("#copy-link"),
  linkNote: document.querySelector("#link-note"),
  encryptedPayload: document.querySelector("#encrypted-payload"),
  decryptPassword: document.querySelector("#decrypt-password"),
  decryptOutput: document.querySelector("#decrypt-output"),
  decryptedText: document.querySelector("#decrypted-text"),
  copyPlain: document.querySelector("#copy-plain"),
  payloadStatus: document.querySelector("#payload-status"),
  status: document.querySelector("#status-message"),
};

function setStatus(message, type = "info") {
  els.status.textContent = message;
  els.status.classList.toggle("is-error", type === "error");
  els.status.classList.toggle("is-success", type === "success");
}

function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
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
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(label, salt, counterBytes)));
    mask.set(digest.slice(0, Math.min(digest.length, length - offset)), offset);
    offset += digest.length;
    counter += 1;
  }

  return mask;
}

async function deriveKey(password, salt, iterations) {
  const sourceKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
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
  const encrypted = await crypto.subtle.encrypt(
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
  if (!payload || payload.v !== 1 || payload.alg !== "AES-GCM") {
    throw new Error("这个加密数据格式不支持。");
  }

  const salt = base64UrlToBytes(payload.salt);
  const iv = base64UrlToBytes(payload.iv);
  const encrypted = base64UrlToBytes(payload.ct);
  const key = await deriveKey(password, salt, payload.iter || ITERATIONS);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
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

function getPayloadFromHash() {
  const hash = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  const params = new URLSearchParams(hash);
  return params.get("payload");
}

function extractPayload(value) {
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

function buildShareUrl(encodedPayload) {
  const url = new URL(window.location.href);
  url.hash = `payload=${encodedPayload}`;
  return url.toString();
}

async function copyText(text, successMessage) {
  await navigator.clipboard.writeText(text);
  setStatus(successMessage, "success");
}

function requireCrypto() {
  if (!window.crypto?.subtle) {
    throw new Error("当前环境不支持 Web Crypto。请用 localhost 或 HTTPS 打开这个页面。");
  }
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  if (label) {
    button.dataset.readyText ||= button.textContent;
    button.textContent = busy ? label : button.dataset.readyText;
  }
}

function plainCharCount() {
  return Array.from(els.plainText.value).length;
}

function updatePlainCounter() {
  const count = plainCharCount();
  els.plainCounter.textContent = `${count} / ${MAX_PLAIN_CHARS}`;
  els.plainCounter.classList.toggle("is-error", count > MAX_PLAIN_CHARS);
}

els.encryptForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const plainText = els.plainText.value;
  const password = els.encryptPassword.value;
  const button = event.submitter;

  if (!plainText.trim()) {
    setStatus("请先输入要加密的内容。", "error");
    els.plainText.focus();
    return;
  }

  if (plainCharCount() > MAX_PLAIN_CHARS) {
    setStatus(`原文最多 ${MAX_PLAIN_CHARS} 个字符，请缩短后再生成链接。`, "error");
    els.plainText.focus();
    return;
  }

  if (!password) {
    setStatus("请设置加密密码。", "error");
    els.encryptPassword.focus();
    return;
  }

  try {
    requireCrypto();
    setBusy(button, true, "正在加密...");
    setStatus("正在本地加密，请稍等。");
    const payload = await encryptText(plainText, password);
    const encoded = await encodePayload(payload);
    const shareUrl = buildShareUrl(encoded);

    els.shareUrl.value = shareUrl;
    els.encryptedPayload.value = encoded;
    els.shareOutput.hidden = false;
    els.linkNote.textContent =
      shareUrl.length > 7800 ? "链接比较长，某些聊天软件可能会截断，建议先测试复制后的完整性。" : "";
    setStatus("加密 URL 已生成，可以复制分享。", "success");
  } catch (error) {
    setStatus(error.message || "加密失败，请重试。", "error");
  } finally {
    setBusy(button, false);
  }
});

els.decryptForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const encoded = extractPayload(els.encryptedPayload.value);
  const password = els.decryptPassword.value;
  const button = event.submitter;

  if (!encoded) {
    setStatus("没有找到可解密的数据。", "error");
    els.encryptedPayload.focus();
    return;
  }

  if (!password) {
    setStatus("请输入解密密码。", "error");
    els.decryptPassword.focus();
    return;
  }

  try {
    requireCrypto();
    setBusy(button, true, "正在解密...");
    setStatus("正在尝试解密。");
    const payload = await decodePayload(encoded);
    const plainText = await decryptPayload(payload, password);
    els.decryptedText.textContent = plainText;
    els.decryptOutput.hidden = false;
    setStatus("解密成功。", "success");
  } catch (error) {
    els.decryptOutput.hidden = true;
    setStatus(error.name === "OperationError" ? "密码不正确，或密文已损坏。" : "解密失败，请检查链接和密码。", "error");
  } finally {
    setBusy(button, false);
  }
});

els.copyLink.addEventListener("click", () => {
  copyText(els.shareUrl.value, "加密链接已复制。").catch(() => {
    els.shareUrl.select();
    setStatus("无法自动复制，请手动复制选中的链接。", "error");
  });
});

els.copyPlain.addEventListener("click", () => {
  copyText(els.decryptedText.textContent, "原文已复制。").catch(() => {
    setStatus("无法自动复制，请手动选择原文复制。", "error");
  });
});

function loadPayloadFromUrl() {
  const encoded = getPayloadFromHash();
  if (!encoded) {
    if (!els.status.textContent) {
      setStatus("准备好了。先生成一个加密 URL，或打开别人发来的加密链接。");
    }
    return false;
  }

  els.encryptedPayload.value = encoded;
  els.payloadStatus.textContent = "已从 URL 自动读取密文，请输入密码解密。";
  els.decryptPassword.focus();
  setStatus("已检测到 URL 中的加密内容。", "success");
  return true;
}

loadPayloadFromUrl();
updatePlainCounter();
els.plainText.addEventListener("input", updatePlainCounter);
window.addEventListener("hashchange", loadPayloadFromUrl);
