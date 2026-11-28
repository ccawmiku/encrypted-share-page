if (typeof module !== "undefined" && typeof require === "function" && typeof encryptText === "undefined") {
  Object.assign(globalThis, require("./crypto-core.js"));
}

function initApp(doc = document, win = window) {
  const els = {
    encryptForm: doc.querySelector("#encrypt-form"),
    decryptForm: doc.querySelector("#decrypt-form"),
    plainText: doc.querySelector("#plain-text"),
    plainCounter: doc.querySelector("#plain-counter"),
    encryptPassword: doc.querySelector("#encrypt-password"),
    shareOutput: doc.querySelector("#share-output"),
    shareUrl: doc.querySelector("#share-url"),
    copyLink: doc.querySelector("#copy-link"),
    linkNote: doc.querySelector("#link-note"),
    encryptedPayload: doc.querySelector("#encrypted-payload"),
    decryptPassword: doc.querySelector("#decrypt-password"),
    decryptOutput: doc.querySelector("#decrypt-output"),
    decryptedText: doc.querySelector("#decrypted-text"),
    copyPlain: doc.querySelector("#copy-plain"),
    payloadStatus: doc.querySelector("#payload-status"),
    status: doc.querySelector("#status-message"),
  };

  function setStatus(message, type = "info") {
    els.status.textContent = message;
    els.status.classList.toggle("is-error", type === "error");
    els.status.classList.toggle("is-success", type === "success");
  }

  async function copyText(text, successMessage) {
    await win.navigator.clipboard.writeText(text);
    setStatus(successMessage, "success");
  }

  function requireCrypto() {
    if (!win.crypto?.subtle) {
      throw new Error("当前环境不支持 Web Crypto。请用 localhost 或 HTTPS 打开这个页面。");
    }
  }

  function setBusy(button, busy, label) {
    if (!button) {
      return;
    }
    button.disabled = busy;
    if (busy && label) {
      button.dataset.readyText ||= button.textContent;
      button.textContent = label;
    } else if (!busy && button.dataset.readyText) {
      button.textContent = button.dataset.readyText;
    }
  }

  function plainCharCount() {
    return countPlainChars(els.plainText.value);
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
      const shareUrl = buildShareUrl(encoded, win.location.href);

      els.shareUrl.value = shareUrl;
      els.encryptedPayload.value = encoded;
      els.shareOutput.hidden = false;
      els.linkNote.textContent =
        shareUrl.length > LONG_URL_THRESHOLD
          ? "链接比较长，某些聊天软件可能会截断，建议先测试复制后的完整性。"
          : "";
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
      setStatus(
        error.name === "OperationError" ? "密码不正确，或密文已损坏。" : "解密失败，请检查链接和密码。",
        "error",
      );
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
    const encoded = getPayloadFromHash(win.location.hash);
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
  win.addEventListener("hashchange", loadPayloadFromUrl);

  return {
    els,
    loadPayloadFromUrl,
    updatePlainCounter,
    plainCharCount,
  };
}

if (typeof document !== "undefined") {
  initApp(document, window);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { initApp };
}
