import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { initApp } = require("../app.js");
const core = require("../crypto-core.js");

function createClassList() {
  const set = new Set();
  return {
    toggle(name, force) {
      if (force === undefined) {
        if (set.has(name)) {
          set.delete(name);
          return false;
        }
        set.add(name);
        return true;
      }
      if (force) {
        set.add(name);
      } else {
        set.delete(name);
      }
      return Boolean(force);
    },
    contains(name) {
      return set.has(name);
    },
  };
}

function createElement(initial = {}) {
  const listeners = new Map();
  return {
    value: "",
    textContent: "",
    hidden: false,
    disabled: false,
    dataset: {},
    classList: createClassList(),
    focused: false,
    selected: false,
    ...initial,
    addEventListener(type, handler) {
      if (!listeners.has(type)) {
        listeners.set(type, []);
      }
      listeners.get(type).push(handler);
    },
    async dispatch(type, event = {}) {
      const evt = { preventDefault() {}, ...event };
      for (const handler of listeners.get(type) || []) {
        await handler(evt);
      }
    },
    focus() {
      this.focused = true;
    },
    select() {
      this.selected = true;
    },
  };
}

function createMockEnv({
  hash = "",
  href = "https://example.com/share/",
  cryptoObj = globalThis.crypto,
  clipboardImpl = null,
} = {}) {
  const winListeners = new Map();
  const elements = {
    "#encrypt-form": createElement(),
    "#decrypt-form": createElement(),
    "#plain-text": createElement(),
    "#plain-counter": createElement(),
    "#encrypt-password": createElement(),
    "#share-output": createElement({ hidden: true }),
    "#share-url": createElement(),
    "#copy-link": createElement(),
    "#link-note": createElement(),
    "#encrypted-payload": createElement(),
    "#decrypt-password": createElement(),
    "#decrypt-output": createElement({ hidden: true }),
    "#decrypted-text": createElement(),
    "#copy-plain": createElement(),
    "#payload-status": createElement(),
    "#status-message": createElement(),
  };

  const doc = {
    querySelector(selector) {
      return elements[selector] || null;
    },
  };

  const win = {
    location: { hash, href },
    crypto: cryptoObj,
    navigator: {
      clipboard: clipboardImpl || {
        async writeText() {},
      },
    },
    addEventListener(type, handler) {
      if (!winListeners.has(type)) {
        winListeners.set(type, []);
      }
      winListeners.get(type).push(handler);
    },
    async dispatch(type) {
      for (const handler of winListeners.get(type) || []) {
        await handler();
      }
    },
  };

  return { doc, win, elements };
}

test("initApp 初始状态、hash 自动加载与 hashchange 响应", async () => {
  const env1 = createMockEnv();
  const app1 = initApp(env1.doc, env1.win);
  assert.equal(
    env1.elements["#status-message"].textContent,
    "准备好了。先生成一个加密 URL，或打开别人发来的加密链接。",
  );
  assert.equal(env1.elements["#plain-counter"].textContent, "0 / 1000");

  env1.win.location.hash = "#payload=p2.from_hashchange";
  await env1.win.dispatch("hashchange");
  assert.equal(env1.elements["#encrypted-payload"].value, "p2.from_hashchange");
  assert.equal(env1.elements["#decrypt-password"].focused, true);
  assert.equal(env1.elements["#status-message"].classList.contains("is-success"), true);
  assert.equal(app1.plainCharCount(), 0);

  const env2 = createMockEnv({ hash: "#payload=p2.initial_payload" });
  initApp(env2.doc, env2.win);
  assert.equal(env2.elements["#encrypted-payload"].value, "p2.initial_payload");
  assert.equal(
    env2.elements["#payload-status"].textContent,
    "已从 URL 自动读取密文，请输入密码解密。",
  );
});

test("initApp plainText input 按码点计数并在超过 1000 时标红", async () => {
  const { doc, win, elements } = createMockEnv();
  const app = initApp(doc, win);

  elements["#plain-text"].value = "😀".repeat(1000);
  await elements["#plain-text"].dispatch("input");
  assert.equal(app.plainCharCount(), 1000);
  assert.equal(elements["#plain-counter"].textContent, "1000 / 1000");
  assert.equal(elements["#plain-counter"].classList.contains("is-error"), false);

  elements["#plain-text"].value = "😀".repeat(1001);
  await elements["#plain-text"].dispatch("input");
  assert.equal(app.plainCharCount(), 1001);
  assert.equal(elements["#plain-counter"].textContent, "1001 / 1000");
  assert.equal(elements["#plain-counter"].classList.contains("is-error"), true);
});

test("initApp 在缺少 Web Crypto subtle 时提示安全上下文错误并恢复按钮状态", async () => {
  const { doc, win, elements } = createMockEnv({ cryptoObj: {} });
  initApp(doc, win);

  const encryptBtn = createElement({ textContent: "生成加密 URL" });
  elements["#plain-text"].value = "hello";
  elements["#encrypt-password"].value = "pw";
  await elements["#encrypt-form"].dispatch("submit", { submitter: encryptBtn });

  assert.equal(
    elements["#status-message"].textContent,
    "当前环境不支持 Web Crypto。请用 localhost 或 HTTPS 打开这个页面。",
  );
  assert.equal(elements["#status-message"].classList.contains("is-error"), true);
  assert.equal(encryptBtn.disabled, false);
  assert.equal(encryptBtn.textContent, "生成加密 URL");

  const decryptBtn = createElement({ textContent: "解密并显示原文" });
  elements["#encrypted-payload"].value = "p2.something";
  elements["#decrypt-password"].value = "pw";
  elements["#decrypt-output"].hidden = false;
  await elements["#decrypt-form"].dispatch("submit", { submitter: decryptBtn });

  assert.equal(elements["#decrypt-output"].hidden, true);
  assert.equal(elements["#status-message"].textContent, "解密失败，请检查链接和密码。");
  assert.equal(decryptBtn.disabled, false);
  assert.equal(decryptBtn.textContent, "解密并显示原文");
});

test("initApp 端到端加密、超长链接提示、解密与剪贴板回退逻辑", async () => {
  const copied = [];
  let shouldFailClipboard = false;
  const longBaseUrl = `https://example.com/share/?pad=${"x".repeat(7600)}`;
  const { doc, win, elements } = createMockEnv({
    href: longBaseUrl,
    clipboardImpl: {
      async writeText(text) {
        if (shouldFailClipboard) {
          throw new Error("denied");
        }
        copied.push(text);
      },
    },
  });
  initApp(doc, win);

  const encryptBtn = createElement({ textContent: "生成加密 URL" });
  elements["#plain-text"].value = "中文与 Emoji 🔐";
  elements["#encrypt-password"].value = "pw-123";
  await elements["#encrypt-form"].dispatch("submit", { submitter: encryptBtn });

  assert.equal(elements["#share-output"].hidden, false);
  assert.ok(elements["#share-url"].value.length > core.LONG_URL_THRESHOLD);
  assert.equal(
    elements["#link-note"].textContent,
    "链接比较长，某些聊天软件可能会截断，建议先测试复制后的完整性。",
  );
  assert.equal(encryptBtn.disabled, false);
  assert.equal(encryptBtn.textContent, "生成加密 URL");

  const decryptBtn = createElement({ textContent: "解密并显示原文" });
  elements["#decrypt-password"].value = "pw-123";
  await elements["#decrypt-form"].dispatch("submit", { submitter: decryptBtn });
  assert.equal(elements["#decrypt-output"].hidden, false);
  assert.equal(elements["#decrypted-text"].textContent, "中文与 Emoji 🔐");
  assert.equal(decryptBtn.disabled, false);
  assert.equal(decryptBtn.textContent, "解密并显示原文");

  await elements["#copy-link"].dispatch("click");
  await elements["#copy-plain"].dispatch("click");
  assert.equal(copied.length, 2);

  shouldFailClipboard = true;
  await elements["#copy-link"].dispatch("click");
  await Promise.resolve();
  assert.equal(elements["#share-url"].selected, true);
  assert.equal(
    elements["#status-message"].textContent,
    "无法自动复制，请手动复制选中的链接。",
  );

  await elements["#copy-plain"].dispatch("click");
  await Promise.resolve();
  assert.equal(
    elements["#status-message"].textContent,
    "无法自动复制，请手动选择原文复制。",
  );
});
