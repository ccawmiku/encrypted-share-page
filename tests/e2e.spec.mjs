import { test, expect } from "@playwright/test";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { encryptText, bytesToBase64Url } = require("../crypto-core.js");

test.describe("加密分享页端到端交互", () => {
  test("完整流程：加密生成链接 -> 打开 #payload 链接自动填充 -> 错误密码 -> 正确密码解密", async ({
    page,
    context,
  }) => {
    const errors = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        errors.push(msg.text());
      }
    });

    await page.goto("/");
    await expect(page.locator("#status-message")).toHaveText(
      "准备好了。先生成一个加密 URL，或打开别人发来的加密链接。",
    );
    await expect(page.locator("#plain-counter")).toHaveText("0 / 1000");
    await expect(page.locator("#share-output")).toBeHidden();
    await expect(page.locator("#decrypt-output")).toBeHidden();

    const secretText = "机密测试内容 🔐\n第二行：Alpha-123";
    const password = "MyStrongPassword!2026";

    await page.fill("#plain-text", secretText);
    await expect(page.locator("#plain-counter")).toHaveText(
      `${Array.from(secretText).length} / 1000`,
    );
    await page.fill("#encrypt-password", password);
    await page.click('#encrypt-form button[type="submit"]');

    await expect(page.locator("#share-output")).toBeVisible();
    await expect(page.locator("#status-message")).toHaveText("加密 URL 已生成，可以复制分享。");
    await expect(page.locator('#encrypt-form button[type="submit"]')).toBeEnabled();
    await expect(page.locator('#encrypt-form button[type="submit"]')).toHaveText("生成加密 URL");

    const shareUrl = await page.inputValue("#share-url");
    expect(shareUrl.startsWith("http://127.0.0.1:4173/#payload=p2.")).toBe(true);
    await expect(page.locator("#link-note")).toHaveText("");

    // 新页面打开生成的分享链接
    const receiverPage = await context.newPage();
    receiverPage.on("pageerror", (err) => errors.push(err.message));
    await receiverPage.goto(shareUrl);

    await expect(receiverPage.locator("#payload-status")).toHaveText(
      "已从 URL 自动读取密文，请输入密码解密。",
    );
    await expect(receiverPage.locator("#status-message")).toHaveText("已检测到 URL 中的加密内容。");
    const filledPayload = await receiverPage.inputValue("#encrypted-payload");
    expect(filledPayload.startsWith("p2.")).toBe(true);

    // 错误密码触发 OperationError 提示
    await receiverPage.fill("#decrypt-password", "wrong-password");
    await receiverPage.click('#decrypt-form button[type="submit"]');
    await expect(receiverPage.locator("#decrypt-output")).toBeHidden();
    await expect(receiverPage.locator("#status-message")).toHaveText("密码不正确，或密文已损坏。");
    await expect(receiverPage.locator("#status-message")).toHaveClass(/is-error/);

    // 正确密码成功解密
    await receiverPage.fill("#decrypt-password", password);
    await receiverPage.click('#decrypt-form button[type="submit"]');
    await expect(receiverPage.locator("#decrypt-output")).toBeVisible();
    await expect(receiverPage.locator("#decrypted-text")).toHaveText(secretText);
    await expect(receiverPage.locator("#status-message")).toHaveText("解密成功。");
    await expect(receiverPage.locator("#status-message")).toHaveClass(/is-success/);
    await expect(receiverPage.locator('#decrypt-form button[type="submit"]')).toBeEnabled();
    await expect(receiverPage.locator('#decrypt-form button[type="submit"]')).toHaveText(
      "解密并显示原文",
    );

    await receiverPage.close();
    expect(errors).toEqual([]);
  });

  test("表单空值校验、字数超限校验、hashchange 自动填充与损坏密文处理", async ({ page }) => {
    await page.goto("/");

    // 空明文提交
    await page.click('#encrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("请先输入要加密的内容。");

    // 仅空格提交
    await page.fill("#plain-text", "   \n  ");
    await page.click('#encrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("请先输入要加密的内容。");

    // 超过 1000 码点校验
    await page.fill("#plain-text", "a".repeat(1001));
    await expect(page.locator("#plain-counter")).toHaveText("1001 / 1000");
    await expect(page.locator("#plain-counter")).toHaveClass(/is-error/);
    await page.click('#encrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText(
      "原文最多 1000 个字符，请缩短后再生成链接。",
    );

    // 合法明文但空密码
    await page.fill("#plain-text", "hello");
    await page.click('#encrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("请设置加密密码。");

    // 解密表单空值与空密码校验
    await page.click('#decrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("没有找到可解密的数据。");

    await page.fill("#encrypted-payload", "p2.invalid");
    await page.click('#decrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("请输入解密密码。");

    // 损坏密文错误提示
    await page.fill("#decrypt-password", "pw");
    await page.click('#decrypt-form button[type="submit"]');
    await expect(page.locator("#status-message")).toHaveText("解密失败，请检查链接和密码。");

    // hashchange 动态更新密文框
    await page.evaluate(() => {
      window.location.hash = "payload=p2.hashchange_demo";
    });
    await expect(page.locator("#encrypted-payload")).toHaveValue("p2.hashchange_demo");
    await expect(page.locator("#payload-status")).toHaveText(
      "已从 URL 自动读取密文，请输入密码解密。",
    );
    await expect(page.locator("#status-message")).toHaveText("已检测到 URL 中的加密内容。");
  });

  test("旧版裸 Base64URL 载荷可在页面中向后兼容解密", async ({ page }) => {
    const legacyPlain = "旧版格式兼容测试";
    const legacyPw = "legacy-pass";
    const payload = await encryptText(legacyPlain, legacyPw);
    const legacyEncoded = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));

    await page.goto(`/#payload=${legacyEncoded}`);
    await expect(page.locator("#encrypted-payload")).toHaveValue(legacyEncoded);
    await page.fill("#decrypt-password", legacyPw);
    await page.click('#decrypt-form button[type="submit"]');

    await expect(page.locator("#decrypt-output")).toBeVisible();
    await expect(page.locator("#decrypted-text")).toHaveText(legacyPlain);
    await expect(page.locator("#status-message")).toHaveText("解密成功。");
  });

  test("超长链接（>7800 字符）提示与 1000 个 Emoji 往返", async ({ page }) => {
    const padQuery = "x".repeat(520);
    await page.goto(`/?pad=${padQuery}`);

    const thousandEmojis = "😀".repeat(1000);
    await page.fill("#plain-text", thousandEmojis);
    await expect(page.locator("#plain-counter")).toHaveText("1000 / 1000");
    await page.fill("#encrypt-password", "emoji-pass");
    await page.click('#encrypt-form button[type="submit"]');

    await expect(page.locator("#share-output")).toBeVisible();
    const shareUrl = await page.inputValue("#share-url");
    expect(shareUrl.length).toBeGreaterThan(7800);
    await expect(page.locator("#link-note")).toHaveText(
      "链接比较长，某些聊天软件可能会截断，建议先测试复制后的完整性。",
    );

    await page.fill("#decrypt-password", "emoji-pass");
    await page.click('#decrypt-form button[type="submit"]');
    await expect(page.locator("#decrypted-text")).toHaveText(thousandEmojis);
  });

  test("剪贴板写入成功与失败回退选中行为", async ({ page }) => {
    // 场景 1: 剪贴板写入成功
    await page.addInitScript(() => {
      window.__copiedTexts = [];
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async (text) => {
            window.__copiedTexts.push(text);
          },
        },
      });
    });

    await page.goto("/");
    await page.fill("#plain-text", "剪贴板测试内容");
    await page.fill("#encrypt-password", "clip-pw");
    await page.click('#encrypt-form button[type="submit"]');
    await expect(page.locator("#share-output")).toBeVisible();

    await page.click("#copy-link");
    await expect(page.locator("#status-message")).toHaveText("加密链接已复制。");

    await page.fill("#decrypt-password", "clip-pw");
    await page.click('#decrypt-form button[type="submit"]');
    await expect(page.locator("#decrypt-output")).toBeVisible();

    await page.click("#copy-plain");
    await expect(page.locator("#status-message")).toHaveText("原文已复制。");

    const copiedTexts = await page.evaluate(() => window.__copiedTexts);
    expect(copiedTexts.length).toBe(2);
    expect(copiedTexts[0]).toContain("#payload=p2.");
    expect(copiedTexts[1]).toBe("剪贴板测试内容");

    // 场景 2: 剪贴板写入失败回退
    await page.evaluate(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: async () => {
            throw new DOMException("Permission denied", "NotAllowedError");
          },
        },
      });
    });

    await page.click("#copy-link");
    await expect(page.locator("#status-message")).toHaveText(
      "无法自动复制，请手动复制选中的链接。",
    );
    await expect(page.locator("#status-message")).toHaveClass(/is-error/);
    const selectionInfo = await page.evaluate(() => {
      const el = document.querySelector("#share-url");
      return {
        activeId: document.activeElement?.id,
        start: el.selectionStart,
        end: el.selectionEnd,
        len: el.value.length,
      };
    });
    expect(selectionInfo.start).toBe(0);
    expect(selectionInfo.end).toBe(selectionInfo.len);
    expect(selectionInfo.len).toBeGreaterThan(0);

    await page.click("#copy-plain");
    await expect(page.locator("#status-message")).toHaveText(
      "无法自动复制，请手动选择原文复制。",
    );
  });
});
