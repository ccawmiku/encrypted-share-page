import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const core = require("../crypto-core.js");
const { initApp } = require("../app.js");

const {
  ITERATIONS,
  MAX_PLAIN_CHARS,
  LONG_URL_THRESHOLD,
  OBFUSCATED_PREFIX,
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
} = core;

test("bytesToBase64Url 与 base64UrlToBytes 支持全字节范围与各长度边界往返", () => {
  const allBytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  const encodedAll = bytesToBase64Url(allBytes);
  assert.equal(/[+/=]/.test(encodedAll), false, "Base64URL 不应包含 +, /, =");
  assert.deepEqual(base64UrlToBytes(encodedAll), allBytes);

  for (const len of [0, 1, 2, 3, 4, 5, 16, 32, 65]) {
    const sample = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 13) & 0xff);
    const b64 = bytesToBase64Url(sample);
    assert.equal(/[+/=]/.test(b64), false);
    assert.deepEqual(base64UrlToBytes(b64), sample);
  }
});

test("concatBytes 与 xorBytes 计算正确且满足自反性", () => {
  assert.deepEqual(concatBytes(), new Uint8Array(0));
  assert.deepEqual(
    concatBytes(new Uint8Array([1, 2]), new Uint8Array(0), new Uint8Array([3, 4, 5])),
    new Uint8Array([1, 2, 3, 4, 5]),
  );

  const data = new Uint8Array([0x00, 0x55, 0xaa, 0xff]);
  const mask = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
  const masked = xorBytes(data, mask);
  assert.deepEqual(masked, new Uint8Array([0x12, 0x61, 0xfc, 0x87]));
  assert.deepEqual(xorBytes(masked, mask), data);
});

test("makeObfuscationMask 在不同长度与 SHA-256 块边界下确定且与 salt 相关", async () => {
  const saltA = new Uint8Array(16).fill(1);
  const saltB = new Uint8Array(16).fill(2);

  for (const len of [0, 1, 31, 32, 33, 64, 100]) {
    const mask1 = await makeObfuscationMask(saltA, len);
    const mask2 = await makeObfuscationMask(saltA, len);
    const maskOther = await makeObfuscationMask(saltB, len);
    assert.equal(mask1.length, len);
    assert.deepEqual(mask1, mask2);
    if (len > 0) {
      assert.notDeepEqual(mask1, maskOther);
    }
  }

  // 超过 32 字节时第 2 块应使用 counter=1，不应与第 1 块重复
  const twoBlocks = await makeObfuscationMask(saltA, 64);
  assert.notDeepEqual(twoBlocks.slice(0, 32), twoBlocks.slice(32, 64));
});

test("encryptText 与 decryptPayload 支持中文、Emoji、换行及 1000 码点上限往返", async () => {
  const messages = [
    "你好，世界！\n第二行\t🔐🎉",
    "a",
    "😀".repeat(MAX_PLAIN_CHARS),
  ];

  for (const plain of messages) {
    const payload = await encryptText(plain, "s3cr3t-密码!");
    assert.equal(payload.v, 1);
    assert.equal(payload.alg, "AES-GCM");
    assert.equal(payload.kdf, "PBKDF2-SHA256");
    assert.equal(payload.iter, ITERATIONS);
    assert.equal(base64UrlToBytes(payload.salt).length, 16);
    assert.equal(base64UrlToBytes(payload.iv).length, 12);
    assert.ok(base64UrlToBytes(payload.ct).length >= 16);

    const decrypted = await decryptPayload(payload, "s3cr3t-密码!");
    assert.equal(decrypted, plain);
  }

  // 相同明文与密码每次加密应生成独立随机 salt/iv/ct
  const p1 = await encryptText("same", "pass");
  const p2 = await encryptText("same", "pass");
  assert.notEqual(p1.salt, p2.salt);
  assert.notEqual(p1.iv, p2.iv);
  assert.notEqual(p1.ct, p2.ct);
});

test("encodePayload 与 decodePayload 支持 p2 混淆往返与旧版裸 Base64URL JSON 兼容", async () => {
  const payload = await encryptText("兼容测试内容 🚀", "pass-123");

  const encoded1 = await encodePayload(payload);
  const encoded2 = await encodePayload(payload);
  assert.ok(encoded1.startsWith(OBFUSCATED_PREFIX));
  assert.ok(encoded2.startsWith(OBFUSCATED_PREFIX));
  assert.notEqual(encoded1, encoded2, "每次混淆应使用随机 16 字节 salt");

  const packed = base64UrlToBytes(encoded1.slice(OBFUSCATED_PREFIX.length));
  assert.equal(packed[0], 2);
  assert.ok(packed.length >= 18);

  const decoded = await decodePayload(encoded1);
  assert.deepEqual(decoded, payload);
  assert.equal(await decryptPayload(decoded, "pass-123"), "兼容测试内容 🚀");

  // 旧版无 p2. 前缀的裸 Base64URL JSON 载荷应向后兼容
  const legacyEncoded = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  assert.equal(legacyEncoded.startsWith(OBFUSCATED_PREFIX), false);
  const legacyDecoded = await decodePayload(legacyEncoded);
  assert.deepEqual(legacyDecoded, payload);
  assert.equal(await decryptPayload(legacyDecoded, "pass-123"), "兼容测试内容 🚀");
});

test("错误密码与篡改密文/IV/Salt 解密应抛出 OperationError", async () => {
  const payload = await encryptText("机密内容", "correct-password");

  await assert.rejects(
    () => decryptPayload(payload, "wrong-password"),
    (err) => err && err.name === "OperationError",
  );

  // 篡改 ct
  const badCt = base64UrlToBytes(payload.ct);
  badCt[0] ^= 0xff;
  await assert.rejects(
    () => decryptPayload({ ...payload, ct: bytesToBase64Url(badCt) }, "correct-password"),
    (err) => err && err.name === "OperationError",
  );

  // 篡改 iv
  const badIv = base64UrlToBytes(payload.iv);
  badIv[0] ^= 0x01;
  await assert.rejects(
    () => decryptPayload({ ...payload, iv: bytesToBase64Url(badIv) }, "correct-password"),
    (err) => err && err.name === "OperationError",
  );

  // 篡改 salt
  const badSalt = base64UrlToBytes(payload.salt);
  badSalt[0] ^= 0x01;
  await assert.rejects(
    () => decryptPayload({ ...payload, salt: bytesToBase64Url(badSalt) }, "correct-password"),
    (err) => err && err.name === "OperationError",
  );
});

test("decodePayload 对截断载荷、错误版本字节、非 Base64URL 字符与损坏 JSON 报错", async () => {
  // 截断载荷: packed.length < 18 (例如 17 字节 = 版本 + 16 字节 salt，无载荷)
  const truncated17 = `${OBFUSCATED_PREFIX}${bytesToBase64Url(new Uint8Array([2, ...new Uint8Array(16)]))}`;
  await assert.rejects(() => decodePayload(truncated17), /格式不支持/);
  await assert.rejects(() => decodePayload(OBFUSCATED_PREFIX), /格式不支持/);

  // 错误版本字节 !== 2
  for (const badVersion of [0, 1, 3, 255]) {
    const wrongVer = `${OBFUSCATED_PREFIX}${bytesToBase64Url(
      new Uint8Array([badVersion, ...new Uint8Array(16), 0x7b, 0x7d]),
    )}`;
    await assert.rejects(() => decodePayload(wrongVer), /格式不支持/);
  }

  // 非 Base64URL 字符
  await assert.rejects(() => decodePayload(`${OBFUSCATED_PREFIX}abc!@#`), Error);
  await assert.rejects(() => decodePayload("not*valid*b64"), Error);

  // 损坏 JSON（裸载荷与 p2. 载荷）
  const badRawJson = bytesToBase64Url(new TextEncoder().encode("{broken"));
  await assert.rejects(() => decodePayload(badRawJson), SyntaxError);

  const salt = new Uint8Array(16).fill(7);
  const badBytes = new TextEncoder().encode("{broken");
  const mask = await makeObfuscationMask(salt, badBytes.length);
  const badP2 = `${OBFUSCATED_PREFIX}${bytesToBase64Url(
    concatBytes(Uint8Array.of(2), salt, xorBytes(badBytes, mask)),
  )}`;
  await assert.rejects(() => decodePayload(badP2), SyntaxError);

  // 非字符串或空字符串
  await assert.rejects(() => decodePayload(""), /格式不支持/);
  await assert.rejects(() => decodePayload(null), /格式不支持/);
});

test("decryptPayload 拦截不支持的 v/alg/kdf/iter 及缺失字段", async () => {
  const valid = await encryptText("ok", "pw");

  const invalidCases = [
    null,
    undefined,
    {},
    { ...valid, v: 2 },
    { ...valid, v: 0 },
    { ...valid, alg: "AES-CBC" },
    { ...valid, kdf: "PBKDF2-SHA512" },
    { ...valid, salt: undefined },
    { ...valid, iv: 123 },
    { ...valid, ct: null },
    { ...valid, iter: 0 },
    { ...valid, iter: -100 },
    { ...valid, iter: "250000" },
  ];

  for (const badPayload of invalidCases) {
    await assert.rejects(() => decryptPayload(badPayload, "pw"), /格式不支持/);
  }
});

test("extractPayload、getPayloadFromHash、buildShareUrl 与 countPlainChars 边界行为", () => {
  assert.equal(extractPayload(""), "");
  assert.equal(extractPayload("   \t\n "), "");
  assert.equal(extractPayload("  p2.abc123  "), "p2.abc123");
  assert.equal(extractPayload("#payload=p2.abc123"), "p2.abc123");
  assert.equal(extractPayload("#payload="), "");
  assert.equal(extractPayload("https://example.com/app/#payload=p2.xyz"), "p2.xyz");
  assert.equal(
    extractPayload("https://example.com/app/?x=1#foo=bar&payload=p2.xyz&y=2"),
    "p2.xyz",
  );
  // 无 payload 参数的普通 URL：保持既有回退行为（返回 trimmed）
  assert.equal(extractPayload("https://example.com/app/"), "https://example.com/app/");
  assert.equal(extractPayload("https://example.com/app/#other=1"), "https://example.com/app/#other=1");

  assert.equal(getPayloadFromHash("#payload=p2.hello"), "p2.hello");
  assert.equal(getPayloadFromHash("payload=p2.hello"), "p2.hello");
  assert.equal(getPayloadFromHash("#a=1&payload=p2.hello"), "p2.hello");
  assert.equal(getPayloadFromHash(""), null);
  assert.equal(getPayloadFromHash("#other=1"), null);

  assert.equal(
    buildShareUrl("p2.token", "https://example.com/page/?v=1#old=hash"),
    "https://example.com/page/?v=1#payload=p2.token",
  );

  // countPlainChars 按 Unicode 码点计数而非 UTF-16 长度
  assert.equal(countPlainChars(""), 0);
  assert.equal(countPlainChars("abc"), 3);
  assert.equal(countPlainChars("中文"), 2);
  assert.equal(countPlainChars("😀"), 1);
  assert.equal("😀".length, 2);
  assert.equal(countPlainChars("🔐🎉中文a"), 5);
  assert.equal(countPlainChars("😀".repeat(MAX_PLAIN_CHARS)), MAX_PLAIN_CHARS);
  assert.equal(LONG_URL_THRESHOLD, 7800);
  assert.equal(typeof initApp, "function");
});

test("randomBytes、deriveKey、空字符串加解密与异常 iter/字段边界", async () => {
  const rb1 = randomBytes(16);
  const rb2 = randomBytes(16);
  assert.equal(rb1.length, 16);
  assert.notDeepEqual(rb1, rb2);

  const salt = new Uint8Array(16).fill(9);
  const key = await deriveKey("pw", salt, 1000);
  assert.equal(key.algorithm.name, "AES-GCM");

  const emptyPayload = await encryptText("", "pw");
  assert.equal(await decryptPayload(emptyPayload, "pw"), "");

  // packed.length === 18（仅 1 字节 JSON "1"）能通过 decodePayload，但 decryptPayload 应拒绝非对象载荷
  const singleByte = new TextEncoder().encode("1");
  const mask = await makeObfuscationMask(salt, singleByte.length);
  const packed18 = `${OBFUSCATED_PREFIX}${bytesToBase64Url(
    concatBytes(Uint8Array.of(2), salt, xorBytes(singleByte, mask)),
  )}`;
  const decodedPrimitive = await decodePayload(packed18);
  assert.equal(decodedPrimitive, 1);
  await assert.rejects(() => decryptPayload(decodedPrimitive, "pw"), /格式不支持/);

  // iter 非整数或 NaN，以及空 IV / 短密文均应失败
  await assert.rejects(() => decryptPayload({ ...emptyPayload, iter: 1.5 }, "pw"), /格式不支持/);
  await assert.rejects(() => decryptPayload({ ...emptyPayload, iter: NaN }, "pw"), /格式不支持/);
  await assert.rejects(() => decryptPayload({ ...emptyPayload, iv: "" }, "pw"), Error);
  await assert.rejects(() => decryptPayload({ ...emptyPayload, ct: "AA" }, "pw"), Error);

  // extractPayload 对非字符串与空值边界
  assert.equal(extractPayload(null), "");
  assert.equal(extractPayload(undefined), "");
  assert.equal(extractPayload(123), "");
  assert.equal(base64UrlToBytes("").length, 0);
  assert.throws(() => base64UrlToBytes(123), /格式不支持/);
});
