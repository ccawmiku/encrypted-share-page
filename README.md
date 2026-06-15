# 加密分享页

一个纯静态的 GitHub Pages 小工具：输入原文和密码后生成包含密文的 URL，别人打开链接后输入密码即可在浏览器本地解密。

## 本地测试

```powershell
python -m http.server 8000
```

然后打开：

```text
http://localhost:8000/
```

## 部署到 GitHub Pages

1. 把这些文件推到 GitHub 仓库。
2. 在仓库 Settings -> Pages 里选择 `Deploy from a branch`。
3. Branch 选择 `master` 或 `main`，目录选择 `/root`。
4. 保存后等待 GitHub Pages 生成访问地址。

## 说明

- 密码不会写入链接。
- 链接中的 `#payload=...` 是加密后的内容，浏览器不会把 fragment 发给服务器。
- 加密使用浏览器 Web Crypto 的 PBKDF2-SHA256 和 AES-GCM。
- 原文限制为最多 1000 个字符，避免生成过长链接。
- 新链接会使用 `p2.` payload，把加密元数据再做一层 URL 混淆；这主要用于降低通讯软件自动扫描的可读性，不替代强密码。
