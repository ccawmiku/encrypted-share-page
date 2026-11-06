# 浏览器端加密分享页

一个部署到 Cloudflare Pages 的纯静态加密分享工具。输入原文和密码后，页面会生成带密文的链接；接收者打开链接并输入密码，即可在浏览器本地解密。

访问地址：https://share.onya.cc

本分支为 `cloudflare-pages`，Pages 生产部署跟踪此分支；`main` 保留原有 GitHub Pages 版本。

## 特点

- 无后端、无数据库，适合静态托管。
- 密码不会写入分享链接。
- 使用 Web Crypto API 的 PBKDF2-SHA256 和 AES-GCM。
- 密文放在 URL Fragment 中，正常情况下不会随 HTTP 请求发送给服务器。
- 新链接使用混淆后的 “p2” 载荷格式，降低通讯软件自动扫描时的可读性。

## 本地运行与构建

~~~bash
npm run dev
~~~

访问 “http://127.0.0.1:8000”。

也可以执行 `npm run build`，得到 `dist/` 静态文件。构建不需要安装任何第三方依赖，Node.js 22 或以上即可。

## 部署到 Cloudflare Pages

- 项目名称：`encrypted-share-page`。
- 代码仓库：`ccawmiku/encrypted-share-page`。
- 生产分支：`cloudflare-pages`。
- 框架预设：无。
- 构建命令：`npm run build`。
- 构建输出目录：`dist`。
- 自定义域名：`share.onya.cc`。

Pages 通过 Git 集成自动构建此分支的后续提交。构建只复制 `index.html`、`app.js`、`styles.css` 和 `_headers`，不会公开仓库配置或开发文件。无需 Workers 脚本、Pages Functions、数据库或服务端密码。

`_headers` 限制脚本和样式仅从本站加载、禁止页面发起网络连接和被嵌入，并设置不发送 Referer、禁止 MIME 嗅探与缓存重新验证。分享链接使用当前访问域名生成，密文继续放在 `#payload=` 中，兼容原有载荷格式。

## 安全说明

- URL 混淆不等于加密强度，安全性主要取决于密码。
- 原文最长 1000 个字符，避免生成过长链接。
- 浏览器扩展、剪贴板历史和聊天软件仍可能接触链接本身；托管服务提供页面文件，正常 HTTP 请求不会携带 Fragment 中的密文。
- 不建议用于长期保存高敏感数据；重要内容应使用成熟的端到端加密工具。

