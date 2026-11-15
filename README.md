# Connection Exposure Audit — Cloudflare Worker

Cloudflare Workers **网络连接／隐私暴露自检网站**：访问后自动显示 Cloudflare Worker 实际收到的 HTTP 元数据、所有请求头、完整可序列化的 `request.cf`、浏览器本地指纹特征，以及独立网络探针的可验证结果。自带中／英文响应式页面、完整 JSON API、JSON 导出。

> **重要安全告知：本项目按要求“全部原样反馈，不申请额外授权”实现。** 当前 HTML 导航请求和 `/api/report` 所带的 **Cookie（包括 HttpOnly）、Authorization、Referer、URL 查询参数，以及 `request.cf.hostMetadata`** 可能包含敏感信息，都会原样回显给相应请求的客户端。HttpOnly Cookie 本来不可被普通页面脚本读取，但服务端主动回显会打破这一隔离。**必须部署到与所有已登录/认证业务彻底隔离的专用主机名，避免共享 Cookie 域；不得加入第三方脚本、第三方统计和外部上传；切勿随意分享导出的 JSON。** 不建议用于已认证业务所在域名。

## 文件结构

```text
cloudflare-connection-audit/
├── worker.js              # 可直接部署的单文件 ES module Worker
├── src/
│   ├── edge.js            # Worker 后端、完整 HTTP/cf 回显与网络探针 API
│   ├── page.html          # 响应式页面结构
│   ├── site.css           # 响应式样式
│   └── client.js          # 中英文 UI、浏览器检测、STUN、报告导出
├── tools/build.mjs        # 将 src/* 无依赖合并为 worker.js
└── test/worker.test.mjs   # 使用 Node.js 内置 test runner 的本地测试
```

## 服务端观察

- `/`：HTML 中嵌入**实际导航请求**的完整 Worker 观察结果；不会另发 API 请求替代导航请求。
- `/api/report`：完整 JSON；报告的是**这一次 API 请求本身**（不保证与首次导航具有相同 UA/headers）。
- `request.method`、完整 `request.url`、全部查询参数（保留重复参数的 `queryEntries`）、请求头数量与 Cookie 数量及标准 Fetch API 请求属性。
- `headers`：`request.headers.entries()` 中的每一项，**原值不做筛选或脱敏**；`headerClassification` 单独提示敏感字段，不改变原值。
- `cf`：基于动态键名 + 文档已知字段完整遍历 `request.cf` 的实际可访问属性与嵌套对象，保留 `false`、`0`、`null`；不依赖固定字段白名单。由于循环对象／不可访问 getter／极端深度可能存在，专门以状态标记。
- 分类展示出口 IP、ASN、地区、协议、TLS、TCP/QUIC RTT、`edgeL4.deliveryRate`、mTLS、JA3/JA4（若启用了 Cloudflare 相关产品）。
- Cloudflare 对传入头可能改写、规范化、删除或添加，例如入站 `Accept-Encoding` 可能被改写、原值存入 `cf.clientAcceptEncoding`；因此报告反映 **Worker 可见值**，不声称等于客户端线上的全部原始字节。

## 自动浏览器检测（不触发权限弹窗）

- 浏览器环境：UA、语言、平台、逻辑 CPU 数、估算内存档位、触控数、插件与 MIME 类型、webdriver 等。
- 显示与本地化：尺寸、DPR、色域/指针媒体特征、时区、locale。
- Canvas：固定图形与字体渲染得到的像素 SHA-256，**不是**指纹唯一性/熵估计。
- WebGL：GPU/渲染器、扩展、最大纹理尺寸；`WEBGL_debug_renderer_info` 不支持时显示不可用。
- Web Audio：`OfflineAudioContext` 离线信号的渲染摘要，**不申请麦克风权限且不播放声音**。
- 字体：少量候选字体的渲染尺寸比较，**只表示启发式推断**。
- UA-CH：`getHighEntropyValues()`，在支持时自动请求高熵信息（不请求摄像头/位置等系统权限）。
- WebRTC/STUN：自动联系 Cloudflare 的 `stun.cloudflare.com:3478/udp`；汇总 ICE 地址候选并与 HTTPS 出口比较。现代浏览器可能仅返回 mDNS 主机名或无候选。未返回额外地址 **不代表无泄漏**。
- 权限状态：使用 `Permissions.query()` **读取状态**，不调用触发授权提示的传感器或设备 API。
- 本地浏览器字段、原始 Canvas/Audio 输出的摘要和其他指纹结果仅在当前标签页计算、显示；本站代码不向 Worker 上传这些结果。

## IPv4/IPv6 与 DNS 主动探针

可选 Worker 环境变量（均可省略）：

| 变量 | 示例 | 含义 |
|---|---|---|
| `PUBLIC_ORIGIN` | `https://audit.example.com` | 允许探针 API 的跨域来源，须与页面实际地址一致 |
| `IPV4_PROBE_ORIGIN` | `https://v4.example.com` | 供浏览器额外请求的专用 IPv4 候选入口 |
| `IPV6_PROBE_ORIGIN` | `https://v6.example.com` | 供浏览器额外请求的专用 IPv6 候选入口 |
| `DNS_PROBE_SUFFIX` | `dns.example.com` | 每次检查生成唯一子域名（例如 `<随机值>.dns.example.com`）并请求 `/_probe/dns` |

针对 IPv4/IPv6，**仅根据服务端实际观察到的地址族给出检测结果**，名称叫 `v4` / `v6` 并不能保证单栈。Cloudflare 通常为代理域名提供 IPv4 + IPv6，独立探针域名必须先经过 A/AAAA 与实际连接的端到端验证；不能由 Worker 单方面强制访问者使用某个地址族。未设置环境变量时 UI 显示“未配置”，不伪造结果。

针对 DNS，随机域名 HTTP 请求成功只表明浏览器成功解析并连接；**普通 Workers 无权获知连接者真正的递归 DNS 服务器**。需要在受控权威 DNS 端获得带 `QueryName`、`SourceIP`、`EDNSSubnet`、`Timestamp` 的单次查询日志，安全关联随机 token 后才能判断解析器路径。Cloudflare DNS Logs 的逐条查询数据可能需要特定套餐与 Logpush 管线。**当前代码实现了随机查询触发与“未验证”状态，但没有实现日志关联接口，不能声称完成 DNS 泄漏判断。**

在启用 `DNS_PROBE_SUFFIX` 前，还要配置完整 wildcard DNS、Worker 路由，以及覆盖 **多级子域名** 的 TLS 证书，否则可能在 TLS 握手或 DNS 阶段失败。该 DNS 流程会向 Cloudflare DNS 产生额外查询，即使 Worker 不记录，也可能存在平台日志。

## 本地构建与验证

要求本机有支持 ES Modules、`node:test`、Fetch API 的 Node.js（建议较新的 LTS 版本）。无需 npm 依赖。

```bash
node tools/build.mjs
node --check worker.js
node --test test/worker.test.mjs
```

测试使用模拟 `request.cf`，验证完整原值、嵌套字段、HTML 转义、防缓存、同源隔离、探针实测地址族等，不代替真实 Cloudflare 边缘实测。

## 部署

1. 在专用 `*.workers.dev` 主机名或新域名创建独立 Worker。采用 Cloudflare Dashboard 编辑器时直接粘贴 `worker.js`，使用 ES Module 导出（`export default { fetch(request, env) {} }`）。对于已有 Cloudflare 项目，遵守项目现有 CLI/部署规则；新项目可参考官方 `cf` CLI。
2. **不要**与登录业务共享域或 `Domain=.example.com` 类 Cookie，也不要设置鉴权密钥到 `request.cf.hostMetadata`。本 Worker 不创建 Cookie 或跨站脚本。
3. 如需多入口探针，将对应主机名/路由指向同一 Worker 并设置变量；实际确认 CORS、HTTPS 与单栈证据后再启用。
4. 复核域名与账号层面的 Cache Rules、WAF、Workers Logs、Analytics、Logpush 与其他平台功能。源码不做持久化不能保证平台不会记录。
5. 在 **真实 Cloudflare 边缘** 测试 `/`、`/api/report`、不同浏览器、VPN/代理、IPv4、IPv6、HTTP/2 和 HTTP/3；Workers Dashboard/Playground 预览可能没有真实 `request.cf`。
6. 只有在明确批准后，才可对外部署、修改 Cloudflare 账号或向 GitHub push。本项目构建和本地测试不需要外部写入。

## 威胁模型与边界

- **无弹窗不等于没有对外数据流量**。页面加载本身会把 HTTP/TLS 信息传给 Cloudflare，WebRTC STUN 与可选探针还会新建连接，页面应明确披露。
- 纯 Worker **不能读取**浏览器未开放的操作系统信息、未经授权的精确位置、摄像头/麦克风、VPN 背后真实 IP、浏览器选择的递归 DNS IP，或 TLS 握手每个原始字节。不能绕过浏览器权限边界。
- 浏览器隐私设置、扩展、企业策略和沙箱可能令指纹结果不可用或随机化。
- 不是全网浏览器指纹唯一性评估；没有全局样本，不计算伪精确的匿名性/风险百分比。
- 某些 `request.cf` 字段为 Cloudflare 套餐功能（如 Bot Management）所限定，缺失不是“访客没暴露”。
- 原始 JSON、页面文字、复制到剪贴板的结果可能含身份令牌。对截图、文件分享、工单外发应特别注意。响应设置 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`、严格 CSP、不设 CORS（仅针对受控探针例外）。

## 参考资料（2026-11-15 核验）

- Cloudflare Request 与 `IncomingRequestCfProperties`: https://developers.cloudflare.com/workers/runtime-apis/request/
- Cloudflare 请求头增改规则: https://developers.cloudflare.com/fundamentals/reference/http-headers/
- 2026-04 新增的 Layer 4 传输字段: https://developers.cloudflare.com/changelog/post/2026-04-01-l4-transport-telemetry-fields/
- Cloudflare 免费 STUN 服务: https://developers.cloudflare.com/realtime/turn/faq/
- Cloudflare authoritative DNS Logs 字段: https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/zone/dns_logs/
- Cloudflare Workers 日志: https://developers.cloudflare.com/workers/observability/logs/workers-logs/
- Cloudflare cf CLI: https://developers.cloudflare.com/cf/agents/index.md

## 未完成／真实环境验收

- 已实现：全量 Worker 可见请求头和可序列化 `request.cf`、自动浏览器检测、STUN、可选双栈 HTTP 探针、DNS nonce HTTP 请求、响应式中英文、JSON 导出。
- 尚未验证：公开 Cloudflare 边缘的 `cf` 字段覆盖、浏览器真实兼容性、IPv4/IPv6 单栈入口、DNS 企业日志收集和关联、自动化端到端浏览器测试。**尚未公开部署**。