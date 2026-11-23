# 连接检测

Cloudflare Pages 上的纯文本风格连接检测。访问根地址 `/` 即可获取 `key=value` 报告。浏览器在同一份文本中追加本地检测和网络探针结果，可复制全文或下载 TXT。命令行通过同一地址直接读取。

## 请求与额度

| 路由 | 服务方式 | 内容 |
| --- | --- | --- |
| `/` | Pages Function | 统一入口，服务端直接观察本次首页请求 |
| `/assets/*`、404 | Pages 静态资源 | CSS、JS 和静态错误页 |
| `/api/report` | Pages Function | 原有 JSON API，支持 `?view=summary` |
| `/_probe/address`、`/_probe/dns`、`/_probe/dns-evidence` | Pages Functions | 配置相应入口后追加的网络探针请求 |

构建在 `dist` 生成 `_routes.json`，只将上表中五条动态路径交给 Functions。默认探针配置下，每次打开首页调用一次 Function。CSS 和 JS 走静态资源，已配置的探针请求单独计量。首页按 `Accept` 选择响应形式，返回 `Vary: Accept` 和 `Cache-Control: no-store`。[Pages 定价](https://developers.cloudflare.com/pages/functions/pricing/) · [调用路由](https://developers.cloudflare.com/pages/functions/routing/#functions-invocation-routes)

服务端报告保留 `schemaVersion=3`，反映访问对应接口的请求。它回显所有可见请求头、URL 和可序列化 `request.cf`，可能包含 Cookie、Authorization、查询参数和 hostMetadata。使用独立站点域名。用于分享的脱敏摘要只有协议、地址族和检测状态。

## Trace 格式

```text
traceVersion=1
server.network.visibleIp="203.0.113.10"
server.request.queryEntries[0][0]="tag"
server.request.queryEntries[0][1]="a=b"
server.headers["x.sample"]="line 1\nline 2"
server.transport.clientTcpRtt=null
browserOnly.status="complete"
activeProbes.dns.status="not-configured"
```

- 每行在第一个 `=` 处分成字段路径和 JSON 值。对象字段用点号分隔，数组位置用 `[0]` 表示。
- 含点号、等号或其他特殊字符的对象键用 JSON 字符串下标表示，键中的等号编码为 `\u003d`。空对象、空数组、空字符串、`false`、`0` 和 `null` 各自保留。
- 命令行或发送 `Accept: text/plain` 的客户端直接收到文本，客户端检测状态是 `not-run`。浏览器按 `Accept` 取得包含同一文本格式的页面，脚本运行后将检测结果填入 `browserOnly.*` 和 `activeProbes.*`。
- IPv4、IPv6、双栈 HTTPS、权威 DNS 记录关联和 WebRTC 的采集及判断仍使用原有逻辑。文本只负责呈现结果。浏览器读取本次请求的结构化基线进行 WebRTC 对照，HTTPS 和 DNS 探针仍受对应地址、CORS 及 CSP 约束。

## 本地验证

需要 Node.js 22 或更新版本。构建只使用 Node.js 内置模块。

    node tools/build.mjs
    node --test test/pages.test.mjs
    npx --yes wrangler@4.162.0 pages dev

本地运行后，直接读取根地址。

    curl -fsS http://127.0.0.1:8788/

回环 TLS、DNS 随机关联和 DNSSEC 运行方法见[网络验收](docs/ipv4-ipv6-validation.md)。

## Cloudflare Pages 部署设置

| 设置 | 值 |
| --- | --- |
| Git 仓库 | Grinch27/cloudflare-workers-trace |
| 生产分支 | main |
| 框架预设 | None |
| 根目录 | 仓库根目录 |
| Build command | node tools/build.mjs |
| Build output directory | dist |

Cloudflare Pages 从 dist 提供静态文件，从仓库根目录的 functions/ 编译 API。Pages 项目的实际 pages.dev 地址以创建结果为准。[Pages Git 集成](https://developers.cloudflare.com/pages/get-started/git-integration/)

从已有 Worker 迁移时，先核对当前 main 的构建触发关系。暂停旧 Workers Builds 自动构建、推送迁移提交及新建 Cloudflare Pages 项目属于生产发布变更。获得批准后可先暂停旧构建，再推送并连接 Pages，核对新地址后决定旧地址的处理。

## 可选探针

| 变量 | 配置位置 | 用途 |
| --- | --- | --- |
| IPV4_PROBE_ORIGIN | Pages 构建变量 | A-only HTTPS 入口 |
| IPV6_PROBE_ORIGIN | Pages 构建变量 | AAAA-only HTTPS 入口 |
| DUAL_STACK_PROBE_ORIGIN | Pages 构建变量 | 双栈 HTTPS 入口 |
| PUBLIC_ORIGIN | 探针端运行时变量 | 允许进行跨域探针请求的主页面 HTTPS Origin |
| DNS_PROBE_SUFFIX | Pages 构建变量及运行时变量 | 指定随机域名后缀，权威证据启用时两处应一致 |
| DNS_EVIDENCE | 可选 Functions 服务绑定 | 查询已配置的权威 DNS 证据服务 |

三类 HTTPS 入口使用不同 DNS 主机名。构建将允许的 Origin 写入静态 CSP。探针返回 HTTPS 终止端观察到的地址族，通过 A/AAAA 查询和实际连接判定单栈。DNS 随机主机名需要可用的 DNS 委派、HTTPS 证书及路由。

权威数据源通过可选的 DNS_EVIDENCE 服务绑定提供。探针服务接收 GET /observations?name=<随机标识>.<DNS_PROBE_SUFFIX>，返回 JSON 对象 observations 数组。每条记录包含小写无末尾圆点的 name、A/AAAA/HTTPS 类型 queryType、实际来源 sourceIp、Unix 毫秒 observedAt，以及可选的 CIDR ecs。主站仅返回精确随机标识最近 120 秒的有限结果。持有随机标识的客户端可读取对应的短时记录。

HTTPS 可达性与权威查询结果各有独立状态。判断 DNS 绕行要比对预期解析器和实际网络配置。WebRTC 候选仅在页面内比较，同地址族出口不同可以作为进一步排查的线索。
