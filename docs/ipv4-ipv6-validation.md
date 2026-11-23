# IPv4、IPv6、双栈 HTTPS 与 DNS 验收

## 目标与前提

分别核验三类 DNS 记录、实际 TLS 连接以及探针服务端观察到的地址族。生产入口与本地回环实验分别记录。

- Pages Functions 的 `/_probe/address` 只报告服务端看到的 IP/地址族；域名名称并不能强制连接协议。
- 在 Cloudflare 代理层确认 A/AAAA 发布、TLS 证书、域名路由、客户端是否连接 IPv4/IPv6。普通 `*.workers.dev` 与标准代理域名不保证独立单栈。
- 选择入口时以该入口实际发布的 A/AAAA 为准。代理层会自动补发 AAAA 的情况，应选用能独立控制地址族的专用 HTTPS 终止端，并从实际连接获取对端地址。
- `CF-Connecting-IP` 可能受 Cloudflare Pseudo IPv4 功能影响；需核对原始 Cloudflare 配置，且记录真实客户端连接的网络证据，不可只凭头字段作出绝对判定。

## 回环实验

需要 Node.js、OpenSSL、curl、Python 3、`dnspython[dnssec]` 和系统的 `libunbound`。测试使用 IPv4 和 IPv6 回环地址、动态端口、临时证书及本地权威 DNS。

```bash
node tools/build.mjs
node --test test/pages.test.mjs
python3 -m pip install 'dnspython[dnssec]==2.8.0'
python3 test/probe_lab.py
```

| 实验入口 | 权威 A / AAAA | IPv4 HTTPS | IPv6 HTTPS |
|---|---|---|---|
| A-only | 有 A，AAAA 空答案 | 返回 200，探针观察 IPv4 | TCP 拒绝 |
| AAAA-only | A 空答案，有 AAAA | TCP 拒绝 | 返回 200，探针观察 IPv6 |
| 双栈 | 均有 | 返回 200，探针观察 IPv4 | 返回 200，探针观察 IPv6 |

实验将权威 DNS 的应答结果与回环 TLS 的实际远端地址对照，再检查Pages 探针处理器返回的 `ipVersion`。随机 DNS 标识在查询前应为空。真实 UDP 查询完成后，首次同源查询应取得相同标识的权威记录，另一个随机标识仍为空。

DNSSEC 对照使用仅供测试的信任锚。权威端给两个域名提供等价 A 记录和 RRSIG，其中一份签名损坏。Unbound 对有效签名应返回 `secure=true`，坏签名应返回 `bogus=true`。这里以 libunbound 的验证标志为准。公网阶段须另测浏览器、其递归解析器和 HTTPS 控制组。

## 验证门槛

1. **G1（只读）**：获取拟用的 `IPV4_PROBE_ORIGIN`、`IPV6_PROBE_ORIGIN` 和 `DUAL_STACK_PROBE_ORIGIN`。分别检查 A/AAAA、CNAME、代理及 IPv4/IPv6 转换。三种入口使用不同的 DNS 主机名。
2. **G2（需明确授权的外部变更）**：如需增改 Cloudflare DNS、Pages 路由、证书、运行时变量或生产配置，先另行批准，不因已批准上传 GitHub 代码而自动批准。
3. **G3（实测）**：在具备 IPv4 和 IPv6 出口的不同网络上，分别执行以下命令（将 URL 换成**实际已配置**的完整 HTTPS 入口）；保留退出状态、远端地址、HTTP 状态、响应 JSON 及测试时间。

```bash
dig +short A v4.example.com
dig +short AAAA v4.example.com
dig +short A v6.example.com
dig +short AAAA v6.example.com
dig +short A dual.example.com
dig +short AAAA dual.example.com

curl -4 --verbose --fail-with-body https://v4.example.com/_probe/address
curl -6 --verbose --fail-with-body https://v4.example.com/_probe/address
curl -4 --verbose --fail-with-body https://v6.example.com/_probe/address
curl -6 --verbose --fail-with-body https://v6.example.com/_probe/address
curl -4 --verbose --fail-with-body https://dual.example.com/_probe/address
curl -6 --verbose --fail-with-body https://dual.example.com/_probe/address
```

示例域名仅供替换，**不是已部署域名**。`curl -4/-6` 约束客户端连接地址族，单独执行不能证明所有网络/代理环境具有相同结果。

## 通过标准

- IPv4 专用入口：有可信网络路径证据证明 HTTPS 仅通过 IPv4 成功，并在 IPv6-only 连接尝试时失败；IPv6 专用入口反之。
- 双栈入口：A 和 AAAA 均已发布，强制 IPv4、IPv6 两种连接均通过，并且探针分别返回对应地址族。
- 校验实际 DNS 解析与客户端 TCP/QUIC 远端地址，而不只检查域名和 Worker 返回的 `ipVersion`。
- 成功响应中 `visibleIp` 与观察到的实际连接地址族符合预期；不一致必须解释代理、伪 IPv4 与 NAT64/464XLAT 等影响。
- 记录每种网络、每个入口、每个协议族的成功/失败和阻塞原因；一旦未验证、缺少证据或 Cloudflare 不支持该拓扑，标记 `inconclusive`，不得显示“通过”。
- 无数据收集服务、日志关联或 Cloudflare 账号更改的扩权操作。

## 当前状态

公开单栈和双栈探针、真实浏览器跨域请求、生产权威 DNS 数据源及其 DNSSEC 对照，均需在对应入口配置后实测。
