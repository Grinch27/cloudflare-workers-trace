# IPv4 / IPv6 专用入口验收计划（未执行）

## 目标与前提

用户要求下一阶段验证真实单栈能力，而非依靠 `v4`、`v6` 域名推断。**当前未配置任何公开探针入口，未执行真实 IPv4/IPv6 网络测试。**

- 现有 Worker 的 `/_probe/address` 只报告服务端看到的 IP/地址族；域名名称并不能强制连接协议。
- 在 Cloudflare 代理层确认 A/AAAA 发布、TLS 证书、域名路由、客户端是否连接 IPv4/IPv6。普通 `*.workers.dev` 与标准代理域名不保证独立单栈。
- `CF-Connecting-IP` 可能受 Cloudflare Pseudo IPv4 功能影响；需核对原始 Cloudflare 配置，且记录真实客户端连接的网络证据，不可只凭头字段作出绝对判定。

## 验证门槛

1. **G1（只读）**：获取拟用的 `IPV4_PROBE_ORIGIN` 和 `IPV6_PROBE_ORIGIN`。检查 DNS A/AAAA 记录及是否受到 CNAME 解析、代理、缓存和 IPv4/IPv6 转换影响；记录实际查询结果，不提前断言单栈。
2. **G2（需明确授权的外部变更）**：如需增改 Cloudflare DNS、Worker 路由、证书、环境变量或生产配置，先另行批准，不因已批准上传 GitHub 代码而自动批准。
3. **G3（实测）**：在具备 IPv4 和 IPv6 出口的不同网络上，分别执行以下命令（将 URL 换成**实际已配置**的完整 HTTPS 入口）；保留退出状态、远端地址、HTTP 状态、响应 JSON 及测试时间。

```bash
dig +short A v4.example.com
dig +short AAAA v4.example.com
dig +short A v6.example.com
dig +short AAAA v6.example.com

curl -4 --verbose --fail-with-body https://v4.example.com/_probe/address
curl -6 --verbose --fail-with-body https://v4.example.com/_probe/address
curl -4 --verbose --fail-with-body https://v6.example.com/_probe/address
curl -6 --verbose --fail-with-body https://v6.example.com/_probe/address
```

示例域名仅供替换，**不是已部署域名**。`curl -4/-6` 约束客户端连接地址族，单独执行不能证明所有网络/代理环境具有相同结果。

## 通过标准

- IPv4 专用入口：有可信网络路径证据证明 HTTPS 仅通过 IPv4 成功，并在 IPv6-only 连接尝试时失败；IPv6 专用入口反之。
- 校验实际 DNS 解析与客户端 TCP/QUIC 远端地址，而不只检查域名和 Worker 返回的 `ipVersion`。
- 成功响应中 `visibleIp` 与观察到的实际连接地址族符合预期；不一致必须解释代理、伪 IPv4 与 NAT64/464XLAT 等影响。
- 记录每种网络、每个入口、每个协议族的成功/失败和阻塞原因；一旦未验证、缺少证据或 Cloudflare 不支持该拓扑，标记 `inconclusive`，不得显示“通过”。
- 无数据收集服务、日志关联或 Cloudflare 账号更改的扩权操作。

## 当前状态

未验证：单栈 DNS、TLS 路由、真实边缘可见地址族、浏览器跨域探针兼容性。不能依赖当前模拟测试推断上述结果。
