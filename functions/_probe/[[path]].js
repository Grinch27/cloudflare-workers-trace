// 待确认：公网 HTTPS 探针和权威 DNS 后端。
// 歧义：可达性与权威查询记录独立。后续研究：实际入口与 DNSSEC 对照。
// 潜在优化：按记录交付延迟调整轮询。风险：探针需受控来源。
// 验证重点：_routes.json 精确匹配，跨源请求不携带凭据。
export { onRequest } from '../../src/edge.js';
