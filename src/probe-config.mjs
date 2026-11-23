// 待确认：独立 HTTPS 探针和 DNS 观测域名。
// 歧义：探针主机名只代表配置，实际地址族由探针观测及独立验收确定。
// 后续研究：公网双栈和权威 DNS 后端接入。
// 潜在优化：可以在发布前自动对照探针的 A/AAAA 记录。
// 风险：构建参数会写入公开静态文件，只能填写公开的 HTTPS Origin 和 DNS 后缀。
// 验证重点：同一组安全校验用于 Pages 静态 CSP 和运行时探针。

export function httpsOrigin(input) {
  if (typeof input !== 'string' || !input) return null;
  try {
    const url = new URL(input);
    const safeHost = /^(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*\.?|\[[a-f0-9:]+\])$/.test(url.hostname);
    if (safeHost && url.protocol === 'https:' && !url.username && !url.password && !url.search && !url.hash && url.pathname === '/') {
      return url.origin;
    }
  } catch { return null; }
  return null;
}

export function dnsSuffix(input) {
  const suffix = String(input || '').trim().toLowerCase();
  const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const labels = suffix.split('.');
  return suffix.length <= 180 && labels.length >= 2 && labels.every(part => label.test(part))
    && /^[a-z]{2,63}$/.test(labels.at(-1)) ? suffix : null;
}

export function probeOrigins(env) {
  return {
    ipv4ProbeOrigin: httpsOrigin(env.IPV4_PROBE_ORIGIN),
    ipv6ProbeOrigin: httpsOrigin(env.IPV6_PROBE_ORIGIN),
    dualStackProbeOrigin: httpsOrigin(env.DUAL_STACK_PROBE_ORIGIN),
  };
}
