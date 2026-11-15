// 待确认：公开部署域名、Cloudflare 套餐、独立 IPv4/IPv6 探针主机以及 DNS 权威日志接入。
// 后续研究：Cloudflare DNS Enterprise Query logs 到仅限访客自查的隔离关联通道。
// 风险：无脱敏回显会把 Cookie/Authorization/URL 查询和 hostMetadata 显示给页面脚本，可能破坏 HttpOnly 隔离；必须使用隔离专用域名、无第三方脚本、严格 CSP、不缓存。
// 验证重点：请求与浏览器检测来源隔离、跨域探针 CORS、无缓存、CSP、输入上限与边缘字段可选性。

const HTML = __PAGE_HTML__;
const CSS = __SITE_CSS__;
const CLIENT_JS = __CLIENT_JS__;
const CF_FIELDS = {
  network: ['asn', 'asOrganization', 'colo', 'country', 'continent', 'isEUCountry'],
  geography: ['city', 'region', 'regionCode', 'postalCode', 'metroCode', 'latitude', 'longitude', 'timezone'],
  transport: ['httpProtocol', 'tlsVersion', 'tlsCipher', 'clientTcpRtt', 'clientQuicRtt', 'clientAcceptEncoding', 'requestPriority', 'tlsClientHelloLength'],
  tls: ['tlsClientCiphersSha1', 'tlsClientExtensionsSha1', 'tlsClientExtensionsSha1Le', 'tlsClientRandom'],
  bots: ['score', 'verifiedBot', 'ja3Hash', 'ja4', 'staticResource', 'signedAgent', 'detectionIds', 'jsDetection'],
};
const SECRET_HEADER = /(?:auth|cookie|cred|csrf|jwt|key|pass|secret|session|signature|token|set-cookie)/i;
const BASE_HEADERS = {
  'cache-control': 'private, no-store, max-age=0',
  'cdn-cache-control': 'no-store',
  'pragma': 'no-cache',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=()',
  'cross-origin-opener-policy': 'same-origin',
};
function value(v) { return v === undefined || v === null ? null : v; }
function pick(o, keys) { return Object.fromEntries(keys.map(k => [k, value(o?.[k])])); }
function cut(s, n = 2048) { return String(s).slice(0, n); }
function ipVersion(ip) { return !ip ? null : ip.includes(':') ? 6 : ip.includes('.') ? 4 : null; }
function originOf(input) {
  if (!input || typeof input !== 'string') return null;
  try {
    const u = new URL(input);
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.pathname !== '/' || u.origin === 'null') return null;
    return u.origin;
  } catch { return null; }
}
function dnsSuffix(input) {
  const suffix = String(input || '').trim().toLowerCase();
  return suffix.length <= 180 && /^(?:[a-z0-9-]+\.)+[a-z]{2,63}$/.test(suffix) ? suffix : null;
}
function config(env) {
  return {
    ipv4ProbeOrigin: originOf(env?.IPV4_PROBE_ORIGIN),
    ipv6ProbeOrigin: originOf(env?.IPV6_PROBE_ORIGIN),
    dnsProbeSuffix: dnsSuffix(env?.DNS_PROBE_SUFFIX),
    publicOrigin: originOf(env?.PUBLIC_ORIGIN),
  };
}
// 原样保留 Worker 实际收到的全部头字段值；Headers API 可能合并重复头并规范化名称。
function headersRaw(headers) {
  const entries = [...headers.entries()].sort(([a], [b]) => a.localeCompare(b));
  return Object.fromEntries(entries);
}
// 显示哪些字段属于认证信息，不改变或隐藏它们的实际值。
function headerClassification(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, val]) => [key, {
    valueLength: val.length,
    sensitive: SECRET_HEADER.test(key),
    source: key.toLowerCase().startsWith('cf-') ? 'potential-cloudflare-added-or-rewritten' : 'worker-visible-request',
  }]));
}
// 尽可能遍历 request.cf 实际暴露的可序列化属性，包括文档已知字段与未预先列出的新字段。
// 不依赖固定白名单；保留 0 / false / null，并将不可序列化情况明确记录。
function cfRaw(cf) {
  const seen = new WeakSet();
  function clone(value, depth = 0) {
    if (value === undefined) return '[undefined]';
    if (typeof value === 'bigint') return String(value) + 'n';
    if (typeof value === 'symbol' || typeof value === 'function') return '[' + typeof value + ']';
    if (!value || typeof value !== 'object') return value;
    if (depth >= 32) return '[max-depth:32]';
    if (seen.has(value)) return '[circular-or-repeated-reference]';
    seen.add(value);
    if (Array.isArray(value)) return value.map(x => clone(x, depth + 1));
    const keys = Object.getOwnPropertyNames(value);
    if (depth === 0) {
      // Cloudflare 新字段可通过属性枚举发现；这里补充已知键，兼容非 enumerable 的代理对象。
      for (const name of [...Object.values(CF_FIELDS).flat(), 'botManagement', 'hostMetadata', 'edgeL4', 'tlsClientAuth', 'verifiedBotCategory']) {
        if (!keys.includes(name)) keys.push(name);
      }
    }
    const out = Object.create(null);
    for (const key of keys) {
      let v;
      try { v = value[key]; } catch (e) { out[key] = '[getter-error:' + String(e?.name || 'error') + ']'; continue; }
      // 已知但当前不可用的 CF 属性省略；实际存在且值为 null/false/0 的属性保留。
      if (v !== undefined) out[key] = clone(v, depth + 1);
    }
    return out;
  }
  return clone(cf || {});
}
function report(req) {
  const cf = cfRaw(req.cf);
  const url = new URL(req.url);
  const headers = headersRaw(req.headers);
  const cookies = req.headers.get('cookie') || '';
  const outgoingIp = req.headers.get('cf-connecting-ipv6') || req.headers.get('cf-connecting-ip');
  return {
    schemaVersion: 3,
    generatedAt: new Date().toISOString(),
    provenance: {
      server: 'Exact Worker-visible navigation/API request; Cloudflare may rewrite/remove/add headers',
      browser: 'Computed locally by page JavaScript; not transmitted to the Worker by this application',
      probes: 'Additional outbound tests, not part of the original navigation request',
    },
    request: {
      method: req.method,
      url: req.url,
      path: url.pathname,
      queryParameters: Object.fromEntries(url.searchParams),
      queryEntries: [...url.searchParams.entries()],
      headerCount: Object.keys(headers).length,
      cookieCount: cookies ? cookies.split(';').filter(Boolean).length : 0,
      cfMetadataAvailable: Boolean(req.cf),
      fetchApiProperties: {
        redirect: value(req.redirect),
        referrer: value(req.referrer),
        referrerPolicy: value(req.referrerPolicy),
        mode: value(req.mode),
        credentials: value(req.credentials),
        destination: value(req.destination),
        integrity: value(req.integrity),
        keepalive: value(req.keepalive),
        bodyUsed: value(req.bodyUsed),
      },
    },
    network: {
      visibleIp: outgoingIp,
      ipVersion: ipVersion(outgoingIp),
      cfConnectingIp: req.headers.get('cf-connecting-ip'),
      cfConnectingIpv6: req.headers.get('cf-connecting-ipv6'),
      ...pick(cf, CF_FIELDS.network),
    },
    geography: pick(cf, CF_FIELDS.geography),
    transport: { ...pick(cf, CF_FIELDS.transport), edgeDeliveryRate: value(cf.edgeL4?.deliveryRate) },
    tls: pick(cf, CF_FIELDS.tls),
    botManagement: { available: Boolean(cf.botManagement), ...pick(cf.botManagement, CF_FIELDS.bots) },
    mutualTls: {
      available: Boolean(cf.tlsClientAuth),
      ...pick(cf.tlsClientAuth, ['certPresented', 'certVerified', 'certRevoked', 'certIssuerDN', 'certSubjectDN', 'certFingerprintSHA1', 'certSerial', 'certNotBefore', 'certNotAfter']),
    },
    // 完整请求头原值（含 Cookie / Authorization 等），仅反馈给该请求的客户端。
    headers,
    // 动态完整 cf 对象，优先按实际对象序列化，而不是只显示固定预选属性。
    cf,
    headerClassification: headerClassification(headers),
    warnings: [
      'RAW CREDENTIAL REFLECTION: Cookie, Authorization, and other secrets are visible to page JavaScript and in exports. Do NOT host alongside authenticated applications.',
      'request.cf.hostMetadata may be operator-configured data, not visitor-supplied information; never put secrets there.',
      'Headers API may merge duplicates/change header casing; some values were overwritten by Cloudflare before this Worker.',
    ],
    limits: {
      dnsResolver: 'not observable from standard Worker HTTP requests',
      realIpBehindVpn: 'not directly observable',
      fingerprintUniqueness: 'cannot be calculated without population data and is not estimated',
    },
  };
}
function corsForProbe(req, cfg) {
  const origin = req.headers.get('origin');
  return origin && cfg.publicOrigin && origin === cfg.publicOrigin ? {
    'access-control-allow-origin': cfg.publicOrigin,
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'access-control-max-age': '600',
    'vary': 'Origin',
    'cross-origin-resource-policy': 'cross-origin',
  } : { 'vary': 'Origin', 'cross-origin-resource-policy': 'same-origin' };
}
function reply(req, body, contentType, status = 200, more = {}) {
  return new Response(req.method === 'HEAD' || status === 204 ? null : body, {
    status, headers: { ...BASE_HEADERS, 'content-type': contentType, ...more },
  });
}
function csp(cfg) {
  const origins = [cfg.ipv4ProbeOrigin, cfg.ipv6ProbeOrigin].filter(Boolean);
  const dns = cfg.dnsProbeSuffix ? 'https://*.' + cfg.dnsProbeSuffix : null;
  return [
    "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
    "connect-src 'self' " + [...new Set([...origins, dns].filter(Boolean))].join(' '),
    "base-uri 'none'", "object-src 'none'", "form-action 'none'", "frame-ancestors 'none'",
  ].join('; ');
}
function htmlJsonSafe(s) { return JSON.stringify(s).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029'); }
export default {
  fetch(req, env) {
    const url = new URL(req.url);
    const cfg = config(env);
    const isProbe = url.pathname === '/_probe/address' || url.pathname === '/_probe/dns';
    if (req.method === 'OPTIONS' && isProbe) return reply(req, null, 'text/plain', 204, corsForProbe(req, cfg));
    if (!['GET', 'HEAD'].includes(req.method)) return reply(req, 'Method Not Allowed', 'text/plain; charset=utf-8', 405, {allow: isProbe ? 'GET, HEAD, OPTIONS' : 'GET, HEAD'});
    if (isProbe) {
      const ip = req.headers.get('cf-connecting-ipv6') || req.headers.get('cf-connecting-ip');
      const answer = {
        type: url.pathname === '/_probe/dns' ? 'dns-http-reachability' : 'address-family',
        visibleIp: ip,
        ipVersion: ipVersion(ip),
        colo: value(req.cf?.colo),
        protocol: value(req.cf?.httpProtocol),
        hostname: cut(url.hostname, 255),
        warning: url.pathname === '/_probe/dns'
          ? 'HTTP reachability cannot identify the DNS recursive resolver or prove absence of DNS leaks.'
          : 'Only the actually observed address family is verified; hostname naming does not force IPv4/IPv6.',
      };
      return reply(req, JSON.stringify(answer), 'application/json; charset=utf-8', 200, corsForProbe(req, cfg));
    }
    if (url.pathname === '/') {
      const boot = htmlJsonSafe({ server: report(req), config: { ...cfg, probeAuto: true } });
      return reply(req, HTML.replace('<!--BOOT_DATA-->', boot), 'text/html; charset=utf-8', 200, {
        'content-security-policy': csp(cfg), 'cross-origin-resource-policy': 'same-origin',
      });
    }
    if (url.pathname === '/api/report') return reply(req, JSON.stringify(report(req), null, 2), 'application/json; charset=utf-8', 200, {'cross-origin-resource-policy':'same-origin'});
    if (url.pathname === '/assets/client.js') return reply(req, CLIENT_JS, 'text/javascript; charset=utf-8', 200, {'cross-origin-resource-policy':'same-origin'});
    if (url.pathname === '/assets/site.css') return reply(req, CSS, 'text/css; charset=utf-8', 200, {'cross-origin-resource-policy':'same-origin'});
    if (url.pathname === '/favicon.ico') return reply(req, null, 'image/x-icon', 204);
    return reply(req, 'Not Found', 'text/plain; charset=utf-8', 404);
  },
};
