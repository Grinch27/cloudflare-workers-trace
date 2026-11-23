// 待确认：Pages 生产域名、独立 IPv4/IPv6 探针主机以及 DNS 权威日志接入。
// 歧义：权威服务器观测到的查询来源可能是递归解析器或转发器的出口。
// 后续研究：比较自有权威 DNS 与 Cloudflare DNS Logs 的事件交付延迟。
// 潜在优化：根据实测的事件到达延迟调整有限重试和记录有效期。
// 风险：完整 API 回显可能包含 Cookie、Authorization、查询和 hostMetadata，需使用专用域名。
// 验证重点：探针 CORS、DNS 随机标识精确匹配、记录有效期、无缓存与原值回显。

import { dnsSuffix, httpsOrigin } from './probe-config.mjs';
import { formatTrace } from './trace.js';

const REPORT_PATH = '/api/report';
const ROOT_PATH = '/';
const ADDRESS_PATH = '/_probe/address';
const DNS_PATH = '/_probe/dns';
const DNS_EVIDENCE_PATH = '/_probe/dns-evidence';
export const DYNAMIC_ROUTES = [ROOT_PATH, REPORT_PATH, ADDRESS_PATH, DNS_PATH, DNS_EVIDENCE_PATH];

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
const SAME_ORIGIN_HEADERS = { 'cross-origin-resource-policy': 'same-origin' };
const DNS_RECORD_MAX_AGE_MS = 120_000;
const DNS_RESPONSE_MAX_BYTES = 8192;
const DNS_OBSERVATION_MAX_COUNT = 12;
function value(v) { return v === undefined || v === null ? null : v; }
function pick(o, keys) { return Object.fromEntries(keys.map(k => [k, value(o?.[k])])); }
function cut(s, n = 2048) { return String(s).slice(0, n); }
function ipVersion(ip) { return !ip ? null : ip.includes(':') ? 6 : ip.includes('.') ? 4 : null; }
function config(env) {
  return {
    dnsProbeSuffix: dnsSuffix(env?.DNS_PROBE_SUFFIX),
    dnsEvidenceEnabled: typeof env?.DNS_EVIDENCE?.fetch === 'function',
    publicOrigin: httpsOrigin(env?.PUBLIC_ORIGIN),
  };
}
function visibleIp(req) {
  return req.headers.get('cf-connecting-ipv6') || req.headers.get('cf-connecting-ip');
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
  const outgoingIp = visibleIp(req);
  return {
    schemaVersion: 3,
    generatedAt: new Date().toISOString(),
    provenance: {
      server: 'Original request that produced this report as seen by Cloudflare; the edge may rewrite/remove/add headers',
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
function summary(req, cfg) {
  const ip = visibleIp(req);
  return {
    network: { visibleIp: ip, ipVersion: ipVersion(ip), ...pick(req.cf, ['asn', 'asOrganization', 'colo', 'country']) },
    transport: pick(req.cf, ['httpProtocol', 'tlsVersion']),
    dnsEvidenceSuffix: cfg.dnsEvidenceEnabled ? cfg.dnsProbeSuffix : null,
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

function prefersHtml(accept = '') {
  const weights = new Map();
  for (const entry of accept.toLowerCase().split(',')) {
    const [type, ...params] = entry.trim().split(';');
    const quality = params.map(parameter => parameter.trim()).find(parameter => parameter.startsWith('q='));
    const weight = quality ? Number(quality.slice(2)) : 1;
    if (weight >= 0 && weight <= 1) weights.set(type.trim(), weight);
  }
  const html = weights.get('text/html') ?? 0;
  const plain = weights.get('text/plain') ?? weights.get('text/*') ?? weights.get('*/*') ?? 0;
  return html > 0 && html >= plain;
}

function escapeHtml(text) {
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

async function homepage(req, cfg, assets) {
  const html = prefersHtml(req.headers.get('accept') || '');
  const headers = { ...SAME_ORIGIN_HEADERS, vary:'Accept' };
  if (req.method === 'HEAD') {
    const type = html ? 'text/html' : 'text/plain';
    return reply(req, null, type + '; charset=utf-8', 200, headers);
  }

  const data = report(req);
  const server = {
    network:data.network, transport:data.transport, ...data,
    dnsEvidenceSuffix:cfg.dnsEvidenceEnabled ? cfg.dnsProbeSuffix : null,
  };
  const trace = formatTrace({
    server, browserOnly:{status:'not-run'}, activeProbes:{status:'not-run'},
  });
  if (!html) return reply(req, trace, 'text/plain; charset=utf-8', 200, headers);

  const unavailable = () => reply(req, 'Page template unavailable', 'text/plain; charset=utf-8', 503, headers);
  try {
    const asset = await assets.fetch(new URL('/', req.url));
    const csp = asset.headers.get('content-security-policy');
    if (!asset.ok || !csp) return unavailable();
    const template = await asset.text();
    const marker = /<!--SERVER_TRACE-->[\s\S]*?<!--\/SERVER_TRACE-->/;
    const probeMarker = 'data-probe-input="{}"';
    if (!marker.test(template) || !template.includes(probeMarker)) return unavailable();
    const probeInput = JSON.stringify({
      visibleIp:server.network.visibleIp, dnsEvidenceSuffix:server.dnsEvidenceSuffix,
    });
    const attribute = escapeHtml(probeInput).replaceAll('"', '&quot;');
    const page = template.replace(probeMarker, () => 'data-probe-input="' + attribute + '"')
      .replace(marker, () => escapeHtml(trace));
    return reply(req, page, 'text/html; charset=utf-8', 200, { ...headers, 'content-security-policy':csp });
  } catch {
    return unavailable();
  }
}
function literalFamily(value) {
  if (typeof value !== 'string') return null;
  if (/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) {
    return value.split('.').every(part => Number(part) <= 255) ? 4 : null;
  }
  if (value.includes(':') && /^[a-f0-9:.]+$/i.test(value)) {
    try {
      return new URL('https://[' + value + ']/').hostname.startsWith('[') ? 6 : null;
    } catch { return null; }
  }
  return null;
}

function clientSubnet(value) {
  if (typeof value !== 'string') return null;
  const [address, prefix, extra] = value.split('/');
  const family = literalFamily(address);
  if (!family || extra !== undefined || !/^[0-9]{1,3}$/.test(prefix ?? '')) return null;
  return Number(prefix) <= (family === 4 ? 32 : 128) ? value : null;
}

async function readEvidenceBody(response) {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return JSON.parse(text + decoder.decode());
      bytes += value.byteLength;
      if (bytes > DNS_RESPONSE_MAX_BYTES) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

function matchingDnsObservations(entries, name, now) {
  const matches = new Map();
  for (const entry of entries) {
    if (entry?.name !== name || !['A', 'AAAA', 'HTTPS'].includes(entry.queryType)) continue;
    if (!literalFamily(entry.sourceIp) || !Number.isSafeInteger(entry.observedAt)) continue;
    if (entry.observedAt < now - DNS_RECORD_MAX_AGE_MS || entry.observedAt > now + 5000) continue;
    const ecs = clientSubnet(entry.ecs);
    const key = [entry.queryType, entry.sourceIp, ecs].join('|');
    const previous = matches.get(key);
    if (!previous || previous.observedAt < entry.observedAt) {
      matches.set(key, {
        queryType: entry.queryType, sourceIp: entry.sourceIp, ecs, observedAt: entry.observedAt,
      });
    }
  }
  return [...matches.values()].sort((a, b) => b.observedAt - a.observedAt).slice(0, DNS_OBSERVATION_MAX_COUNT);
}

async function dnsEvidence(req, url, cfg, binding) {
  const answer = (status, code, observations = []) => reply(req,
    JSON.stringify({ type: 'dns-authority-observation', status, observations }),
    'application/json; charset=utf-8', code, SAME_ORIGIN_HEADERS);
  if (!cfg.dnsProbeSuffix || !cfg.dnsEvidenceEnabled) return answer('not-configured', 503);
  const nonce = url.searchParams.get('nonce');
  if (!nonce || !/^[a-f0-9]{32}$/.test(nonce) || url.searchParams.size !== 1) return answer('invalid-nonce', 400);
  const origin = req.headers.get('origin');
  if (origin && origin !== url.origin) return answer('forbidden', 403);
  const name = nonce + '.' + cfg.dnsProbeSuffix;
  const lookup = new URL('https://dns-evidence.invalid/observations');
  lookup.searchParams.set('name', name);
  try {
    const upstream = await binding.fetch(new Request(lookup, { signal: AbortSignal.timeout(1500) }));
    if (!upstream.ok) return answer('unavailable', 502);
    const body = await readEvidenceBody(upstream);
    if (!Array.isArray(body?.observations)) return answer('unavailable', 502);
    const observations = matchingDnsObservations(body.observations, name, Date.now());
    return answer(observations.length ? 'observed' : 'not-observed', 200, observations);
  } catch {
    return answer('unavailable', 502);
  }
}

export function onRequest({ request: req, env }) {
  const url = new URL(req.url);
  const path = url.pathname;
  const cfg = config(env);
  const isAddressProbe = path === ADDRESS_PATH || path === DNS_PATH;
  if (req.method === 'OPTIONS' && isAddressProbe) return reply(req, null, 'text/plain', 204, corsForProbe(req, cfg));
  if (!['GET', 'HEAD'].includes(req.method)) {
    return reply(req, 'Method Not Allowed', 'text/plain; charset=utf-8', 405, {
      allow: isAddressProbe ? 'GET, HEAD, OPTIONS' : 'GET, HEAD',
    });
  }
  if (path === ROOT_PATH) return homepage(req, cfg, env?.ASSETS);
  if (path === DNS_EVIDENCE_PATH) return dnsEvidence(req, url, cfg, env?.DNS_EVIDENCE);
  if (isAddressProbe) {
    const ip = visibleIp(req);
    const isDns = path === DNS_PATH;
    const answer = {
      type: isDns ? 'dns-http-reachability' : 'address-family',
      visibleIp: ip,
      ipVersion: ipVersion(ip),
      colo: value(req.cf?.colo),
      asn: value(req.cf?.asn),
      protocol: value(req.cf?.httpProtocol),
      hostname: cut(url.hostname, 255),
      warning: isDns
        ? 'HTTP reachability cannot identify the DNS recursive resolver or prove absence of DNS leaks.'
        : 'Only the actually observed address family is verified; hostname naming does not force IPv4/IPv6.',
    };
    return reply(req, JSON.stringify(answer), 'application/json; charset=utf-8', 200, corsForProbe(req, cfg));
  }
  if (path === REPORT_PATH) {
    const compact = url.searchParams.get('view') === 'summary';
    const data = req.method === 'HEAD' ? null : compact ? JSON.stringify(summary(req, cfg)) : JSON.stringify(report(req), null, 2);
    return reply(req, data, 'application/json; charset=utf-8', 200, SAME_ORIGIN_HEADERS);
  }
  return reply(req, 'Not Found', 'text/plain; charset=utf-8', 404);
}
