// 待确认：公网探针所在的 HTTP 终止端如何提供服务端观测地址。
// 歧义：本地 TCP 对端地址与 Cloudflare 提供的边缘字段属于不同来源。
// 后续研究：使用真实单栈公网入口和代理网络复测同一矩阵。
// 潜在优化：为公网对照加入单独的带证书浏览器验收。
// 风险：本文件只用于回环接口测试，生成的证书和密钥只在测试进程中使用。
// 验证重点：TLS 与 SNI、实际 TCP 地址族、Pages 探针处理器及权威查询结果接入。
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { onRequest } from '../functions/_probe/[[path]].js';

const [keyFile, certFile, evidencePort] = process.argv.slice(2);
const tls = {key:readFileSync(keyFile), cert:readFileSync(certFile)};

const env = {
  DNS_PROBE_SUFFIX: 'dns.probe.test',
  DNS_EVIDENCE: {
    fetch(request) {
      const lookup = new URL(request.url);
      const origin = 'http://127.0.0.1:' + evidencePort;
      return fetch(origin + lookup.pathname + lookup.search, {signal:request.signal, redirect:'error'});
    },
  },
};

async function listen(host, port = 0) {
  const server = createServer(tls, async (incoming, outgoing) => {
    try {
      const headers = new Headers({'cf-connecting-ip':incoming.socket.remoteAddress});
      if (incoming.headers.origin) headers.set('origin', incoming.headers.origin);
      const url = new URL(incoming.url, 'https://' + incoming.headers.host);
      const response = await onRequest({ request: new Request(url, {method:incoming.method, headers}), env });
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(500).end('Local Pages handler invocation failed');
    }
  });
  server.listen({port, host, ipv6Only:host === '::1'});
  await once(server, 'listening');
  return server.address().port;
}

const ipv4 = await listen('127.0.0.1');
const ipv6 = await listen('::1');
const dual = await listen('127.0.0.1');
await listen('::1', dual);
Object.assign(env, {
  PUBLIC_ORIGIN: 'https://page.probe.test:' + dual,
  IPV4_PROBE_ORIGIN: 'https://a.probe.test:' + ipv4,
  IPV6_PROBE_ORIGIN: 'https://aaaa.probe.test:' + ipv6,
  DUAL_STACK_PROBE_ORIGIN: 'https://dual.probe.test:' + dual,
});
process.stdout.write(JSON.stringify({ipv4, ipv6, dual}) + '\n');
