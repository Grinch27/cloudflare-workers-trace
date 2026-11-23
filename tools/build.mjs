// 待确认：Pages 项目及探针公开配置。歧义：构建变量与 Functions 运行时绑定独立。
// 后续研究：公网单栈和 DNS 关联验证。潜在优化：根据产物大小评估进一步优化。
// 风险：只把经过验证的公开探针地址写进静态资源。
// 验证重点：可重复构建、精确动态路由、静态 CSP 与未配置的默认行为。
import { copyFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DYNAMIC_ROUTES } from '../src/edge.js';
import { dnsSuffix, probeOrigins } from '../src/probe-config.mjs';

const project = path.dirname(fileURLToPath(new URL('../wrangler.jsonc', import.meta.url)));
const output = path.join(project, 'dist');
if (existsSync(path.join(output, '_worker.js'))) {
  throw new Error('dist/_worker.js would override Pages Functions. Build into a clean dist directory.');
}
mkdirSync(path.join(output, 'assets'), { recursive: true });

const entries = [
  ['page.html', 'index.html'],
  ['404.html', '404.html'],
  ['site.css', 'assets/site.css'],
  ['client.js', 'assets/client.js'],
  ['trace.js', 'assets/trace.js'],
  ['probes.js', 'assets/probes.js'],
  ['browser.js', 'assets/browser.js'],
];
for (const [source, target] of entries) {
  copyFileSync(path.join(project, 'src', source), path.join(output, target));
}

const origins = probeOrigins(process.env);
const suffix = dnsSuffix(process.env.DNS_PROBE_SUFFIX);
const connectSources = new Set(["'self'", ...Object.values(origins).filter(Boolean)]);
if (suffix) connectSources.add('https://*.' + suffix);
const csp = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
  'connect-src ' + [...connectSources].join(' '),
  "base-uri 'none'", "object-src 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join('; ');

writeFileSync(path.join(output, '_headers'), [
  '/*',
  '  Content-Security-Policy: ' + csp,
  '  X-Content-Type-Options: nosniff',
  '  X-Frame-Options: DENY',
  '  Referrer-Policy: no-referrer',
  '  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), bluetooth=(), serial=(), hid=()',
  '  Cross-Origin-Opener-Policy: same-origin',
  '',
].join('\n'));
writeFileSync(path.join(output, '_routes.json'), JSON.stringify({ version: 1, include: DYNAMIC_ROUTES, exclude: [] }, null, 2) + '\n');
writeFileSync(path.join(output, 'assets', 'probe-config.js'),
  'export default ' + JSON.stringify({ ...origins, dnsProbeSuffix: suffix }) + ';\n');
console.log('Built Pages static assets in dist/ with ' + DYNAMIC_ROUTES.length + ' dynamic routes.');
