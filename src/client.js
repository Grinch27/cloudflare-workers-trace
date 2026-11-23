// 待确认：生产 Pages 域名。歧义：部分浏览器会限制探针与权限读数。
// 后续研究：配置公网探针后逐项实测。潜在优化：根据线上表现调整超时。
// 风险：完整报告原样显示敏感值。验证重点：首页文本、探针状态与一次动态首页请求。

import { browserChecks } from './browser.js';
import probeConfig from './probe-config.js';
import { runNetworkProbes } from './probes.js';
import { formatTrace, parseTrace } from './trace.js';

const text = {
  zh: {
    title: '连接检测', refresh: '重新检测', copy: '复制全文', download: '下载 TXT',
    redacted: '复制脱敏摘要', warning: '全文可能包含 Cookie、认证头和查询参数。',
    copied: '已复制全文', copiedRedacted: '已复制脱敏摘要', copyFailed: '无法使用剪贴板',
  },
  en: {
    title: 'Connection trace', refresh: 'Check again', copy: 'Copy full trace', download: 'Download TXT',
    redacted: 'Copy redacted summary', warning: 'The full trace can contain cookies, authorization headers and query parameters.',
    copied: 'Full trace copied', copiedRedacted: 'Redacted summary copied', copyFailed: 'Clipboard unavailable',
  },
};

const element = id => document.getElementById(id);
const output = element('trace-output');
const status = element('status');
const viewActions = ['refresh', 'copy-trace', 'download', 'copy-summary'];
const addressKeys = ['ipv4', 'ipv6', 'dualStack'];
const probeStates = ['complete', 'http-reached', 'not-configured', 'invalid-configuration', 'timeout',
  'unavailable', 'failed', 'http-error', 'invalid-response', 'network-error'];
let lang = navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en';
const serverTrace = output.textContent.split('\n')
  .filter(line => !line.startsWith('browserOnly.') && !line.startsWith('activeProbes.')).join('\n');
const probeInput = JSON.parse(output.dataset.probeInput);
const current = { browserOnly:{status:'pending'}, activeProbes:{status:'pending'} };

function translate() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  document.title = text[lang].title;
  for (const item of document.querySelectorAll('[data-i18n]')) item.textContent = text[lang][item.dataset.i18n];
  element('language').textContent = lang === 'zh' ? 'English' : '简体中文';
  element('language').lang = lang === 'zh' ? 'en' : 'zh-CN';
}

function render() {
  output.textContent = formatTrace(current, serverTrace);
}

async function collect() {
  render();
  const update = async (key, read) => {
    try {
      current[key] = await read();
    } catch (error) {
      current[key] = { status:'failed', error:error?.message || String(error) };
    }
    render();
  };

  await Promise.all([
    update('browserOnly', browserChecks),
    update('activeProbes', async () => {
      const result = await runNetworkProbes(probeConfig, {
        network:{visibleIp:probeInput.visibleIp ?? null},
        dnsEvidenceSuffix:probeInput.dnsEvidenceSuffix,
      });
      return { status:'complete', ...result };
    }),
  ]);
  for (const id of viewActions) element(id).disabled = false;
}

function redactedTrace() {
  const server = parseTrace(serverTrace);
  const { activeProbes } = current;
  const family = value => value === 4 || value === 6 ? value : null;
  const safeStatus = key => probeStates.includes(activeProbes[key]?.status) ? activeProbes[key].status : 'unknown';
  const protocol = server.get('server.transport.httpProtocol');
  const webrtc = activeProbes.webrtc?.verdict;
  const dns = activeProbes.dns?.evidenceStatus;
  const summary = {
    https: {
      observedFamily: family(server.get('server.network.ipVersion')),
      protocol: ['HTTP/1.0','HTTP/1.1','HTTP/2','HTTP/3'].includes(protocol) ? protocol : null,
      probes: Object.fromEntries(addressKeys.map(key => [key, {
        status: safeStatus(key), observedFamily: family(activeProbes[key]?.observedFamily),
      }])),
    },
    webrtc: {
      status: safeStatus('webrtc'),
      comparison: ['same','different','different-family'].includes(webrtc) ? webrtc : 'inconclusive',
    },
    dns: {
      httpsStatus: safeStatus('dns'),
      authorityEvidence: ['observed','not-observed','not-configured','unavailable'].includes(dns) ? dns : 'unknown',
    },
  };
  return formatTrace({ summary });
}

async function copy(value, message) {
  try {
    await navigator.clipboard.writeText(value);
    status.textContent = text[lang][message];
  } catch {
    status.textContent = text[lang].copyFailed;
  }
}

element('refresh').addEventListener('click', () => location.reload());
element('copy-trace').addEventListener('click', () => copy(output.textContent, 'copied'));
element('copy-summary').addEventListener('click', () => copy(redactedTrace(), 'copiedRedacted'));
element('download').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([output.textContent], {type:'text/plain;charset=utf-8'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'connection-trace.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
element('language').addEventListener('click', () => {
  lang = lang === 'zh' ? 'en' : 'zh';
  translate();
});

translate();
void collect();
