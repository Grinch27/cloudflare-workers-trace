// 待确认：正式站点 IPv4/IPv6 探针与 DNS 日志能力、各浏览器指纹 API 的版本覆盖。
// 后续研究：跨会话指纹一致性必须由访客自行保存并比较，本项目不创建服务端访客档案。
// 风险：原始服务端回显包括 Cookie/Authorization 与查询参数；不要与认证站点共用域名，也不要把报告随意分享。WebRTC 会向 Cloudflare STUN 发送 UDP。
// 验证重点：无弹窗自动启动、异常与超时、无 XSS/远端指纹上传、中文/英文、JSON 与结果证据一致。
'use strict';

const TEXT = {
  zh: {
    title: '你的连接向网站暴露了什么？',
    intro: '自动检查本次 HTTPS 请求、Cloudflare 边缘可见信息，以及浏览器无需弹窗即可读取的特征。每一项都标注来源和验证边界。',
    automatic: '打开页面后自动检测，无需点击启动', loading: '正在自动检测…',
    rerun: '重新运行检测', download: '导出完整 JSON', copy: '复制 JSON', memoryOnly: '仅在本次页面内存中保留客户端检测数据',
    riskTitle: '隐私暴露评估', riskHint: '只报告证据，不虚构唯一性百分比',
    serverTitle: '01 · 服务端实际收到', serverHelp: '来自初始 HTML 导航请求。请求头可能包含 Cloudflare 新增或改写的字段，不全是浏览器原始发送内容。',
    browserTitle: '02 · 浏览器本地可读取', browserHelp: '脚本自动读取并只在本页显示。可被读取不代表这些值已随 HTTP 请求自动上传。',
    probeTitle: '03 · 主动网络探针', probeHelp: 'WebRTC 自动联系 Cloudflare 公共 STUN 服务。IPv4/IPv6 和 DNS 专用探针仅在站点部署对应端点后运行。',
    rawTitle: '04 · 原始报告与方法', rawHelp: '完整回显当次请求可见的请求头（包括 Cookie、Authorization）、URL、全部可序列化的 request.cf 字段。注意：页面脚本与导出 JSON 将能读取这些原值。', rawToggle: '显示完整 JSON',
    limitsTitle: '无法凭一次访问证明', limitsBody: '真实身份、家庭住址、VPN 背后的原始 IP、准确 DNS 解析器、完整匿名性、指纹在人群中的唯一性，以及未被浏览器开放的权限数据。',
    privacy: '本站不主动设置 Cookie、不使用持久化数据库或第三方统计脚本；但访问请求可能携带 Cookie/认证信息，本站会原样反馈，页面脚本和 JSON 导出均可读取。WebRTC 使用 Cloudflare STUN；平台级日志不受本站代码控制。',
    ip: 'HTTPS 出口 IP', protocol: '到 Cloudflare 的协议', headers: '可见请求头数量', fingerprint: '可读取的指纹类别',
    request: 'HTTP 请求', network: '网络出口与 ASN', geography: 'IP 推测地理位置', transport: '连接与传输', tls: 'TLS 握手指纹材料', bots: 'Bot / JA3 / JA4（套餐依赖）', mtls: '客户端 TLS 证书（如有）', cfKeys: '完整 request.cf 元数据及嵌套值', hostKeys: '请求头识别与敏感字段标记', headersTitle: '收到的全部请求头（原值，未脱敏）',
    environment: '浏览器与设备环境', screen: '显示与交互', localization: '语言、时间与区域', capabilities: '网络 / 存储 / 权限状态',
    canvas: 'Canvas 指纹', webgl: 'WebGL / GPU 指纹', audio: '离线 Audio 指纹', fonts: '字体测量推断', uach: 'UA Client Hints',
    webrtc: 'WebRTC / STUN', ipv4: 'IPv4 专用探针', ipv6: 'IPv6 专用探针', dns: 'DNS 测试',
    noValue: '未提供 / 不可用', hidden: '[原值已隐藏]', empty: '暂无结果', checking: '检测中', notConfigured: '未配置专用探针',
    done: '已完成', failed: '失败', timeout: '超时', disabled: '不支持或被浏览器禁用', notMeasured: '未验证',
    serverData: '服务端接收', browserData: '本地读取', activeData: '额外探针',
    ipRisk: '公网出口身份', ipRiskText: '此连接向 Cloudflare 显示出口 IP，通常可关联到网络服务商和近似位置；无法直接判断是否存在 VPN。',
    headersRisk: 'HTTP 元数据', headersRiskText: '请求头和客户端提示可能暴露浏览器、语言、来源等属性。Cloudflare 可能增加或改写部分字段。',
    fingerprintRisk: '浏览器指纹面', fingerprintRiskText: 'Canvas、WebGL、Audio 和字体组合可辅助跨站关联；哈希值长度不代表在人群中的唯一性。',
    rtcRisk: 'WebRTC 额外网络出口', rtcUnknown: '未发现可比较的额外公网候选，不能据此保证 VPN 不泄漏。',
    rtcSame: '当前可比较的 STUN 公网地址与 HTTPS 出口一致；其他未检测路径仍未知。',
    rtcDifferent: 'STUN 观察到与同地址族 HTTPS 出口不同的公网地址：可能存在代理绕行或不同网络路径，需人工核实。',
    rtcDifferentFamily: '出现了未能与 HTTPS 同地址族出口比较的公网地址；不能直接判断是否泄漏。',
    dnsRisk: 'DNS 解析器可见性', dnsRiskText: '普通 Worker 无法看到用户的递归解析器。仅成功请求随机子域名不能证明 DNS 没有泄漏；需要权威 DNS 逐查询日志。',
    severe: '需关注', caution: '可观察', unknown: '未验证', info: '已观察',
    automaticNote: '访问者不需要额外操作；可能被浏览器策略拒绝的 API 将记录为不可用。',
    copied: '已复制 JSON', copyError: '剪贴板不可用',
    noScript: '无法运行客户端脚本',
  },
  en: {
    title: 'What does your connection reveal?',
    intro: 'Automatically inspect this HTTPS request, Cloudflare edge-visible metadata, and browser properties accessible without permission prompts. Evidence and limitations are separated.',
    automatic: 'Automatic inspection on page load; no Start button', loading: 'Running automatic checks…',
    rerun: 'Run checks again', download: 'Export full JSON', copy: 'Copy JSON', memoryOnly: 'Client-side measurements remain in this tab memory only',
    riskTitle: 'Exposure assessment', riskHint: 'Evidence-based; no invented uniqueness percentages',
    serverTitle: '01 · Received by server', serverHelp: 'Captured from the initial HTML navigation. Cloudflare may add or rewrite headers; not every header was originally sent by your browser.',
    browserTitle: '02 · Browser-readable properties', browserHelp: 'Automatically read and shown locally. Accessible to JavaScript does not imply that a value was sent in the original HTTP request.',
    probeTitle: '03 · Active network probes', probeHelp: 'WebRTC contacts the Cloudflare public STUN server. IPv4/IPv6 and DNS probes require the corresponding operator-configured endpoints.',
    rawTitle: '04 · Raw report & methods', rawHelp: 'Full Worker-visible headers (including Cookie and Authorization), URL, and all serializable request.cf values are echoed. Page JavaScript and exported JSON can read these sensitive values.', rawToggle: 'Show complete JSON',
    limitsTitle: 'Cannot establish from a single visit', limitsBody: 'Real-world identity, home address, underlying IP behind a VPN, exact recursive DNS resolver, complete anonymity, fingerprint population uniqueness, or data protected by browser permission boundaries.',
    privacy: 'No app-set cookies, persistent database, or third-party analytics. Any cookies/credentials sent in the request are reflected unredacted to this page and JSON export. WebRTC contacts Cloudflare STUN; platform-level logs are outside this app’s control.',
    ip: 'HTTPS exit IP', protocol: 'Protocol to Cloudflare', headers: 'Request headers visible', fingerprint: 'Browser fingerprint categories',
    request: 'HTTP request', network: 'Network identity & ASN', geography: 'IP-based approximate location', transport: 'Connection & transport', tls: 'TLS fingerprint material', bots: 'Bot / JA3 / JA4 (plan-dependent)', mtls: 'Client mTLS certificate (if present)', cfKeys: 'Complete request.cf metadata and nested values', hostKeys: 'Header provenance & secret warnings', headersTitle: 'All received headers (raw values, no redaction)',
    environment: 'Browser & device environment', screen: 'Display & interaction', localization: 'Locale and timezone', capabilities: 'Network / storage / permissions',
    canvas: 'Canvas fingerprint', webgl: 'WebGL / GPU fingerprint', audio: 'Offline Audio fingerprint', fonts: 'Font measurement inference', uach: 'UA Client Hints',
    webrtc: 'WebRTC / STUN', ipv4: 'IPv4 endpoint probe', ipv6: 'IPv6 endpoint probe', dns: 'DNS probe',
    noValue: 'Not provided / unavailable', hidden: '[raw value redacted]', empty: 'No results', checking: 'Checking', notConfigured: 'Dedicated probe not configured',
    done: 'Complete', failed: 'Failed', timeout: 'Timed out', disabled: 'Unsupported or disabled', notMeasured: 'Unverified',
    serverData: 'Received by edge', browserData: 'Browser local only', activeData: 'Additional probe',
    ipRisk: 'Public exit identity', ipRiskText: 'Cloudflare sees this connection’s exit IP, commonly associable with an ISP and approximate location. It does not establish whether a VPN is active.',
    headersRisk: 'HTTP metadata', headersRiskText: 'Headers and client hints may expose browser, language, and referrer properties. Some fields are added or rewritten by Cloudflare.',
    fingerprintRisk: 'Fingerprinting surface', fingerprintRiskText: 'Combined Canvas, WebGL, Audio, and font metrics can aid cross-site correlation. A long hash does not establish population uniqueness.',
    rtcRisk: 'WebRTC alternative exit', rtcUnknown: 'No comparable additional public candidate observed; this does not prove that a VPN cannot leak.',
    rtcSame: 'Comparable public STUN address matched the HTTPS exit; untested network paths remain unknown.',
    rtcDifferent: 'STUN exposed a public address differing from the HTTPS exit of the same IP family. Possible proxy bypass or alternate routing requires investigation.',
    rtcDifferentFamily: 'A public address of an unverified address family was observed; a leak verdict is not possible.',
    dnsRisk: 'DNS resolver visibility', dnsRiskText: 'A standard Worker cannot identify the user’s recursive DNS resolver. Random-subdomain HTTP success is not evidence of no DNS leak; authoritative DNS query logs are required.',
    severe: 'Investigate', caution: 'Observable', unknown: 'Unverified', info: 'Observed',
    automaticNote: 'No user interaction required. APIs blocked by policy or unsupported are reported as unavailable.',
    copied: 'JSON copied', copyError: 'Clipboard not available', noScript: 'Client-side JavaScript could not run',
  },
};

const el = id => document.getElementById(id);
const boot = JSON.parse(el('boot').textContent);
const report = {
  version: 2,
  generatedAt: new Date().toISOString(),
  service: 'Connection Exposure Audit',
  sources: {
    server: 'initial HTML navigation request to Cloudflare',
    browser: 'automatically computed locally, not uploaded by this app',
    active: 'additional network probes; STUN uses Cloudflare',
  },
  server: boot.server,
  browserOnly: { status: 'pending' },
  activeProbes: { status: 'pending' },
  assessment: [],
};
let lang = navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en';
let runToken = 0;
const t = key => TEXT[lang][key] || key;
const shown = val => val === null || val === undefined || val === '' ? t('noValue') : (typeof val === 'object' ? JSON.stringify(val) : String(val));

function applyTranslations() {
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
  for (const item of document.querySelectorAll('[data-i18n]')) item.textContent = t(item.dataset.i18n);
  el('language').textContent = lang === 'zh' ? 'EN' : '中文';
  render();
}
function group(root, title, data, expanded = false, isHeaders = false) {
  const details = document.createElement('details'); details.open = expanded;
  const summary = document.createElement('summary');
  summary.textContent = title + ' · ' + Object.keys(data || {}).length;
  const table = document.createElement('table'); const body = document.createElement('tbody');
  for (const [key, original] of Object.entries(data || {})) {
    const row = document.createElement('tr'); const left = document.createElement('td'); const right = document.createElement('td');
    left.textContent = key;
    if (isHeaders) {
      right.textContent = shown(original);
      if (/(?:auth|cookie|cred|csrf|jwt|key|pass|secret|session|signature|token|set-cookie)/i.test(key)) right.className = 'masked';
    } else {
      right.textContent = shown(original);
      if (original === null || original === undefined) right.className = 'null';
    }
    row.append(left, right); body.append(row);
  }
  table.append(body); details.append(summary, table); root.append(details);
}
function renderGroups(rootId, pairs) {
  const root = el(rootId); root.replaceChildren();
  for (const [title, data, open, headers] of pairs) group(root, title, data, open, headers);
}
function metric(value, label) {
  const box = document.createElement('div'); box.className = 'metric';
  const strong = document.createElement('strong'); strong.textContent = shown(value);
  const caption = document.createElement('span'); caption.textContent = label;
  box.append(strong, caption); return box;
}
function assessment(id, category, title, desc) { return { id, category, title, desc }; }
function assess() {
  const result = [
    assessment('exit', 'info', t('ipRisk'), t('ipRiskText')),
    assessment('headers', 'info', t('headersRisk'), t('headersRiskText')),
    assessment('browser', report.browserOnly.status === 'complete' ? 'warn' : 'unknown', t('fingerprintRisk'), t('fingerprintRiskText')),
  ];
  const wc = report.activeProbes.webrtc;
  let verdict = t('rtcUnknown'); let category = 'unknown';
  if (wc?.verdict === 'different') { category = 'high'; verdict = t('rtcDifferent'); }
  else if (wc?.verdict === 'same') { category = 'ok'; verdict = t('rtcSame'); }
  else if (wc?.verdict === 'different-family') verdict = t('rtcDifferentFamily');
  result.push(assessment('webrtc', category, t('rtcRisk'), verdict));
  result.push(assessment('dns', 'unknown', t('dnsRisk'), t('dnsRiskText')));
  report.assessment = result.map(x => ({...x}));
  return result;
}
function render() {
  const server = report.server;
  const metrics = el('metrics'); metrics.replaceChildren();
  const fpCount = ['canvas','webgl','audio','fonts','uach'].filter(k => report.browserOnly[k]?.status === 'complete').length;
  metrics.append(metric(server.network.visibleIp, t('ip')),
    metric(server.transport.httpProtocol, t('protocol')),
    metric(server.request.headerCount, t('headers')),
    metric(fpCount + '/5', t('fingerprint')));
  renderGroups('server', [
    [t('request'), server.request, true], [t('network'), server.network, true],
    [t('geography'), server.geography, false], [t('transport'), server.transport, false],
    [t('tls'), server.tls, false], [t('bots'), server.botManagement, false],
    [t('mtls'), server.mutualTls, false],
    [t('cfKeys'), server.cf, false],
    [t('hostKeys'), server.headerClassification, false],
    [t('headersTitle'), server.headers, false, true],
  ]);
  renderGroups('browser', [
    [t('environment'), report.browserOnly.environment || {status:t('checking')}, true],
    [t('screen'), report.browserOnly.screen || {}, false],
    [t('localization'), report.browserOnly.localization || {}, false],
    [t('capabilities'), report.browserOnly.capabilities || {}, false],
    ...['canvas','webgl','audio','fonts','uach'].map(k => [t(k), report.browserOnly[k] || {status:t('checking')}, false]),
  ]);
  renderGroups('probes', [
    [t('webrtc'), report.activeProbes.webrtc || {status:t('checking')}, true],
    [t('ipv4'), report.activeProbes.ipv4 || {status:t('checking')}, false],
    [t('ipv6'), report.activeProbes.ipv6 || {status:t('checking')}, false],
    [t('dns'), report.activeProbes.dns || {status:t('checking')}, false],
  ]);
  const risks = el('risks'); risks.replaceChildren();
  for (const x of assess()) {
    const card = document.createElement('div'); card.className = 'risk';
    const status = document.createElement('span'); status.className = 'status ' + x.category;
    status.textContent = x.category === 'high' ? t('severe') : x.category === 'unknown' ? t('unknown') : x.category === 'warn' ? t('caution') : t('info');
    const h = document.createElement('h3'); h.textContent = x.title;
    const p = document.createElement('p'); p.textContent = x.desc;
    card.append(status, h, p); risks.append(card);
  }
  el('raw').textContent = JSON.stringify(report, null, 2);
}
function errorOf(err) { return err?.name ? err.name + ': ' + (err.message || '') : String(err); }
async function sha256(bytes) {
  if (!crypto?.subtle) return 'Web Crypto unavailable';
  const buffer = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(buffer)].map(n => n.toString(16).padStart(2, '0')).join('');
}
function basicBrowser() {
  const n = navigator;
  const c = n.connection || n.mozConnection || n.webkitConnection;
  const media = match => window.matchMedia?.(match).matches ?? null;
  const time = Intl.DateTimeFormat().resolvedOptions();
  const entries = performance.getEntriesByType('navigation');
  return {
    status: 'complete',
    environment: {
      userAgent: n.userAgent, platform: n.platform, vendor: n.vendor, appVersion: n.appVersion,
      language: n.language, languages: [...(n.languages || [])], hardwareConcurrency: n.hardwareConcurrency ?? null,
      deviceMemoryGiBApprox: n.deviceMemory ?? null, maxTouchPoints: n.maxTouchPoints ?? null,
      webdriver: n.webdriver ?? null, cookieEnabled: n.cookieEnabled, pdfViewerEnabled: n.pdfViewerEnabled ?? null,
      doNotTrack: n.doNotTrack ?? null, globalPrivacyControl: n.globalPrivacyControl ?? null,
      secureContext: window.isSecureContext, crossOriginIsolated: window.crossOriginIsolated,
    },
    screen: {
      width: screen.width, height: screen.height, availableWidth: screen.availWidth, availableHeight: screen.availHeight,
      colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth, devicePixelRatio: window.devicePixelRatio,
      innerWidth: window.innerWidth, innerHeight: window.innerHeight, outerWidth: window.outerWidth, outerHeight: window.outerHeight,
      orientationType: screen.orientation?.type ?? null, orientationAngle: screen.orientation?.angle ?? null,
      darkMode: media('(prefers-color-scheme: dark)'), reducedMotion: media('(prefers-reduced-motion: reduce)'),
      forcedColors: media('(forced-colors: active)'), contrastMore: media('(prefers-contrast: more)'),
      colorGamutP3: media('(color-gamut: p3)'), colorGamutRec2020: media('(color-gamut: rec2020)'),
      anyHover: media('(any-hover: hover)'), anyFinePointer: media('(any-pointer: fine)'),
    },
    localization: {
      timezone: time.timeZone ?? null, locale: time.locale, calendar: time.calendar, numberingSystem: time.numberingSystem,
      timeZoneOffsetMinutes: new Date().getTimezoneOffset(), dateString: new Date().toString(),
    },
    capabilities: {
      onlineHint: n.onLine, connectionType: c?.type ?? null, effectiveType: c?.effectiveType ?? null,
      downlinkMbpsEstimate: c?.downlink ?? null, rttMsEstimate: c?.rtt ?? null, saveData: c?.saveData ?? null,
      documentVisibility: document.visibilityState, historyLength: history.length,
      localStorageAvailable: typeof Storage !== 'undefined', indexedDbAvailable: 'indexedDB' in window,
      serviceWorkerAvailable: 'serviceWorker' in n, webSocketAvailable: 'WebSocket' in window,
      pluginNames: Array.from(n.plugins || [], p => p.name).slice(0, 60),
      mimeTypeNames: Array.from(n.mimeTypes || [], p => p.type).slice(0, 60),
      webGpuAvailable: Boolean(n.gpu),
      performanceMemory: performance.memory ? {jsHeapSizeLimit:performance.memory.jsHeapSizeLimit,
        totalJSHeapSize:performance.memory.totalJSHeapSize,usedJSHeapSize:performance.memory.usedJSHeapSize} : null,
      webRtcAvailable: 'RTCPeerConnection' in window,
      navigationProtocol: entries[0]?.nextHopProtocol || null,
    },
  };
}
async function canvasCheck() {
  try {
    const c = document.createElement('canvas'); c.width=400; c.height=90;
    const g = c.getContext('2d', {willReadFrequently:true});
    if (!g) return {status:'unavailable'};
    g.fillStyle='#edf7f6'; g.fillRect(0,0,c.width,c.height);
    g.font='20px Arial'; g.fillStyle='#2450b5'; g.fillText('Audit: ㊣ Ω 日本語 12345',9,29);
    g.font='16px serif'; g.fillStyle='#d42a50'; g.fillText('Canvas + emoji 🌐 🧪',11,64);
    g.beginPath(); g.arc(240,40,24,0,Math.PI*2); g.fill();
    const pixels = g.getImageData(0,0,c.width,c.height);
    return {status:'complete', sha256:await sha256(pixels.data.buffer), width:c.width, height:c.height,
      purpose:'pixel hash indicates a rendering output, NOT population entropy or stable identity'};
  } catch(e) {return {status:'failed',error:errorOf(e)};}
}
function glCheck() {
  const canvas = document.createElement('canvas');
  let gl;
  try {
    gl = canvas.getContext('webgl2') || canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return {status:'unavailable'};
    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    const result = {
      status:'complete',version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
      vendor: gl.getParameter(gl.VENDOR), renderer: gl.getParameter(gl.RENDERER),
      unmaskedVendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : null,
      unmaskedRenderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null,
      maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
      maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
      maxViewportDims: Array.from(gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []),
      supportedExtensions: gl.getSupportedExtensions() || [],
    };
    return result;
  } catch(e) {return {status:'failed',error:errorOf(e)};}
  finally {try {gl?.getExtension('WEBGL_lose_context')?.loseContext();} catch{}}
}
async function audioCheck() {
  const Offline = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!Offline) return {status:'unavailable'};
  try {
    const ctx = new Offline(1, 44100, 44100);
    const osc=ctx.createOscillator(); const compressor=ctx.createDynamicsCompressor();
    osc.type='triangle'; osc.frequency.value=1000;
    compressor.threshold.value=-50; compressor.knee.value=40; compressor.ratio.value=12;
    compressor.attack.value=0; compressor.release.value=.25;
    osc.connect(compressor); compressor.connect(ctx.destination);
    osc.start(0);
    const rendered=await Promise.race([
      ctx.startRendering(), new Promise((_,reject)=>setTimeout(()=>reject(new Error('audio-timeout')),7000)),
    ]);
    const samples=rendered.getChannelData(0).slice(4000, 12000);
    const sum=samples.reduce((acc,n)=>acc+Math.abs(n),0);
    return {status:'complete', sha256:await sha256(samples.buffer), amplitudeSum:Number(sum.toFixed(6)),
      note:'Offline audio rendering; no microphone access and no sound playback'};
  } catch(e) {return {status:'failed',error:errorOf(e)};}
}
function fontsCheck() {
  const candidates = [
    'Arial','Helvetica','Times New Roman','Courier New','Verdana','Tahoma','Georgia','Trebuchet MS',
    'Impact','Comic Sans MS','Calibri','Cambria','Consolas','Segoe UI','Roboto','Noto Sans',
    'Noto Sans CJK SC','Microsoft YaHei','SimSun','PingFang SC','Heiti SC','San Francisco',
    'Ubuntu','DejaVu Sans','Liberation Sans','Menlo','Monaco','Fira Code',
  ];
  try {
    const test='mmmmmmmmmmWQ@漢字1234567890';
    const node=document.createElement('span'); node.textContent=test;
    Object.assign(node.style,{position:'absolute',visibility:'hidden',left:'-9999px',fontSize:'72px',whiteSpace:'nowrap'});
    document.body.append(node);
    const measure=(family,base)=>{
      node.style.fontFamily='"'+family.replace(/"/g,'')+'",'+base;
      return [node.getBoundingClientRect().width,node.getBoundingClientRect().height].join('x');
    };
    const generic=['monospace','sans-serif','serif'];
    const baseline=generic.map(x=>{node.style.fontFamily=x;return [node.getBoundingClientRect().width,node.getBoundingClientRect().height].join('x');});
    const likely=[];
    for (const f of candidates) if (generic.some((base,i)=>measure(f,base)!==baseline[i])) likely.push(f);
    node.remove();
    return {status:'complete', tested:candidates.length, likelyPresent:likely,
      accuracy:'heuristic, false positives/negatives possible; not an enumeration of installed fonts'};
  } catch(e) {return {status:'failed',error:errorOf(e)};}
}
async function uachCheck() {
  const data=navigator.userAgentData;
  if (!data) return {status:'unavailable',reason:'API unavailable (browser support varies)'};
  const result={status:'complete',brands:data.brands,mobile:data.mobile,platform:data.platform};
  try {
    result.highEntropy=await data.getHighEntropyValues([
      'architecture','bitness','formFactors','fullVersionList','model','platformVersion','uaFullVersion','wow64',
    ]);
  } catch(e){result.highEntropyError=errorOf(e);}
  return result;
}
async function permissionsCheck() {
  const results={};
  if (!navigator.permissions?.query) return {supported:false};
  for (const name of ['geolocation','camera','microphone','notifications','local-fonts','clipboard-read']) {
    try {results[name]=(await navigator.permissions.query({name})).state;}
    catch{results[name]='not-supported';}
  }
  return results;
}
async function nonPromptDeviceInfo() {
  const info={};
  if (navigator.mediaDevices?.enumerateDevices) {
    try {const devices=await navigator.mediaDevices.enumerateDevices();
      info.mediaDeviceKinds=devices.reduce((obj,d)=>{obj[d.kind]=(obj[d.kind]||0)+1;return obj;},{});
      info.mediaDeviceLabelsVisible=devices.some(d=>Boolean(d.label));
    }catch(e){info.mediaDeviceError=errorOf(e);}
  }
  if (navigator.storage?.estimate) {
    try {const storage=await navigator.storage.estimate();
      info.storageEstimate={quota:storage.quota??null,usage:storage.usage??null};
    }catch(e){info.storageError=errorOf(e);}
  }
  if (navigator.getBattery) {
    try {const battery=await navigator.getBattery();
      info.battery={charging:battery.charging,level:battery.level,chargingTime:battery.chargingTime,dischargingTime:battery.dischargingTime};
    }catch(e){info.batteryError=errorOf(e);}
  }
  return info;
}
async function browserChecks() {
  const result=basicBrowser();
  const all=await Promise.allSettled([canvasCheck(),Promise.resolve().then(glCheck),audioCheck(),Promise.resolve().then(fontsCheck),uachCheck(),permissionsCheck(),nonPromptDeviceInfo()]);
  const keys=['canvas','webgl','audio','fonts','uach'];
  all.forEach((r,i)=>{
    const data=r.status==='fulfilled'?r.value:{status:'failed',error:errorOf(r.reason)};
    if (i<keys.length) result[keys[i]]=data;
    else if(i===keys.length) result.capabilities.permissionStates=data;
    else Object.assign(result.capabilities,data);
  });
  return result;
}
function ipv4Parts(address) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) return null;
  const n=address.split('.').map(Number); return n.every(x=>x>=0&&x<=255)?n:null;
}
function classifyAddress(addr) {
  if (typeof addr !== 'string') return {family:null,scope:'unknown'};
  const value=addr.toLowerCase();
  if (value.endsWith('.local')) return {family:null,scope:'mdns-masked'};
  const v4=ipv4Parts(value);
  if (v4) {
    const [a,b,c]=v4;
    if (a===10 || a===127 || a===0 || (a===172&&b>=16&&b<=31) || (a===192&&b===168) || (a===169&&b===254)) return {family:4,scope:'private-or-local'};
    if ((a===100&&b>=64&&b<=127) || a>=224 || (a===192&&b===0&&c===2) || (a===198&&b===51&&c===100) || (a===203&&b===0&&c===113)) return {family:4,scope:'special-use'};
    return {family:4,scope:'public'};
  }
  if (/^[0-9a-f:.%]+$/i.test(value) && value.includes(':')) {
    if (value==='::1'||value==='::'||value.startsWith('fe80:')||/^f[cd][0-9a-f]/.test(value)) return {family:6,scope:'private-or-local'};
    if (value.startsWith('2001:db8:') || value.startsWith('ff')) return {family:6,scope:'special-use'};
    return {family:6,scope:'possibly-public'};
  }
  return {family:null,scope:'unknown'};
}
function parseCandidate(raw) {
  const parts=raw.trim().split(/\s+/);
  const typ=parts.indexOf('typ');
  if (typ<0 || !parts[4]) return {type:'unknown',address:null,scope:'unknown'};
  const address=parts[4];
  return {type:parts[typ+1] || null,transport:parts[2] || null,address,
    port: parts[5] || null,...classifyAddress(address)};
}
function webrtcVerdict(items, server, familyExtras=[]) {
  const serverIps=[server.network.visibleIp,...familyExtras.filter(Boolean)];
  const comparedIps=new Set(serverIps.map(ip => String(ip).toLowerCase()));
  let same=false, different=false, differentFamily=false;
  for (const item of items) {
    if (!['srflx','host'].includes(item.type) || !['public','possibly-public'].includes(item.scope)) continue;
    if (comparedIps.has(item.address.toLowerCase())) {same=true;continue;}
    if (serverIps.some(ip=>classifyAddress(ip).family===item.family)) different=true;
    else differentFamily=true;
  }
  return different?'different':differentFamily?'different-family':same?'same':'inconclusive';
}
async function webrtcCheck() {
  if (!window.RTCPeerConnection) return {status:'unavailable',verdict:'inconclusive',server:'stun.cloudflare.com:3478'};
  return new Promise(resolve=>{
    let pc,completed=false;
    const unique=new Map();
    const finish=(state)=>{
      if(completed)return; completed=true;clearTimeout(timer);
      try {pc?.close();}catch{}
      const candidates=[...unique.values()];
      resolve({status:state,stunServer:'stun.cloudflare.com:3478',candidateCount:candidates.length,candidates,
        verdict:webrtcVerdict(candidates,report.server),
        note:'ICE candidate addresses are displayed locally and are not sent to this Worker. Different IPs do not alone prove a VPN leak.'});
    };
    const timer=setTimeout(()=>finish('timeout'),6500);
    try {
      pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}],iceTransportPolicy:'all'});
      pc.onicecandidate=event=>{
        if (!event.candidate) {finish('complete');return;}
        const parsed=parseCandidate(event.candidate.candidate||'');
        if(parsed.address) unique.set(parsed.type+'|'+parsed.address+'|'+parsed.port,parsed);
      };
      pc.createDataChannel('audit-datachannel');
      pc.createOffer().then(desc=>pc.setLocalDescription(desc)).catch(e=>{
        finish('failed: '+errorOf(e));
      });
    } catch(e) {finish('failed: '+errorOf(e));}
  });
}
async function fetchJson(url) {
  const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),6500);
  try {
    const res=await fetch(url,{mode:'cors',method:'GET',cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer',signal:controller.signal});
    if (!res.ok) throw new Error('HTTP '+res.status);
    return await res.json();
  } finally {clearTimeout(timer);}
}
async function addressCheck(origin, expected) {
  if (!origin) return {status:'not-configured',expectedFamily:expected,note:'Requires separately configured and independently verified endpoint; Cloudflare hostnames are normally dual-stack.'};
  try {
    const res=await fetchJson(origin+'/_probe/address');
    if(res.type!=='address-family' || ![4,6].includes(res.ipVersion)) throw new Error('invalid response');
    return {status:'complete',expectedFamily:expected,observedFamily:res.ipVersion,visibleIp:res.visibleIp,
      matchesExpected:res.ipVersion===expected,colo:res.colo,
      warning:'The probe reports observed protocol, not proof the hostname is single-stack.'};
  } catch(e){return {status:'failed',expectedFamily:expected,error:errorOf(e)};}
}
async function dnsCheck(suffix) {
  if (!suffix) return {status:'not-configured',resolver:'unknown',note:'Requires wildcard DNS, working TLS, Worker route, and authoritative DNS query-level logs for resolver identity.'};
  const token=crypto.randomUUID ? crypto.randomUUID().replace(/-/g,'') : Math.random().toString(36).slice(2);
  const host=token+'.'+suffix;
  try {
    const res=await fetchJson('https://'+host+'/_probe/dns');
    if(res.type!=='dns-http-reachability'||res.hostname!==host) throw new Error('invalid probe response');
    return {status:'http-reached',probeHostname:host,httpObservedIp:res.visibleIp,
      resolver:'unverified',dnsLeakVerdict:'unverified',
      evidence:'The browser resolved and connected to a nonce hostname, but DNS recursive resolver addresses were NOT collected.'};
  }catch(e){return {status:'failed',probeHostname:host,error:errorOf(e),resolver:'unverified',dnsLeakVerdict:'unverified'};}
}
async function runAll() {
  const token=++runToken;
  report.browserOnly={status:'pending'};
  report.activeProbes={status:'pending',webrtc:{status:'pending'},ipv4:{status:'pending'},ipv6:{status:'pending'},dns:{status:'pending'}};
  render();
  const jobs=[
    browserChecks().then(data=>{if(token===runToken){report.browserOnly=data;render();}}),
    webrtcCheck().then(data=>{if(token===runToken){report.activeProbes.webrtc=data;render();}}),
    addressCheck(boot.config.ipv4ProbeOrigin,4).then(data=>{if(token===runToken){report.activeProbes.ipv4=data;render();}}),
    addressCheck(boot.config.ipv6ProbeOrigin,6).then(data=>{if(token===runToken){report.activeProbes.ipv6=data;render();}}),
    dnsCheck(boot.config.dnsProbeSuffix).then(data=>{if(token===runToken){report.activeProbes.dns=data;render();}}),
  ];
  await Promise.allSettled(jobs);
  if(token!==runToken)return;
  const matched=[];
  for(const p of [report.activeProbes.ipv4,report.activeProbes.ipv6])if(p?.status==='complete')matched.push(p.visibleIp);
  if(report.activeProbes.webrtc?.candidates){
    report.activeProbes.webrtc.verdict=webrtcVerdict(report.activeProbes.webrtc.candidates,report.server,matched);
  }
  report.activeProbes.status='complete';render();
}
function exportJson() {
  return JSON.stringify({...report,exportedAt:new Date().toISOString()},null,2);
}
el('language').addEventListener('click',()=>{lang=lang==='zh'?'en':'zh';applyTranslations();});
el('rerun').addEventListener('click',()=>{void runAll();});
el('download').addEventListener('click',()=>{
  const blob=new Blob([exportJson()],{type:'application/json'});
  const href=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=href;a.download='connection-exposure-'+new Date().toISOString().replace(/[:.]/g,'-')+'.json';
  document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(href),1000);
});
el('copy').addEventListener('click',async e=>{
  try {await navigator.clipboard.writeText(exportJson()); e.currentTarget.textContent=t('copied');}
  catch{e.currentTarget.textContent=t('copyError');}
});
applyTranslations();
void runAll();
