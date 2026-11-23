// 待确认：独立探针域名和权威 DNS 后端。歧义：连接失败有多种原因。
// 后续研究：公网 CORS、双栈和 DNSSEC 实测。潜在优化：按权威查询延迟调整轮询。
// 风险：启动探针会向配置的服务发起连接。验证重点：同地址族比较、限时与凭据隔离。
const errorOf = error => error?.name || 'Error';

function ipv4Parts(address) {
  if (!/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(address)) return null;
  const parts = address.split('.').map(Number);
  return parts.every(part => part <= 255) ? parts : null;
}
function ipv4Details(parts) {
  const [first, second, third] = parts;
  const local = first === 0 || first === 10 || first === 127 || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
  const special = first >= 224 || (first === 100 && second >= 64 && second <= 127)
    || (first === 192 && second === 0 && (third === 0 || third === 2))
    || (first === 198 && (second === 18 || second === 19 || (second === 51 && third === 100)))
    || (first === 203 && second === 0 && third === 113);
  return { family: 4, normalizedAddress: parts.join('.'), scope: local ? 'private-or-local' : special ? 'special-use' : 'public' };
}
function addressDetails(address) {
  const unknown = { family: null, normalizedAddress: null, scope: 'unknown' };
  if (typeof address !== 'string') return unknown;
  const text = address.toLowerCase();
  if (text.endsWith('.local') || text.endsWith('.local.')) return { ...unknown, scope: 'mdns-masked' };
  const ipv4 = ipv4Parts(text);
  if (ipv4) return ipv4Details(ipv4);
  if (!text.includes(':') || !/^[a-f0-9:.]+$/.test(text)) return unknown;
  let canonical;
  try {
    canonical = new URL('https://[' + text + ']/').hostname.slice(1, -1);
  } catch { return unknown; }
  const mapped = canonical.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
  if (mapped) {
    const words = mapped.slice(1).map(word => Number.parseInt(word, 16));
    return ipv4Details(words.flatMap(word => [word >> 8, word & 255]));
  }
  const prefix = Number.parseInt(canonical.split(':')[0] || '0', 16);
  const local = canonical === '::' || canonical === '::1'
    || (prefix & 0xffc0) === 0xfe80 || (prefix & 0xfe00) === 0xfc00;
  const special = (prefix & 0xe000) !== 0x2000 || canonical.startsWith('2001:db8:') || canonical === '2001:db8::';
  return { family: 6, normalizedAddress: canonical, scope: local ? 'private-or-local' : special ? 'special-use' : 'possibly-public' };
}
export function parseCandidate(candidate) {
  const parts = (candidate.candidate || '').trim().split(/\s+/);
  const typeIndex = parts.indexOf('typ');
  const address = candidate.address || (typeIndex >= 0 ? parts[4] : null);
  return {
    type: candidate.type || (typeIndex >= 0 ? parts[typeIndex + 1] : null),
    address,
    transport: candidate.protocol ?? parts[2] ?? null,
    port: candidate.port ?? (parts[5] ? Number(parts[5]) : null),
    ...addressDetails(address),
  };
}
function publiclyComparable(scope) {
  return scope === 'public' || scope === 'possibly-public';
}
export function compareWebRtc(candidates, exits) {
  const httpsBaselines = exits.flatMap(({ source, address }) => {
    const details = addressDetails(address);
    return publiclyComparable(details.scope) ? [{ source, address: details.normalizedAddress, family: details.family }] : [];
  });
  const compared = candidates.map(candidate => {
    const comparable = ['srflx', 'host'].includes(candidate.type) && publiclyComparable(candidate.scope);
    const sameFamily = httpsBaselines.filter(item => item.family === candidate.family);
    let comparison = 'not-comparable';
    if (comparable) {
      if (!sameFamily.length) comparison = 'different-family';
      else comparison = sameFamily.some(item => item.address === candidate.normalizedAddress) ? 'same' : 'different';
    }
    return { ...candidate, comparison };
  });
  const verdict = ['different', 'different-family', 'same'].find(value => compared.some(item => item.comparison === value)) || 'inconclusive';
  return { verdict, candidates: compared, httpsBaselines };
}
async function webrtcCheck() {
  if (typeof RTCPeerConnection === 'undefined') {
    return { status: 'unavailable', candidateCount: 0, candidates: [], stunServer: 'stun.cloudflare.com:3478' };
  }
  return new Promise(resolve=>{
    let pc,completed=false;
    const unique=new Map();
    const finish=(status,error)=>{
      if(completed)return; completed=true;clearTimeout(timer);
      try {pc?.close();}catch{}
      const candidates=[...unique.values()];
      resolve({status,error,stunServer:'stun.cloudflare.com:3478',candidateCount:candidates.length,candidates,
        note:'ICE candidates stay in this tab. Compare same-family exits using the HTTPS baselines in this report.'});
    };
    const timer=setTimeout(()=>finish('timeout'),6500);
    try {
      pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}],iceTransportPolicy:'all'});
      pc.onicecandidate=event=>{
        if (!event.candidate) {finish('complete');return;}
        const parsed=parseCandidate(event.candidate);
        if(parsed.address) unique.set(parsed.type+'|'+(parsed.normalizedAddress || parsed.address)+'|'+parsed.port,parsed);
      };
      pc.createDataChannel('audit-datachannel');
      pc.createOffer().then(desc=>pc.setLocalDescription(desc)).catch(e=>{
        finish('failed',errorOf(e));
      });
    } catch(e) {finish('failed',errorOf(e));}
  });
}
async function fetchProbe(url, timeout = 6500) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      mode: 'cors', method: 'GET', cache: 'no-store', credentials: 'omit',
      referrerPolicy: 'no-referrer', redirect: 'error', signal: controller.signal,
    });
    if (!response.ok) return { status: 'http-error', httpStatus: response.status };
    return { status: 'complete', data: await response.json() };
  } catch (error) {
    if (controller.signal.aborted) return { status: 'timeout' };
    return { status: error instanceof SyntaxError ? 'invalid-response' : 'network-error' };
  } finally { clearTimeout(timer); }
}
async function addressCheck(probe, hostnames, page) {
  const { origin, expectedFamily } = probe;
  const expected = { expectedFamily };
  if (!origin) return { ...expected, status: 'not-configured' };
  const hostname = new URL(origin).hostname;
  const dnsName = hostname.replace(/\.$/, '');
  if (dnsName === page.hostname.replace(/\.$/, '') || hostnames.filter(item => item === dnsName).length > 1
      || hostname.startsWith('[') || ipv4Parts(dnsName)) {
    return { ...expected, status: 'invalid-configuration', hostname };
  }
  const started = performance.now();
  const { status, httpStatus, data } = await fetchProbe(origin + '/_probe/address');
  const measured = { ...expected, hostname, durationMs: Math.round(performance.now() - started) };
  if (status !== 'complete') return { ...measured, status, httpStatus };
  const address = addressDetails(data?.visibleIp);
  if (data?.type !== 'address-family' || data.hostname !== hostname || !address.family
      || ![address.family, data.visibleIp.includes(':') ? 6 : 4].includes(data.ipVersion)) {
    return { ...measured, status: 'invalid-response' };
  }
  return {
    ...measured, status: 'complete', observedFamily: address.family, reportedFamily: data.ipVersion,
    visibleIp: data.visibleIp, matchesExpected: expectedFamily === null ? null : address.family === expectedFamily,
    colo: data.colo, asn: data.asn, protocol: data.protocol,
  };
}
async function dnsQueryEvidence(nonce, page, enabled) {
  if (!enabled) return { evidenceStatus: 'not-configured' };
  const url = page.origin + '/_probe/dns-evidence?nonce=' + nonce;
  for (const delay of [0, 250, 750]) {
    if (delay) await new Promise(resolve => setTimeout(resolve, delay));
    const { status, data } = await fetchProbe(url, 1800);
    if (status !== 'complete' || data?.type !== 'dns-authority-observation' || !Array.isArray(data.observations)) {
      return { evidenceStatus: 'unavailable' };
    }
    if (data.status === 'observed' && data.observations.length) {
      return { evidenceStatus: 'observed', observations: data.observations };
    }
    if (data.status !== 'not-observed') return { evidenceStatus: 'unavailable' };
  }
  return { evidenceStatus: 'not-observed' };
}
async function dnsCheck(suffix, page, evidenceSuffix) {
  if (!suffix) return { status: 'not-configured', evidenceStatus: 'not-configured', resolver: 'unknown' };
  if (!globalThis.crypto?.getRandomValues) return { status: 'unavailable', resolver: 'unverified' };
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const hostname = nonce + '.' + suffix;
  const { status, httpStatus, data } = await fetchProbe('https://' + hostname + '/_probe/dns');
  const valid = data?.type === 'dns-http-reachability' && data.hostname === hostname;
  const evidence = await dnsQueryEvidence(nonce, page, suffix === evidenceSuffix);
  return {
    status: valid ? 'http-reached' : status === 'complete' ? 'invalid-response' : status,
    httpStatus, probeHostname: hostname, httpObservedIp: valid ? data.visibleIp : null,
    ...evidence, resolver: evidence.evidenceStatus === 'observed' ? 'authority-source-observed' : 'unverified',
    dnsLeakVerdict: 'unverified',
  };
}

export async function runNetworkProbes(config, { network, dnsEvidenceSuffix }, page = location) {
  const definitions = [
    ['ipv4', 4, config.ipv4ProbeOrigin],
    ['ipv6', 6, config.ipv6ProbeOrigin],
    ['dualStack', null, config.dualStackProbeOrigin],
  ];
  const hostnames = definitions.flatMap(([, , origin]) => origin ? [new URL(origin).hostname.replace(/\.$/, '')] : []);
  const [addressResults, webrtc, dns] = await Promise.all([
    Promise.all(definitions.map(async ([key, expectedFamily, origin]) => [
      key, await addressCheck({ origin, expectedFamily }, hostnames, page),
    ])),
    webrtcCheck(),
    dnsCheck(config.dnsProbeSuffix, page, dnsEvidenceSuffix),
  ]);
  const baselines = [{ source: 'server', address: network.visibleIp }];
  for (const [source, result] of addressResults) {
    if (result.status === 'complete') baselines.push({ source, address: result.visibleIp });
  }
  return { ...Object.fromEntries(addressResults), webrtc: { ...webrtc, ...compareWebRtc(webrtc.candidates, baselines) }, dns };
}
