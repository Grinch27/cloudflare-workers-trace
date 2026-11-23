// 待确认：Pages 生产域名与公网 CORS。歧义：单测模拟 request.cf 和浏览器 DOM。
// 后续研究：浏览器真实单栈、DNSSEC。潜在优化：对照线上调用计量。
// 风险：夹具只使用合成凭据。验证重点：路由精确、无缓存、文本可解析、完整回显与脱敏。
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { onRequest as report } from '../functions/api/report.js';
import { onRequest as probe } from '../functions/_probe/[[path]].js';
import { onRequest as homepage } from '../functions/index.js';
import { compareWebRtc, parseCandidate, runNetworkProbes } from '../src/probes.js';
import { dnsSuffix, httpsOrigin } from '../src/probe-config.mjs';
import { formatTrace, parseTrace } from '../src/trace.js';

const read = file => readFileSync(new URL('../dist/' + file, import.meta.url), 'utf8');

function dispatch(request, env) {
  const path = new URL(request.url).pathname;
  const handler = path === '/' ? homepage : path === '/api/report' ? report : probe;
  return handler({ request, env });
}

function req(url='https://audit.example/api/report?token=SECRET&x=%3C%2Fscript%3E') {
  const r=new Request(url,{headers:{
    'cf-connecting-ip':'2001:db8::1234',authorization:'Bearer VERY_SECRET',
    cookie:'session=HIDDEN123; login=HIDDEN456',
    referer:'https://example.org/private?code=REF_SECRET',
    'x-api-key':'API_SECRET', 'x-weird':'UNKNOWN_SECRET', 'accept-language':'zh-CN',
  }});
  Object.defineProperty(r,'cf',{value:{
    asn:64512,asOrganization:'Test ASN',colo:'DFW',country:'US',tlsVersion:'TLSv1.3',
    httpProtocol:'HTTP/3',clientQuicRtt:28,
    hostMetadata:{internalSecret:'NOT_FOR_VISITORS'},
    tlsClientAuth:{certPresented:'1',certIssuerDN:'ExampleIssuer'},
    botManagement:{ja4:'faked-ja4',score:90,jsDetection:{passed:false}},
    novelField2026:{deep:{flag:false,value:0,unicode:'测试'}},
  }});
  return r;
}
test('the complete API report preserves request and Cloudflare fields', async () => {
  const response = await dispatch(req());
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /application\/json/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  const data = await response.json();
  assert.equal(data.schemaVersion,3);
  assert.equal(data.request.url,'https://audit.example/api/report?token=SECRET&x=%3C%2Fscript%3E');
  assert.deepEqual(data.request.queryEntries,[['token','SECRET'],['x','</script>']]);
  assert.equal(data.network.visibleIp,'2001:db8::1234');
  assert.equal(data.network.ipVersion,6);
  assert.equal(data.transport.clientQuicRtt,28);
  assert.equal(data.request.cookieCount,2);
  assert.equal(data.headers.authorization,'Bearer VERY_SECRET');
  assert.equal(data.headers.cookie,'session=HIDDEN123; login=HIDDEN456');
  assert.equal(data.headers['x-api-key'],'API_SECRET');
  assert.equal(data.headers['x-weird'],'UNKNOWN_SECRET');
  assert.equal(data.headers['accept-language'],'zh-CN');
  assert.equal(data.headerClassification.authorization.sensitive,true);
  assert.equal(data.mutualTls.certPresented,'1');
  assert.equal(data.cf.hostMetadata.internalSecret,'NOT_FOR_VISITORS');
  assert.equal(data.cf.novelField2026.deep.flag,false);
  assert.equal(data.cf.novelField2026.deep.value,0);
  assert.equal(data.cf.botManagement.jsDetection.passed,false);
  assert.equal(data.cf.verifiedBotCategory,undefined);
});
test('JSON API is no-cache, no CORS and reports its own incoming request',async()=>{
  const res=await dispatch(new Request('https://audit.example/api/report'));
  assert.equal(res.headers.get('access-control-allow-origin'),null);
  assert.match(res.headers.get('content-type'),/application\/json/);
  assert.match(res.headers.get('cache-control'),/no-store/);
  assert.equal(res.headers.get('cdn-cache-control'),'no-store');
  const data=await res.json();
  assert.equal(data.network.visibleIp,null);
  assert.equal(data.request.path,'/api/report');
  assert.equal(data.limits.dnsResolver,'not observable from standard Worker HTTP requests');
});
test('no requested sensitive cookie is sent to optional probe',async()=>{
  const res=await dispatch(new Request('https://ip4.example/_probe/address',{headers:{authorization:'Bearer x',cookie:'id=abc'}}));
  const text=await res.text();
  assert.ok(!text.includes('Bearer x'));
  assert.ok(!text.includes('id=abc'));
});
test('probe reports actual IP family, never fabricates expected family or DNS resolver',async()=>{
  const a=await dispatch(req('https://ip4.example/_probe/address'));
  assert.equal(a.status,200);
  const result=await a.json();
  assert.equal(result.ipVersion,6);
  assert.equal(result.type,'address-family');
  assert.match(result.warning,/not force IPv4\/IPv6/);
  const d=await (await dispatch(req('https://nonce.dns.example/_probe/dns'))).json();
  assert.equal(d.type,'dns-http-reachability');
  assert.match(d.warning,/cannot identify/);
});
test('probe CORS restricts to configured public site origin',async()=>{
  const env={PUBLIC_ORIGIN:'https://audit.example'};
  const allowed=new Request('https://ip4.example/_probe/address',{headers:{origin:'https://audit.example'}});
  const ok=await dispatch(allowed,env);
  assert.equal(ok.headers.get('access-control-allow-origin'),'https://audit.example');
  assert.equal(ok.headers.get('vary'),'Origin');
  const wrong=new Request('https://ip4.example/_probe/address',{headers:{origin:'https://attacker.example'}});
  const no=await dispatch(wrong,env);
  assert.equal(no.headers.get('access-control-allow-origin'),null);
  const preflight=await dispatch(new Request('https://ip4.example/_probe/address',{method:'OPTIONS',headers:{origin:'https://audit.example'}}),env);
  assert.equal(preflight.status,204);
  assert.equal(preflight.headers.get('access-control-allow-origin'),'https://audit.example');
});
test('DNS evidence is same-origin and returns only fresh records for the exact nonce hostname', async () => {
  const now = Date.now();
  const nonce = 'a'.repeat(32);
  const name = nonce + '.dns.example';
  const fresh = {name, queryType:'A', sourceIp:'2001:db8::20', observedAt:now};
  const request = req('https://audit.example/_probe/dns-evidence?nonce=' + nonce);
  let calls = 0;
  const env = {
    DNS_PROBE_SUFFIX:'dns.example',
    DNS_EVIDENCE:{
      fetch(lookup) {
        calls++;
        assert.equal(lookup.url, 'https://dns-evidence.invalid/observations?name=' + name);
        assert.equal(lookup.method, 'GET');
        assert.equal(lookup.headers.get('cookie'), null);
        assert.equal(lookup.headers.get('authorization'), null);
        return Response.json({observations:[
          {...fresh, name:'b'.repeat(32) + '.dns.example'},
          {...fresh, observedAt:now - 121_000},
          {...fresh, observedAt:now + 6000},
          {...fresh, queryType:'TXT'},
          {...fresh, sourceIp:'not-an-address.example'},
          {...fresh, sourceIp:'256.168.1.1'},
          {...fresh, queryType:'AAAA', ecs:'192.0.2.0/24'},
          {...fresh, observedAt:now - 500},
          {...fresh, ecs:'192.0.2.0/99'},
        ]});
      },
    },
  };
  const response = await dispatch(request, env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(response.headers.get('cross-origin-resource-policy'), 'same-origin');
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.deepEqual(await response.json(), {
    type:'dns-authority-observation', status:'observed', observations:[
      {queryType:'AAAA', sourceIp:'2001:db8::20', ecs:'192.0.2.0/24', observedAt:now},
      {queryType:'A', sourceIp:'2001:db8::20', ecs:null, observedAt:now},
    ],
  });
  const crossSite = await dispatch(new Request(request.url, {headers:{origin:'https://other.example'}}), env);
  assert.equal(crossSite.status, 403);
  assert.equal((await dispatch(new Request(request.url + '&name=other.example'), env)).status, 400);
  assert.equal((await dispatch(new Request(request.url.replace(nonce, 'short')), env)).status, 400);
  assert.equal(calls, 1);
});

test('DNS lookup distinguishes unavailable, not configured and no matching observation', async () => {
  const request = new Request('https://audit.example/_probe/dns-evidence?nonce=' + '0'.repeat(32));
  const env = {DNS_PROBE_SUFFIX:'dns.example', DNS_EVIDENCE:{fetch:() => Response.json({observations:[]})}};
  let response = await dispatch(request);
  assert.equal(response.status, 503);
  assert.equal((await response.json()).status, 'not-configured');
  response = await dispatch(request, env);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, 'not-observed');
  env.DNS_EVIDENCE.fetch = () => new Response('x'.repeat(9000));
  response = await dispatch(request, env);
  assert.equal(response.status, 502);
  assert.equal((await response.json()).status, 'unavailable');
});

test('the compact API serves only necessary connection information', async () => {
  const response = await dispatch(req('https://audit.example/api/report?view=summary&token=SECRET'));
  const body = await response.text();
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.deepEqual(JSON.parse(body), {
    network:{visibleIp:'2001:db8::1234', ipVersion:6, asn:64512, asOrganization:'Test ASN', colo:'DFW', country:'US'},
    transport:{httpProtocol:'HTTP/3', tlsVersion:'TLSv1.3'},
    dnsEvidenceSuffix:null,
  });
  assert.doesNotMatch(body, /SECRET|HIDDEN123|private|127\.0\.0\.1|cookie|user-agent/);
});

test('the static artifact has a closed list of dynamic routes and no data embedded in the page', () => {
  assert.deepEqual(JSON.parse(read('_routes.json')), {
    version:1, include:['/','/api/report','/_probe/address','/_probe/dns','/_probe/dns-evidence'], exclude:[],
  });
  assert.equal(existsSync(new URL('../dist/_worker.js', import.meta.url)), false);
  const page = read('index.html');
  assert.doesNotMatch(page, /id="boot"|request\.cf|<!--BOOT_DATA-->/);
  assert.equal([...page.matchAll(/<pre\b/g)].length, 1);
  assert.doesNotMatch(page, /<(details|table)\b/);
  assert.doesNotMatch(page, /href="\/trace"/);
  assert.deepEqual([...page.matchAll(/<script [^>]*src="([^"]+)"/g)].map(match => match[1]), ['/assets/client.js']);
  assert.match(read('_headers'), /connect-src 'self'[^;]*;/);
  assert.doesNotMatch(read('assets/client.js'), /RTCPeerConnection|getHighEntropyValues|OfflineAudioContext/);
  assert.match(read('assets/probes.js'), /stun\.cloudflare\.com:3478/);
  assert.match(read('assets/browser.js'), /getHighEntropyValues/);
});

test('probe configuration rejects credentials, paths and CSP delimiters', () => {
  assert.equal(httpsOrigin('https://ip4.example:8443/'), 'https://ip4.example:8443');
  for (const value of ['https://bad.example;', 'https://bad.example/extra', 'https://a:b@bad.example', 'http://bad.example']) {
    assert.equal(httpsOrigin(value), null);
  }
  assert.equal(dnsSuffix(' DNS.Example.COM '), 'dns.example.com');
  assert.equal(dnsSuffix('bad.com; script-src *'), null);
  assert.equal(dnsSuffix('-bad.example.com'), null);
});

test('dynamic routes retain HEAD, method rules and the complete raw format', async () => {
  const url = 'https://audit.example/api/report';
  const head = await dispatch(new Request(url, {method:'HEAD'}));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await dispatch(new Request(url, {method:'POST'}))).status, 405);
  const original = "literal $& $$ $' </script>";
  const response = await dispatch(new Request(url, {headers:{'x-probe-value':original}}));
  assert.equal((await response.json()).headers['x-probe-value'], original);
});

test('WebRTC canonicalizes addresses and compares only public candidates against the same IP family', () => {
  const candidates = [
    {type:'host', address:'2606:4700:0000:0000:0000:0000:0000:1111'},
    {type:'srflx', address:'::ffff:1.1.1.1'},
    {candidate:'candidate:1 1 udp 100 8.8.8.8 5000 typ srflx'},
    {type:'host', address:'client.local.'},
    {type:'host', address:'fe90::1'},
    {type:'relay', address:'9.9.9.9'},
  ].map(parseCandidate);
  const observed = compareWebRtc(candidates, [
    {source:'summary', address:'2606:4700::1111'}, {source:'ipv4', address:'1.1.1.1'},
  ]);
  assert.equal(observed.verdict, 'different');
  assert.deepEqual(observed.candidates.map(item => item.comparison),
    ['same','same','different','not-comparable','not-comparable','not-comparable']);
  assert.equal(observed.candidates[1].normalizedAddress, '1.1.1.1');
  assert.equal(observed.candidates[3].scope, 'mdns-masked');
  assert.equal(observed.candidates[4].scope, 'private-or-local');
  assert.equal(compareWebRtc([candidates[0]], [{source:'summary', address:'1.1.1.1'}]).verdict, 'different-family');
});

test('HTTPS probe failure preserves separate authoritative DNS evidence', async t => {
  const urls = [];
  let nonce;
  t.mock.method(globalThis, 'fetch', async (input, options) => {
    const url = new URL(input);
    urls.push(url.pathname);
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.redirect, 'error');
    if (url.pathname === '/_probe/dns') {
      nonce = url.hostname.split('.')[0];
      throw new TypeError('synthetic HTTPS failure');
    }
    if (url.pathname === '/_probe/dns-evidence') {
      assert.match(nonce, /^[a-f0-9]{32}$/);
      assert.equal(url.origin, 'https://audit.example');
      assert.equal(url.searchParams.get('nonce'), nonce);
      return Response.json({type:'dns-authority-observation', status:'observed', observations:[{sourceIp:'9.9.9.9'}]});
    }
    return Response.json({type:'address-family', hostname:url.hostname, ipVersion:6, visibleIp:'2606:4700::1111'});
  });
  const probes = await runNetworkProbes({
    ipv4ProbeOrigin:'https://v4.example', ipv6ProbeOrigin:'https://v6.example',
    dualStackProbeOrigin:'https://dual.example', dnsProbeSuffix:'dns.example',
  }, {network:{visibleIp:'1.1.1.1'}, dnsEvidenceSuffix:'dns.example'}, new URL('https://audit.example'));
  assert.equal(urls.filter(path => path === '/_probe/address').length, 3);
  assert.equal(probes.ipv4.matchesExpected, false);
  assert.equal(probes.ipv6.matchesExpected, true);
  assert.equal(probes.dualStack.matchesExpected, null);
  assert.equal(probes.dns.status, 'network-error');
  assert.equal(probes.dns.evidenceStatus, 'observed');
});

test('reused HTTPS probe hostnames are rejected before sending requests', async t => {
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected probe'); });
  const results = await runNetworkProbes({
    ipv4ProbeOrigin:'https://same.example', ipv6ProbeOrigin:'https://same.example:8443',
    dualStackProbeOrigin:'https://audit.example',
  }, {network:{visibleIp:null}}, new URL('https://audit.example'));
  for (const key of ['ipv4','ipv6','dualStack']) assert.equal(results[key].status, 'invalid-configuration');
  assert.equal(fetch.mock.callCount(), 0);
});

function traceFields(text) {
  assert.ok(text.endsWith('\n'));
  const fields = new Map();
  for (const line of text.slice(0, -1).split('\n')) {
    const separator = line.indexOf('=');
    assert.ok(separator > 0, line);
    const key = line.slice(0, separator);
    assert.ok(!fields.has(key), key);
    fields.set(key, JSON.parse(line.slice(separator + 1)));
  }
  assert.equal(fields.get('traceVersion'), 1);
  return fields;
}

test('trace paths and single-line JSON values preserve every kind of report field', () => {
  const unusual = 'value=a\nb\r\nc\u0085d\u2028e\u2029f\u202eg';
  const encoded = formatTrace({ server:{
    plain: 'simple',
    nested: { 'has.dot': unusual, 'q=x': 'one=two=three', '0': 0, 'list[0]': false, '中文': null, '': '' },
    list: [0, false, [' ', ''], undefined, {}, []],
    absent: undefined,
  }});
  assert.doesNotMatch(encoded, /[\r\u0085\u2028\u2029\u202e]/);
  const fields = traceFields(encoded);
  assert.deepEqual(parseTrace(encoded), fields);
  assert.throws(() => parseTrace('x="first"\nx="duplicate"\n'), SyntaxError);
  assert.deepEqual(Object.fromEntries(fields), {
    traceVersion:1, 'server.plain':'simple',
    'server.nested["has.dot"]':unusual, 'server.nested["q\\u003dx"]':'one=two=three',
    'server.nested["0"]':0, 'server.nested["list[0]"]':false, 'server.nested["中文"]':null, 'server.nested[""]':'',
    'server.list[0]':0, 'server.list[1]':false, 'server.list[2][0]':' ', 'server.list[2][1]':'',
    'server.list[3]':null, 'server.list[4]':{}, 'server.list[5]':[],
  });
});

test('the root URL returns uncached text with raw, nested and repeated request values', async () => {
  const url = 'https://audit.example/?x=first&x=second&has%3Dequals=v%3D1';
  const res = await dispatch(req(url));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.match(res.headers.get('cache-control'), /no-store/);
  assert.equal(res.headers.get('vary'), 'Accept');
  assert.equal(res.headers.get('access-control-allow-origin'), null);
  const fields = traceFields(await res.text());
  assert.equal(fields.get('server.request.url'), url);
  assert.equal(fields.get('server.request.path'), '/');
  assert.equal(fields.get('server.request.queryParameters["has\\u003dequals"]'), 'v=1');
  assert.equal(fields.get('server.request.queryEntries[0][1]'), 'first');
  assert.equal(fields.get('server.request.queryEntries[1][1]'), 'second');
  assert.equal(fields.get('server.cf.novelField2026.deep.flag'), false);
  assert.equal(fields.get('server.cf.novelField2026.deep.value'), 0);
  assert.equal(fields.get('server.headers.cookie'), 'session=HIDDEN123; login=HIDDEN456');
  assert.equal(fields.get('browserOnly.status'), 'not-run');
  assert.equal(fields.get('activeProbes.status'), 'not-run');
  const head = await dispatch(new Request(url, {method:'HEAD'}));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
  assert.equal((await dispatch(new Request(url, {method:'POST'}))).status, 405);
});

test('the same root embeds escaped fields for HTML and preserves the asset CSP', async () => {
  const path = 'https://audit.example/?x=first&x=second';
  const request = req(path);
  request.headers.set('accept', 'text/html,application/xhtml+xml,*/*;q=0.8');
  const header = '$& </pre><script>alert(1)</script> &lt; x=y';
  request.headers.set('x-trace-test', header);
  const policy = "default-src 'none'; connect-src 'self' https://probe.example https://*.dns.example";
  let assetCalls = 0;
  const env = {
    DNS_PROBE_SUFFIX:'dns.example',
    DNS_EVIDENCE:{fetch:() => Response.json({observations:[]})},
    ASSETS:{
      fetch(url) {
        assetCalls++;
        assert.equal(url.href, 'https://audit.example/');
        return new Response(read('index.html'), {headers:{'content-security-policy':policy}});
      },
    },
  };
  const response = await dispatch(request, env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(response.headers.get('vary'), 'Accept');
  assert.equal(response.headers.get('content-security-policy'), policy);
  assert.match(response.headers.get('cache-control'), /no-store/);
  const page = await response.text();
  assert.doesNotMatch(page, /<script>alert|<!--SERVER_TRACE-->/);
  const raw = page.match(/<pre id="trace-output"[^>]*>([\s\S]*?)<\/pre>/)[1];
  const fields = traceFields(raw.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&'));
  assert.equal(fields.get('server.headers.x-trace-test'), header);
  assert.equal(fields.get('server.network.visibleIp'), '2001:db8::1234');
  assert.equal(fields.get('server.dnsEvidenceSuffix'), 'dns.example');
  assert.equal(fields.get('server.request.queryEntries[1][1]'), 'second');
  const input = page.match(/data-probe-input="([^"]*)"/)[1];
  assert.deepEqual(JSON.parse(input.replaceAll('&quot;', '"')), {
    visibleIp:'2001:db8::1234', dnsEvidenceSuffix:'dns.example',
  });

  request.headers.set('accept', 'text/html;q=0.5,text/plain;q=1');
  const plain = await dispatch(request, env);
  const sameFormat = traceFields(await plain.text());
  assert.equal(plain.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(sameFormat.get('server.headers.x-trace-test'), fields.get('server.headers.x-trace-test'));
  assert.equal(sameFormat.get('server.network.visibleIp'), fields.get('server.network.visibleIp'));
  assert.equal(sameFormat.get('server.dnsEvidenceSuffix'), fields.get('server.dnsEvidenceSuffix'));
  assert.equal(assetCalls, 1);
});
