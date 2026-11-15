// 待确认：边缘实机接入后验证 request.cf 字段覆盖和 Cloudflare Enterprise DNS logs。
// 风险：测试仅使用模拟 request.cf；不宣称覆盖真实 IPv4/IPv6、STUN、DNS 与浏览器差异。
// 验证重点：原值无删减、嵌套 CF 字段、HTML 转义避免 XSS、国际化、自包含、CORS、探针不伪造结果。
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import vm from 'node:vm';
import test from 'node:test';

const base=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const code=readFileSync(path.join(base,'worker.js'),'utf8');
const worker=(await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'))).default;
function req(url='https://audit.example/?token=SECRET&x=%3C%2Fscript%3E') {
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
function bootFromHtml(html) {
  const part=html.match(/<script id="boot" type="application\/json">([\s\S]*?)<\/script>/);
  assert.ok(part,'boot JSON script');
  return JSON.parse(part[1]);
}
test('complete raw request and Cloudflare fields on initial navigation',async()=>{
  const response=await worker.fetch(req());
  assert.equal(response.status,200);
  assert.match(response.headers.get('content-type'),/text\/html/);
  assert.match(response.headers.get('content-security-policy'),/script-src 'self'/);
  assert.match(response.headers.get('cache-control'),/no-store/);
  assert.equal(response.headers.get('referrer-policy'),'no-referrer');
  const html=await response.text();
  for (const raw of ['Bearer VERY_SECRET','HIDDEN123','HIDDEN456','REF_SECRET','API_SECRET','UNKNOWN_SECRET','NOT_FOR_VISITORS']) assert.ok(html.includes(raw),raw);
  const boot=bootFromHtml(html);
  assert.equal(boot.server.schemaVersion,3);
  assert.equal(boot.server.request.url,'https://audit.example/?token=SECRET&x=%3C%2Fscript%3E');
  assert.deepEqual(boot.server.request.queryEntries,[['token','SECRET'],['x','</script>']]);
  assert.equal(boot.server.network.visibleIp,'2001:db8::1234');
  assert.equal(boot.server.network.ipVersion,6);
  assert.equal(boot.server.transport.clientQuicRtt,28);
  assert.equal(boot.server.request.cookieCount,2);
  assert.equal(boot.server.headers.authorization,'Bearer VERY_SECRET');
  assert.equal(boot.server.headers.cookie,'session=HIDDEN123; login=HIDDEN456');
  assert.equal(boot.server.headers['x-api-key'],'API_SECRET');
  assert.equal(boot.server.headers['x-weird'],'UNKNOWN_SECRET');
  assert.equal(boot.server.headers['accept-language'],'zh-CN');
  assert.equal(boot.server.headerClassification.authorization.sensitive,true);
  assert.equal(boot.server.mutualTls.certPresented,'1');
  assert.equal(boot.server.cf.hostMetadata.internalSecret,'NOT_FOR_VISITORS');
  assert.equal(boot.server.cf.novelField2026.deep.flag,false);
  assert.equal(boot.server.cf.novelField2026.deep.value,0);
  assert.equal(boot.server.cf.botManagement.jsDetection.passed,false);
  assert.equal(boot.server.cf.verifiedBotCategory,undefined);
});
test('prevents script injection using HTML and JSON escaping',async()=>{
  const r=new Request('https://audit.example/?%3Cscript%3E=1',{headers:{'user-agent':'</script><script>alert(1)</script>','cf-connecting-ip':'203.0.113.42'}});
  const html=await (await worker.fetch(r)).text();
  assert.equal(html.includes('</script><script>alert(1)'),false);
  const boot=bootFromHtml(html);
  assert.equal(boot.server.headers['user-agent'],'</script><script>alert(1)</script>');
});
test('JSON API is no-cache, no CORS and reports its own incoming request',async()=>{
  const res=await worker.fetch(new Request('https://audit.example/api/report'));
  assert.equal(res.headers.get('access-control-allow-origin'),null);
  assert.match(res.headers.get('content-type'),/application\/json/);
  assert.match(res.headers.get('cache-control'),/no-store/);
  assert.equal(res.headers.get('cdn-cache-control'),'no-store');
  const data=await res.json();
  assert.equal(data.network.visibleIp,null);
  assert.equal(data.request.path,'/api/report');
  assert.equal(data.limits.dnsResolver,'not observable from standard Worker HTTP requests');
});
test('same-origin assets include automatic check behavior, bilingual UI and CSP',async()=>{
  const js=await (await worker.fetch(new Request('https://audit.example/assets/client.js'))).text();
  const css=await (await worker.fetch(new Request('https://audit.example/assets/site.css'))).text();
  new vm.Script(js);
  assert.match(js,/stun\.cloudflare\.com:3478/);
  assert.match(js,/void runAll\(\)/);
  assert.match(js,/getHighEntropyValues/);
  assert.match(js,/OfflineAudioContext/);
  assert.match(js,/sha256/);
  assert.match(js,/canvasCheck/);
  assert.match(js,/fontsCheck/);
  assert.match(js,/lang==='zh'\?'en':'zh'/);
  assert.match(js,/server\.cf/);
  assert.match(css,/@media\(max-width:480px\)/);
});
test('no requested sensitive cookie is sent to optional probe',async()=>{
  const res=await worker.fetch(new Request('https://ip4.example/_probe/address',{headers:{authorization:'Bearer x',cookie:'id=abc'}}));
  const text=await res.text();
  assert.ok(!text.includes('Bearer x'));
  assert.ok(!text.includes('id=abc'));
});
test('probe reports actual IP family, never fabricates expected family or DNS resolver',async()=>{
  const a=await worker.fetch(req('https://ip4.example/_probe/address'));
  assert.equal(a.status,200);
  const result=await a.json();
  assert.equal(result.ipVersion,6);
  assert.equal(result.type,'address-family');
  assert.match(result.warning,/not force IPv4\/IPv6/);
  const d=await (await worker.fetch(req('https://nonce.dns.example/_probe/dns'))).json();
  assert.equal(d.type,'dns-http-reachability');
  assert.match(d.warning,/cannot identify/);
});
test('probe CORS restricts to configured public site origin',async()=>{
  const env={PUBLIC_ORIGIN:'https://audit.example'};
  const allowed=new Request('https://ip4.example/_probe/address',{headers:{origin:'https://audit.example'}});
  const ok=await worker.fetch(allowed,env);
  assert.equal(ok.headers.get('access-control-allow-origin'),'https://audit.example');
  assert.equal(ok.headers.get('vary'),'Origin');
  const wrong=new Request('https://ip4.example/_probe/address',{headers:{origin:'https://attacker.example'}});
  const no=await worker.fetch(wrong,env);
  assert.equal(no.headers.get('access-control-allow-origin'),null);
  const preflight=await worker.fetch(new Request('https://ip4.example/_probe/address',{method:'OPTIONS',headers:{origin:'https://audit.example'}}),env);
  assert.equal(preflight.status,204);
  assert.equal(preflight.headers.get('access-control-allow-origin'),'https://audit.example');
});
test('configured probe origins and DNS suffix are validated before CSP injection',async()=>{
  const env={
    IPV4_PROBE_ORIGIN:'https://ip4.example',
    IPV6_PROBE_ORIGIN:'https://ip6.example',
    DNS_PROBE_SUFFIX:'dns.example.com',
    PUBLIC_ORIGIN:'https://audit.example',
  };
  const page=await worker.fetch(req('https://audit.example/'),env);
  assert.match(page.headers.get('content-security-policy'),/https:\/\/ip4.example/);
  assert.match(page.headers.get('content-security-policy'),/https:\/\/\*\.dns.example.com/);
  const boot=bootFromHtml(await page.text());
  assert.equal(boot.config.ipv6ProbeOrigin,'https://ip6.example');
  assert.equal(boot.config.probeAuto,true);
  const evil=await worker.fetch(req('https://audit.example/'),{
    IPV4_PROBE_ORIGIN:'javascript:alert(1)',DNS_PROBE_SUFFIX:'bad.com; script-src *',
  });
  const data=bootFromHtml(await evil.text());
  assert.equal(data.config.ipv4ProbeOrigin,null);
  assert.equal(data.config.dnsProbeSuffix,null);
});
test('method, path and HEAD semantics remain predictable',async()=>{
  assert.equal((await worker.fetch(new Request('https://audit.example/',{method:'POST'}))).status,405);
  assert.equal((await worker.fetch(new Request('https://audit.example/not-found'))).status,404);
  assert.equal((await worker.fetch(new Request('https://audit.example/favicon.ico'))).status,204);
  const head=await worker.fetch(new Request('https://audit.example/',{method:'HEAD'}));
  assert.equal(head.status,200);
  assert.equal(await head.text(),'');
});
