// 待确认：目标浏览器版本。歧义：浏览器兼容性与隐私设置可影响返回值。
// 后续研究：人工核对各浏览器读数。潜在优化：缓存同一标签页中的检测结果。
// 风险：指纹输出只能用于当前访客自检。验证重点：本地执行、结果齐全和异常处理。

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
export async function browserChecks() {
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
