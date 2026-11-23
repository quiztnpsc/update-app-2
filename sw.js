const A='quiz-app-v1',D='quiz-data-v1';
const APP=['./','index.html','app.js','data/meta.js','manifest.webmanifest','logo-192.png','logo-512.png','logo-maskable-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(A).then(c=>c.addAll(APP)));self.skipWaiting()});
self.addEventListener('activate',e=>e.waitUntil(Promise.all([caches.keys().then(k=>Promise.all(k.filter(x=>x!==A&&x!==D).map(x=>caches.delete(x)))),caches.open(D).then(c=>c.delete(new Request('data.js')))]).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{const r=e.request;
  if(r.url.indexOf('config.js')>-1&&new URL(r.url).origin===location.origin&&r.method==='GET'){e.respondWith(fetch(r).then(x=>{const c=x.clone();caches.open(D).then(k=>k.put(r,c));return x}).catch(()=>caches.match(r)));return}
  if(r.method!=='GET'||r.cache==='no-store'||r.url.indexOf('version.json')>-1||r.url.indexOf('content.json')>-1||new URL(r.url).origin!==location.origin)return;
  e.respondWith(caches.match(r).then(h=>h||fetch(r).then(x=>{if(x.ok){const c=x.clone();caches.open(D).then(k=>k.put(r,c))}return x})))});
