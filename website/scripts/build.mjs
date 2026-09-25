import {mkdir,readFile,writeFile,rm,cp,readdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {config} from '../site.config.mjs';
import {validateSiteUrl,escape as e} from '../src/lib/core.mjs';
import {pages} from '../src/content/pages.mjs';
import {utilityPages} from '../src/content/utility.mjs';
import {locales} from '../src/content/locales.mjs';
import {claims} from '../src/content/claims.mjs';
import {document,makeContext} from '../src/components/document.mjs';
import {t,encountered} from '../src/i18n/translate.mjs';
import {methods,refinementCopy} from '../src/phase3/refinement.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const dist=path.join(root,'dist'), site=validateSiteUrl(config.siteUrl),base=site.pathname;
const digest=s=>createHash('sha256').update(s).digest('hex');
const sri=s=>'sha256-'+createHash('sha256').update(s).digest('base64');
await rm(dist,{recursive:true,force:true});await mkdir(dist,{recursive:true});await cp(path.join(root,'public'),dist,{recursive:true});
await mkdir(path.join(dist,'assets/client'),{recursive:true});
const assets={};
async function asset(src,label,ext){const body=await readFile(path.join(root,src),'utf8');const name=`assets/${label}.${digest(body).slice(0,12)}.${ext}`;await writeFile(path.join(dist,name),body);return name;}
const css=(await Promise.all(['latin-fonts.css','site.css','phase2.css','phase3.css'].map(f=>readFile(path.join(root,'src/styles',f),'utf8')))).join('\n').replace(/\/\*[\s\S]*?\*\//g,'');
assets.css=`assets/site.${digest(css).slice(0,12)}.css`;await writeFile(path.join(dist,assets.css),css);
assets.boot=await asset('src/client/boot.js','preferences','js');
let fonts="@font-face{font-family:'Kurd Display';src:local('Unikurd Magroon');font-weight:400;font-style:normal;font-display:swap}@font-face{font-family:'Kurd Reading';src:local('shasenem-kiteb');font-weight:400;font-style:normal;font-display:swap}";
const fontSources=[['Kurd Display','Unikurd Magroon','k-magroon.woff2'],['Kurd Reading','shasenem-kiteb','shasenem-kiteb.woff2']];
let localFonts=[];
for(const [family,localName,name] of fontSources){try{await readFile(path.join(root,'public/assets/fonts',name));localFonts.push(`@font-face{font-family:'${family}';src:url('./fonts/${name}') format('woff2');font-weight:400;font-style:normal;font-display:swap}`);}catch(err){if(err.code!=='ENOENT')throw err;}}
if(localFonts.length===2)fonts=localFonts.join('');else if(localFonts.length)throw Error('Both original Sorani fonts are required. Run the font import command with both files.');
assets.fonts=`assets/sorani-fonts.${digest(fonts).slice(0,12)}.css`;await writeFile(path.join(dist,assets.fonts),fonts);


const rewritten=new Map();
async function compileModule(src){
 if(rewritten.has(src))return rewritten.get(src);
 let body=await readFile(src,'utf8');
 const imports=[...body.matchAll(/from ['"]([^'"]+)['"]/g)];
 for(const match of imports){const target=path.resolve(path.dirname(src),match[1]);if(!target.startsWith(path.join(root,'src')+path.sep))throw Error('Nonlocal build import');const name=await compileModule(target);body=body.replace(match[0],`from './${path.basename(name)}'`)}
 const filename=`assets/client/${path.basename(src).replace(/\.(js|mjs)$/,'')}.${digest(body).slice(0,12)}.js`;
 await writeFile(path.join(dist,filename),body);rewritten.set(src,filename);return filename;
}
assets.js=await compileModule(path.join(root,'src/client/site.js'));
const all=[...pages,...utilityPages(pages)];
if(new Set(all.map(p=>p.slug)).size!==all.length)throw Error('Duplicate site route');
const headers={},routes=[];
const permission='camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()';
function policy(html,prototype=false){const hashes=[...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(x=>`'${sri(x[1])}'`);return ["default-src 'none'",`script-src 'self' ${hashes.join(' ')}`.trim(),`style-src 'self'${prototype?" 'unsafe-inline'":''}`,"img-src 'self' data:","font-src 'self'",prototype?"connect-src 'none'":"connect-src 'self'",prototype?"frame-src 'none'":"frame-src 'self'",prototype?"frame-ancestors 'self'":"frame-ancestors 'none'","base-uri 'none'","object-src 'none'","form-action 'none'","worker-src 'self'"].join('; ')}
async function emit(relative,html,route,meta={}){
 const file=path.join(dist,relative);await mkdir(path.dirname(file),{recursive:true});await writeFile(file,html);
 headers[route]={'Content-Security-Policy':policy(html),'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':permission,'X-Frame-Options':'DENY','Cross-Origin-Opener-Policy':'same-origin'};
 routes.push({path:route,file:relative,...meta});
}
for(const code of Object.keys(locales))for(const p of all){const ctx=makeContext(code,base),route=ctx.p(p.slug);await emit(code+'/'+(p.slug?p.slug+'/':'')+'index.html',document(p,ctx,assets,all,{error:p.error}),route,{locale:code,title:t(p.title,code),category:t(p.category,code),indexable:!p.error,slug:p.slug});}
await emit('index.html',document(all[0],makeContext('en',base),assets,all,{alias:true}),base,{indexable:false,alias:true});
const error=all.find(p=>p.slug==='404');await emit('404.html',document(error,makeContext('en',base),assets,all,{error:true}),base+'404.html',{indexable:false,error:true});
await emit('offline.html',document(all.find(p=>p.slug==='offline'),makeContext('en',base),assets,all,{error:true}),base+'offline.html',{indexable:false});
// Extract the exact supplied prototype to ordered classic scripts. Preserve original bytes separately.
const original=await readFile(path.join(root,'src/prototype/app.html'),'utf8');
if(/ORS-\d|OBLIGATIONS|SCOPE_GROUPS|SCOPE_ROUTES|Phase 2\.7|phase18\//i.test(original))throw Error('Private content in public demo source');
let prototype=original.replace(/<title>[\s\S]*?<\/title>/,'<title>Kurdistan VPN · supplied design prototype · simulated</title>');
const protoCss=[...original.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map(m=>m[1]).join('\n')+'\n'+await readFile(path.join(root,'src/styles/app-design.css'),'utf8')+'\n'+await readFile(path.join(root,'src/styles/prototype-host.css'),'utf8');
prototype=prototype.replace(/<style[^>]*>[\s\S]*?<\/style>/g,'');
await mkdir(path.join(dist,'prototype'),{recursive:true});await writeFile(path.join(dist,'prototype/reference.css'),protoCss);
prototype=prototype.replace('</head>','<link rel="stylesheet" href="reference.css"><meta name="robots" content="noindex,nofollow"></head>');
prototype=prototype.replace('</head>',`<link rel="stylesheet" href="../${assets.fonts}"></head>`);
let scriptIndex=0;const scriptWrites=[];
prototype=prototype.replace(/<script([^>]*)>([\s\S]*?)<\/script>/g,(_,attrs,body)=>{const name='reference-'+String(scriptIndex++).padStart(2,'0')+'.js';scriptWrites.push(writeFile(path.join(dist,'prototype',name),body));return `<script src="${name}"></script>`});
await Promise.all(scriptWrites);
await cp(path.join(root,'src/client/prototype-history.js'),path.join(dist,'prototype/history.js'));
prototype=prototype.replace('</head>','<script src="history.js"></script></head>');
await cp(path.join(root,'src/client/prototype-adapter.js'),path.join(dist,'prototype/adapter.js'));
prototype=prototype.replace('</body>','<script src="adapter.js"></script></body>');
await cp(path.join(root,'src/client/app-design.js'),path.join(dist,'prototype/app-design.js'));
const protocolLogos=JSON.parse(await readFile(path.join(root,'src/refinement/protocol-logos.json'),'utf8'));
await cp(path.join(root,'src/refinement/protocol-logos'),path.join(dist,'prototype/protocol-logos'),{recursive:true});
await cp(path.join(root,'public/assets/kurdistan-mark.svg'),path.join(dist,'prototype/protocol-logos/kurd.svg'));
await writeFile(path.join(dist,'prototype/copy.js'),'window.DemoCopy='+JSON.stringify(refinementCopy)+';window.DemoMethods='+JSON.stringify(methods.map(p=>({...p,logo:protocolLogos[p.id]?.file||null})))+';');
prototype=prototype.replace('<script src="adapter.js">','<script src="copy.js"></script><script src="app-design.js"></script><script src="adapter.js">');
await writeFile(path.join(dist,'prototype/index.html'),prototype);
headers[base+'prototype/index.html']={'Content-Security-Policy':policy(prototype,true),'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':permission,'X-Frame-Options':'SAMEORIGIN','X-Robots-Tag':'noindex, nofollow'};
await cp(path.join(root,'src/content/protocols.json'),path.join(dist,'prototype/protocols.json'));
// Search metadata is factual website content. No remote service or input endpoint.
for(const code of Object.keys(locales)){
const searchIndex=all.filter(p=>!p.error&&p.slug!=='search').map(p=>({title:t(p.title,code),description:t(p.description,code),category:t(p.category,code),url:makeContext(code,base).p(p.slug),keywords:p.sections?.map(s=>t(s.title,code)).join(' ')||''}));
searchIndex.push(...methods.map(p=>({title:p.name,description:refinementCopy[code].ribbonHelp,category:refinementCopy[code].methods,url:makeContext(code,base).p('')+'#method-'+p.id,keywords:p.name+' '+p.family})));
await writeFile(path.join(dist,`search-index-${code}.json`),JSON.stringify(searchIndex));
}
// English alias retained only for older local guide caches; no extra locale is published.
await cp(path.join(dist,'search-index-en.json'),path.join(dist,'search-index.json'));
await mkdir(path.join(dist,'evidence'),{recursive:true});await writeFile(path.join(dist,'evidence/claims.json'),JSON.stringify({revision:config.revision,reviewed:config.reviewed,claims},null,2));
await cp(path.join(root,'src/content/protocols.json'),path.join(dist,'evidence/protocols.json'));
await cp(path.join(root,'src/content/privacy.json'),path.join(dist,'evidence/privacy.json'));
const indexed=routes.filter(r=>r.indexable);
await writeFile(path.join(dist,'sitemap.xml'),'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+indexed.map(r=>`<url><loc>${e(site.origin+r.path)}</loc></url>`).join('')+'</urlset>\n');
await writeFile(path.join(dist,'robots.txt'),`User-agent: *\nAllow: /\nDisallow: ${base}prototype/\nSitemap: ${site.origin}${base}sitemap.xml\n`);
await writeFile(path.join(dist,'.nojekyll'),'');
const cachePrefix='kurdistan-guides-'+encodeURIComponent(base)+'-';
const guidePaths=Object.keys(locales).flatMap(code=>['docs/profile','docs/enrollment','docs/recovery','help','privacy','offline'].map(s=>makeContext(code,base).p(s)));
const guideBodies=await Promise.all(guidePaths.map(p=>readFile(path.join(dist,p.slice(base.length),'index.html'),'utf8')));
const cacheKey=cachePrefix+digest(Object.values(assets).join('')+guideBodies.join('')).slice(0,12);
const offlineAssets=[...Object.values(assets),...rewritten.values(),'assets/kurdistan-mark.svg','assets/flag-uk.svg','assets/flag-kurdistan.svg','search-index-en.json','search-index-ckb.json','search-index-kmr.json','offline.html'].map(x=>base+x);
const cached=[...new Set([...guidePaths,...offlineAssets])];
const offlineMessages={en:'You are offline and no saved guide is available. Nothing was changed. Reconnect, then try again.',ckb:'ئینتەرنێت پچڕاوە و ڕێنماییەکی پاشەکەوتکراو بەردەست نییە. هیچ نەگۆڕاوە. دووبارە پەیوەست بە و هەوڵ بدەرەوە.',kmr:'Girêdana înternetê tune ye û rêberê tomarkirî nayê dîtin. Tiştek neguheriye. Dîsa girêbide û biceribîne.'};
const worker=`/* Explicit opt-in public-document cache. Never cache artifacts, user data or the prototype. */
const PREFIX=${JSON.stringify(cachePrefix)},CACHE=${JSON.stringify(cacheKey)},URLS=${JSON.stringify(cached)},BASE=${JSON.stringify(base)},MESSAGES=${JSON.stringify(offlineMessages)};
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(c=>c.addAll(URLS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k.startsWith(PREFIX)&&k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{const u=new URL(event.request.url);if(event.request.method!=='GET'||u.origin!==self.location.origin||u.search)return;
 const segment=u.pathname.slice(BASE.length).split('/')[0],locale=Object.hasOwn(MESSAGES,segment)?segment:'en';
 const failure=()=>new Response(MESSAGES[locale],{status:503,headers:{'Content-Type':'text/plain; charset=utf-8','Content-Language':locale}});
 if(URLS.includes(u.pathname)){event.respondWith(fetch(event.request).catch(async()=>await caches.match(event.request)||failure()));return;}
 if(event.request.mode==='navigate')event.respondWith(fetch(event.request).catch(async()=>await caches.match(BASE+locale+'/offline/')||failure()));});
`;
await writeFile(path.join(dist,'service-worker.js'),worker);
// Server/deployment header manifests. Do not assume GitHub Pages applies these headers.
for(const name of await readdir(path.join(root,'public/assets/fonts')))if(name.endsWith('.woff2'))headers[base+'assets/fonts/'+name]={'Access-Control-Allow-Origin':'*','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'};
await writeFile(path.join(dist,'security-headers.json'),JSON.stringify(headers,null,2));
const netlify=Object.entries(headers).map(([route,h])=>route+'\n'+Object.entries(h).map(([k,v])=>'  '+k+': '+v).join('\n')).join('\n\n');
await writeFile(path.join(dist,'_headers'),netlify+'\n');
await writeFile(path.join(dist,'build-info.json'),JSON.stringify({websiteVersion:config.websiteVersion,sourceRevision:config.revision,sourceReview:config.reviewed,siteUrl:config.siteUrl,base,assets,routes},null,2));
const entries=[];async function walk(dir){for(const item of await readdir(dir,{withFileTypes:true})){const full=path.join(dir,item.name);if(item.isDirectory())await walk(full);else{const rel=path.relative(dist,full).replaceAll('\\','/');if(rel==='BUILD_MANIFEST.json')continue;const bytes=await readFile(full);entries.push({path:rel,bytes:bytes.length,sha256:digest(bytes)})}}}await walk(dist);entries.sort((a,b)=>a.path.localeCompare(b.path));await writeFile(path.join(dist,'BUILD_MANIFEST.json'),JSON.stringify(entries,null,2));
console.log(`Built ${routes.length} static documents, ${indexed.length} indexable routes, ${entries.length} files.`);
console.log('Base path: '+base);console.log('Production output: '+dist);

if(process.env.I18N_COLLECT==='1'){await mkdir(path.join(root,'qa'),{recursive:true});await writeFile(path.join(root,'qa/translation-inventory.json'),JSON.stringify([...encountered],null,2));console.log('EDITORIAL COLLECTION BUILD: NOT VERIFIED FOR HANDOFF');}
