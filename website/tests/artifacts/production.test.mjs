import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir,stat} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {config} from '../../site.config.mjs';
import {claims} from '../../src/content/claims.mjs';
const root=process.cwd(), dist=path.join(root,'dist');
const budget=JSON.parse(await readFile('performance-budgets.json','utf8'));
const text=f=>readFile(path.join(dist,f),'utf8');
const info=JSON.parse(await text('build-info.json'));
const manifest=JSON.parse(await text('BUILD_MANIFEST.json'));
const hash=b=>createHash('sha256').update(b).digest('hex');
const decode=s=>s.replaceAll('&amp;','&').replaceAll('&quot;','"').replaceAll('&#39;',"'").replaceAll('&lt;','<').replaceAll('&gt;','>');
const attrs=(html,key)=>[...html.matchAll(new RegExp(`\\b${key}="([^"]*)"`,'g'))].map(m=>decode(m[1]));
const routeFiles=new Map(info.routes.map(r=>[r.path,r.file]));
routeFiles.set(info.base+'prototype/index.html','prototype/index.html');
const htmlByFile=new Map();for(const r of info.routes)htmlByFile.set(r.file,await text(r.file));
const publicFiles=[];async function walk(dir){for(const d of await readdir(dir,{withFileTypes:true})){if(d.isDirectory())await walk(path.join(dir,d.name));else publicFiles.push(path.relative(dist,path.join(dir,d.name)).replaceAll('\\','/'));}}await walk(dist);

test('all declared routes have complete static content, one main and one H1',()=>{
 for(const [f,h]of htmlByFile){assert.match(h,/<\/html>/i,f);assert.equal((h.match(/<main\b/g)||[]).length,1,f);assert.equal((h.match(/<h1\b/g)||[]).length,1,f);assert.ok(h.length>2500,f);assert.match(h,/class="skip-link" href="#content"/,f);assert.match(h,/<title>[^<]{12,}/,f);}
});
test('all local links, image/script/style resources and anchor targets resolve',async()=>{
 let checked=0;
 for(const [f,h]of htmlByFile){const route=info.routes.find(r=>r.file===f).path;
  for(const u of [...attrs(h,'href'),...attrs(h,'src')]){
   if(/^(https?:|data:|mailto:)/.test(u))continue;
   const resolved=new URL(u,'https://local.test'+route),rel=resolved.pathname.slice(info.base.length);assert.ok(resolved.pathname.startsWith(info.base),`${f}: link outside site ${u}`);
   const file=routeFiles.get(resolved.pathname)||rel;
   assert.ok(publicFiles.includes(file),`${f}: missing ${u} => ${file}`);
   if(resolved.hash&&file.endsWith('.html')){const target=htmlByFile.get(file)||await text(file);assert.ok(attrs(target,'id').includes(decodeURIComponent(resolved.hash.slice(1))),`${f}: missing anchor ${u}`);}
   checked++;
  }
 }
 assert.ok(checked>500,`Unexpectedly sparse link set ${checked}`);
});
test('indexable page metadata is distinct and canonical in all three locales',async()=>{
 const sitemap=await text('sitemap.xml'),titles=new Set();
 for(const r of info.routes){const h=htmlByFile.get(r.file);const title=h.match(/<title>([^<]+)<\/title>/)[1];
  if(r.indexable){assert.ok(!titles.has(title),`Repeated title ${title}`);titles.add(title);assert.ok(sitemap.includes(new URL(r.path,config.siteUrl).href),r.path);assert.match(h,/content="index,follow"/);}
  else assert.match(h,/content="noindex,follow"/);
  assert.match(h,/<link rel="canonical" href="https:\/\//);assert.match(h,/<meta name="description" content="[^"]{30,}"/);assert.match(h,/<meta property="og:image"/);
  for(const j of [...h.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)]){const d=JSON.parse(j[1]);assert.equal(d['@type'],'WebPage');assert.ok(!d.aggregateRating);}
 }
 assert.equal((sitemap.match(/<url>/g)||[]).length,info.routes.filter(r=>r.indexable).length);
 assert.ok(sitemap.includes('/ckb/')&&sitemap.includes('/kmr/')&&!sitemap.includes('/fa/')&&!sitemap.includes('/ar/')&&!sitemap.includes('/prototype/'));
});
test('every production HTML response has restrictive CSP with correct JSON-LD hash',async()=>{
 const headers=JSON.parse(await text('security-headers.json'));
 for(const r of info.routes){const h=headers[r.path],html=htmlByFile.get(r.file);assert.ok(h,r.path);const c=h['Content-Security-Policy'];assert.ok(c.includes("default-src 'none'")&&c.includes("frame-ancestors 'none'")&&c.includes("object-src 'none'"));assert.ok(!c.includes("'unsafe-inline'")&&!c.includes("'unsafe-eval'"));
  for(const m of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)){const v=createHash('sha256').update(m[1]).digest('base64');assert.ok(c.includes(`'sha256-${v}'`),r.path);}
  assert.equal(h['Referrer-Policy'],'no-referrer');assert.equal(h['X-Content-Type-Options'],'nosniff');
 }
 const c=headers[info.base+'prototype/index.html']['Content-Security-Policy'];assert.ok(c.includes("connect-src 'none'"));
});
test('supplied prototype initializes near the viewport in a labelled opaque sandbox',async()=>{
 const page=await text('en/product/index.html');assert.ok(!page.includes('data-demo-load'));assert.match(page,/demo-state-controls/);assert.ok(!/<iframe/.test(page));assert.match(page,/simulat|demonstration|prototype/i);
 const client=await readFile(path.join(root,'src/client/preview.js'),'utf8');assert.ok(client.includes("frame.sandbox='allow-scripts allow-downloads'"));assert.ok(!/sandbox.*allow-same-origin/.test(client));assert.ok(client.includes('event.source!==frame.contentWindow'));assert.ok(client.includes('IntersectionObserver'));assert.ok(client.includes("rootMargin:'800px 0px'"));
 assert.ok((await text('prototype/history.js')).includes('window.parent'));
 const original=await readFile(path.join(root,'src/prototype/app.html'),'utf8');const scripts=[...original.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
 for(let i=0;i<scripts.length;i++)assert.equal(await text(`prototype/reference-${String(i).padStart(2,'0')}.js`),scripts[i][2]);
});
test('claim registry never invents a released APK, metrics or audit evidence',()=>{
 assert.deepEqual(config.release.artifacts,[]);
 for(const c of claims){assert.ok(c.evidence.length,c.id);assert.ok(c.reviewed,c.id);assert.ok(c.limit,c.id);}
 for(const [f,h]of htmlByFile){assert.ok(!/href="[^"]+\.apk(?:[?#"])|trustpilot|100% anonymous|military.grade privacy|[0-9]+ million users/i.test(h),f);}
});
test('manifest binds actual build bytes and locally provided assets',async()=>{
 const entries=Array.isArray(manifest)?manifest:manifest.files;
 assert.ok(entries.length>70);
 for(const x of entries){const b=await readFile(path.join(dist,x.path||x.file));assert.equal(hash(b),x.sha256,x.path||x.file);assert.equal(b.length,x.bytes,x.path||x.file);}
 const fonts=publicFiles.filter(f=>/\.(woff2?|ttf|otf|eot)$/i.test(f));
 assert.equal(fonts.length,9);
 for(const f of fonts)assert.ok(f.startsWith('assets/fonts/')&&f.endsWith('.woff2'));
 const svg=await readFile(path.join(dist,'assets/kurdistan-mark.svg'));
 assert.equal(createHash('sha1').update(`blob ${svg.length}\0`).update(svg).digest('hex'),'52043eb1df2d0bf511dded884a89f4f88b92dca0');
});
test('production CSS and enhancement graph meet explicit transfer budgets',async()=>{
 const css=await readFile(path.join(dist,info.assets.css));assert.ok(gzipSync(css).length<budget.cssGzipBytes,'Shared CSS gzip budget');
 const jsFiles=publicFiles.filter(f=>f.startsWith('assets/')&&f.endsWith('.js'));let total=0;
 for(const f of jsFiles)total+=gzipSync(await readFile(path.join(dist,f))).length;
 assert.ok(total<budget.javascriptGzipBytes,`Shared enhancement budget; found ${total}`);
 assert.ok((await stat(path.join(dist,'assets/prototype-home.webp'))).size<100000);
});
test('site is dependency-free at runtime and build time',async()=>{
 const pkg=JSON.parse(await readFile('package.json','utf8'));assert.equal(Object.keys(pkg.dependencies||{}).length,0);assert.equal(Object.keys(pkg.devDependencies||{}).length,0);
 for(const [f,h]of htmlByFile){for(const src of attrs(h,'src'))assert.ok(!src.startsWith('http'),`${f}: remote resource ${src}`);assert.ok(!/\son[a-z]+="/i.test(h),f);}
});
test('public guide cache is scoped, opt-in and excludes release and prototype data',async()=>{
 const w=await text('service-worker.js');assert.match(w,/kurdistan-guides-/);assert.ok(w.includes('k.startsWith(PREFIX)'));assert.ok(!w.includes('prototype/'));assert.ok(!w.includes('/releases/'));assert.ok(w.includes('status:503'));assert.ok(w.includes('u.search'));
});

// HTTP navigation is environment-blocked here; do not substitute this for live ESM tests.
test('all emitted ES-module imports resolve within the published asset graph',async()=>{
 let imports=0;
 for(const f of publicFiles.filter(f=>f.startsWith('assets/client/')&&f.endsWith('.js'))){
  const body=await text(f);
  for(const m of body.matchAll(/from [\'"]([^\'"]+)[\'"]/g)){
   assert.ok(m[1].startsWith('./'),'Only published relative imports are allowed');
   const target=path.posix.normalize(path.posix.join(path.posix.dirname(f),m[1]));
   assert.ok(publicFiles.includes(target),`${f} imports missing ${target}`);imports++;
  }
 }
 assert.ok(imports>=3,'Main enhancements must retain their declared module relationships');
});
