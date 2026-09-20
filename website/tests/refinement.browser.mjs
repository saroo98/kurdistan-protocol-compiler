import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const axeSource=await readFile(process.env.AXE_SOURCE||require.resolve('axe-core/axe.min.js'),'utf8');
const info=JSON.parse(await readFile('dist/build-info.json','utf8'));
const port=Number(process.env.QA_PORT||4191),origin=`http://127.0.0.1:${port}`,base=origin+info.base;
const server=spawn(process.execPath,['scripts/serve.mjs','--host','127.0.0.1','--port',String(port)],{stdio:['ignore','pipe','pipe']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('exit',code=>reject(Error('Preview exited '+code)));});
const browser=await chromium.launch();
const report={passed:false,browser:browser.version(),transport:'Real local HTTP with production CSP',routes:0,layouts:[],journeys:[],errors:[],accessibility:[],limitations:['No physical devices, native-speaker sign-off or human assistive-technology testing.','Local lab performance is not field Core Web Vitals.']};
await mkdir('qa/screenshots',{recursive:true});
const shot=async(page,name)=>page.screenshot({path:`qa/screenshots/${name}.png`,fullPage:false});
async function newPage(locale='en',width=1440,theme='light',motion='reduce'){
 const p=await browser.newPage({viewport:{width,height:1000},colorScheme:theme,reducedMotion:motion});p.setDefaultTimeout(6000);
 p.on('pageerror',e=>report.errors.push(e.message));
 p.on('console',m=>{if(m.type()==='error'&&!m.text().includes('favicon'))report.errors.push(m.text());});
 await p.goto(base+locale+'/');await p.evaluate(()=>document.fonts.ready);return p;
}
async function demo(p){await p.locator('[data-demo]').scrollIntoViewIfNeeded();await p.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoReady==='true');return p.frames().find(f=>f.url().includes('/prototype/'));}
function check(value,message){assert.ok(value,message);report.journeys.push(message);}
try{
 const crawler=await newPage();
 for(const route of info.routes){const response=await crawler.goto(origin+route.path);assert.equal(response.status(),200,route.path);assert.equal(await crawler.locator('main h1').count(),1,route.path);report.routes++;}
 await crawler.close();
 for(const locale of ['en','ckb','kmr'])for(const theme of ['light','dark']){
  const p=await newPage(locale,1440,theme);
  for(const width of [320,360,390,430,768,1024,1280,1440,1920,2048,2560]){
   await p.setViewportSize({width,height:1000});
   const overflow=await p.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
   assert.equal(overflow,false,`${locale}/${theme}@${width}`);report.layouts.push({locale,theme,width,pass:true});
   if(theme==='light'&&width===390)await shot(p,`home-${locale}-390`);
  }
  await p.setViewportSize({width:1440,height:1000});await shot(p,`home-${locale}-${theme}`);
  await p.evaluate(axeSource);const accessibility=await p.evaluate(()=>axe.run({runOnly:{type:'tag',values:['wcag2a','wcag2aa']}}));
  report.accessibility.push({locale,theme,violations:accessibility.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)}))});assert.deepEqual(accessibility.violations,[],`${locale}/${theme} accessibility`);
  for(const id of ['phone','server','kurd']){await p.locator(`[data-hero-info=${id}]`).click();check(await p.locator(`[data-hero-panel=${id}]`).isVisible(),`${locale} hero ${id} selection`);assert.equal(await p.locator(`[data-hero-info=${id}]`).getAttribute('aria-pressed'),'true');}
  check(await p.locator('#protocols .method-link').count()===22,`${locale} all connection methods present`);
  assert.equal(await p.locator('#protocols .method-logo').count(),22);
  await p.locator('#protocols').scrollIntoViewIfNeeded();
  await p.waitForFunction(()=>[...document.querySelectorAll('#protocols img')].every(e=>e.complete&&e.naturalWidth>0));
  check(await p.locator('#method-wireguard').isVisible()&&await p.locator('#protocols details').count()===0,`${locale} methods need no disclosure`);
  await p.evaluate(()=>location.hash='method-wireguard');await p.locator('#method-wireguard').waitFor({state:'visible'});
  await p.locator('[data-search-open]').click();await p.locator('#global-search').fill('WireGuard');await p.locator('.search-result[href$="#method-wireguard"]').waitFor();await shot(p,`search-${locale}-${theme}`);await p.keyboard.press('Escape');
  assert.equal(await p.locator('.method-ribbon').count(),0);
  assert.equal(await p.locator('#protocols .method-link').first().evaluate(e=>getComputedStyle(e).borderRadius),'6px');
  assert.equal(await p.locator('.method-family').count(),5);assert.equal(await p.locator('.method-family ul li').count(),22);
  assert.deepEqual(await p.locator('#method-kurd').evaluate(e=>{const s=getComputedStyle(e);return [s.fontSize,s.fontWeight,s.color]}),await p.locator('#method-wireguard').evaluate(e=>{const s=getComputedStyle(e);return [s.fontSize,s.fontWeight,s.color]}));
  await p.locator('#protocols').screenshot({path:`qa/screenshots/protocols-${locale}-${theme}.png`});
  if(theme==='light'){await p.setViewportSize({width:390,height:1000});await p.locator('#protocols').screenshot({path:`qa/screenshots/protocols-${locale}-mobile.png`});await p.setViewportSize({width:1440,height:1000});}
  await p.locator('.privacy-explorer').scrollIntoViewIfNeeded();await p.locator('.privacy-explorer').screenshot({path:`qa/screenshots/privacy-${locale}-${theme}.png`});
  if(theme==='light'){await p.setViewportSize({width:390,height:1000});await p.locator('.privacy-explorer').screenshot({path:`qa/screenshots/privacy-${locale}-mobile.png`});await p.setViewportSize({width:1440,height:1000});}
  const f=await demo(p);
  if(locale==='en'&&theme==='light'){
   await p.locator('[data-demo-command=connecting]').click();
   await p.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoState==='connecting');
   await p.waitForTimeout(2200);
   assert.equal(await p.locator('[data-demo]').getAttribute('data-demo-state'),'connecting');
   await p.locator('[data-demo-command=disconnected]').click();
   await p.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoState==='disconnected');
  }
  assert.equal(await f.locator('[data-home-latency]').textContent(),'—');
  assert.deepEqual(await f.locator('[data-transfer]').allTextContents(),['—','—']);
  assert.equal(await f.locator('.refined-profile [data-home-latency]').count(),1);
  assert.equal(await p.locator('[data-demo-notice]').count(),1);
  assert.equal(await f.locator('.prototype-stamp,.refined-primary p').count(),0);
  const themeDetails=await f.evaluate(()=>({accent:getComputedStyle(document.querySelector('.device')).getPropertyValue('--accent').trim().toLowerCase(),rays:document.querySelectorAll('.refined-connect polygon').length,flag:getComputedStyle(document.querySelector('.bottom-nav'),'::before').display,logo:getComputedStyle(document.querySelector('.brand img')).filter}));
  assert.equal(themeDetails.accent,theme==='dark'?'#e4b33a':'#c69318');assert.equal(themeDetails.rays,21);assert.equal(themeDetails.flag,'none');assert.ok(themeDetails.logo.includes('brightness(0)'));
  const branding=await f.evaluate(()=>{const nav=document.querySelector('.bottom-nav'),stripe=getComputedStyle(nav,'::before'),brand=document.querySelector('.toolbar .brand');return {center:parseFloat(stripe.left)+parseFloat(stripe.marginLeft)+parseFloat(stripe.width)/2,width:nav.clientWidth,name:brand.textContent.trim(),outline:getComputedStyle(brand,'::after').outlineWidth};});
  assert.equal(branding.name,'KurdistanVPN');assert.equal(branding.outline,'1px');
  const shape=await f.evaluate(()=>{const main=document.querySelector('.screen-main'),a=document.querySelector('.refined-profile').getBoundingClientRect(),b=document.querySelector('.refined-metrics').getBoundingClientRect(),d=document.querySelector('.refined-primary>.btn').getBoundingClientRect();return {overflow:main.scrollHeight-main.clientHeight,edges:[a.left-b.left,b.left-d.left,a.right-b.right,b.right-d.right]};});
  check(shape.overflow<=1,`${locale}/${theme} Home primary controls fit`);check(shape.edges.every(n=>Math.abs(n)<=1),`${locale}/${theme} Phone alignment within 1px`);
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-home-${locale}-${theme}.png`});
  for(const key of ['device','server','session']){
   const control=f.locator(`[data-refine-screen=${key}]`).first();await control.click();check(await f.locator('.refined-detail').isVisible(),`${locale}/${theme} ${key} details`);
   if(locale==='en'&&theme==='light')await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-${key}.png`});
   await f.locator('[data-refine-back]').click();check(await control.evaluate(e=>e===document.activeElement),`${locale}/${theme} ${key} focus restored`);
   assert.equal(await f.evaluate(()=>KurdDemo.getState().session.status),'IDLE');
  }
  // Use normal timing here so cancellation is tested while completion is pending.
  await f.evaluate(()=>{const s=KurdDemo.getState();s.settings.reducedMotion=false;KurdDemo.setState(s);});
  for(const route of ['home','profiles','settings']){await f.evaluate(route=>KurdDemo.go(route),route);check(await f.locator('.toolbar [data-go=scan-qr]').count()===1&&await f.locator('.toolbar [data-action=profiles-add]').count()===1&&await f.locator('.toolbar [data-go=settings]').count()===0,`${locale}/${theme} ${route} shared import toolbar`);}
  await f.evaluate(()=>KurdDemo.go('home'));
  await f.locator('[data-focus-key=home-protocol-metric]').click();
  check(await f.locator('.protocol-options>button').count()===22,`${locale}/${theme} full protocol picker`);
  const expectedCount=await f.evaluate(()=>new Intl.NumberFormat(app.settings.language).format(app.profiles.filter(p=>p.protocol.toLowerCase()==='kurd').length));
  assert.ok((await f.locator('[data-value=kurd] .protocol-profile-count').innerText()).startsWith(expectedCount));
  assert.ok((await f.locator('[data-value=vmess] .protocol-profile-count').innerText()).startsWith(await f.evaluate(()=>new Intl.NumberFormat(app.settings.language).format(0))));
  assert.equal(await f.locator('[data-value=kurd][data-action=choose-demo-protocol]').getAttribute('aria-pressed'),'true');
  check(await f.locator('.toolbar [data-action=profiles-add]').count()===0,`${locale}/${theme} subscreen has back navigation only`);
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-protocol-picker-${locale}-${theme}.png`});
  await f.locator('[data-go=protocol-guide]').click();assert.equal(await f.locator('.protocol-guide section').count(),22);await f.locator('.toolbar [data-action=back]').click();
  await f.locator('[data-value=wireguard][data-action=choose-demo-protocol]').click();assert.equal(await f.locator('.protocol-lockup').innerText(),'WireGuard');assert.equal(await f.locator('.protocol-lockup svg').count(),0);
  await f.waitForFunction(()=>{const img=document.querySelector('.protocol-project-logo');return img?.complete&&img.naturalWidth>0;});
  assert.equal(await f.locator('.refined-route .refined-mini-sun').count(),0);
  if(locale==='en')await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-wireguard-${theme}.png`});
  if(locale==='en'&&theme==='light'){
   const choices=await f.evaluate(()=>DemoMethods.map(({id,logo})=>({id,logo})));
   for(const choice of choices){await f.locator('[data-focus-key=home-protocol-metric]').click();await f.locator(`[data-action=choose-demo-protocol][data-value="${choice.id}"]`).click();assert.equal(await f.locator('.refined-route .refined-mini-sun').count(),choice.id==='kurd'?1:0);if(choice.logo)await f.waitForFunction(()=>{const img=document.querySelector('.protocol-project-logo');return img?.complete&&img.naturalWidth>0;});else assert.equal(await f.locator('.protocol-project-logo').count(),0);}
   check(true,'All 22 selections use Kurd sun, verified project artwork, or text only');
  }
  await f.locator('[data-focus-key=home-protocol-metric]').click();await f.locator('[data-value=kurd][data-action=choose-demo-protocol]').click();
  await f.locator('.refined-connect').click();await f.locator('.refined-connect').click();await p.waitForTimeout(1250);
  check(await f.evaluate(()=>KurdDemo.getState().session.status)==='IDLE',`${locale}/${theme} Cancel prevents delayed connection`);
  await f.locator('.refined-primary [data-action=connect]').click();await p.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoState==='connected');
  assert.match(await f.locator('[data-home-latency]').textContent(),/^\d+ ms$/);
  assert.deepEqual(await f.locator('[data-transfer]').allTextContents(),['1.24 MB/s','86 KB/s']);
  check(await f.locator('.refined-transfer').isVisible(),`${locale}/${theme} Simulated transfer rates appear with connection`);
  check(await p.locator('[data-demo-command=connected]').getAttribute('aria-pressed')==='true',`${locale}/${theme} Parent reflects completed connection`);
  const beforePreferences=await f.evaluate(()=>({session:KurdDemo.getState().session.status,route:KurdDemo.getUI().route}));
  await p.evaluate(t=>{document.documentElement.dataset.theme=t;document.documentElement.dataset.motion='reduce';document.documentElement.dataset.text='large';},theme==='light'?'dark':'light');
  await f.waitForFunction(dark=>document.querySelector('.device').classList.contains('dark')===dark,theme==='light');
  check(await f.locator('.device.pref-large').count()===1,`${locale}/${theme} larger text reaches demo`);
  assert.deepEqual(await f.evaluate(()=>({session:KurdDemo.getState().session.status,route:KurdDemo.getUI().route})),beforePreferences,`${locale} preference changes preserve session and route`);
  await p.evaluate(t=>{document.documentElement.dataset.theme=t;delete document.documentElement.dataset.text;},theme);
  await f.waitForFunction(()=>!document.querySelector('.device').classList.contains('pref-large'));
  if(locale==='en'&&theme==='light')await p.locator('[data-demo-host]').screenshot({path:'qa/screenshots/phone-connected.png'});
  await f.locator('.refined-primary [data-action=disconnect]').click();await f.locator('.bottom-nav [data-go=profiles]').click();
  check(await f.locator('.profile-latency').evaluateAll(es=>es.every(e=>getComputedStyle(e).whiteSpace==='nowrap')),`${locale}/${theme} profile statuses stay on one line`);
  assert.equal(await f.locator('.compact-star').count(),0);
  assert.ok(await f.locator('.compact-profile').evaluateAll(es=>es.every(e=>getComputedStyle(e,'::before').display==='none')));
  assert.ok(await f.locator('.profile-metadata').evaluateAll(es=>es.every(e=>e.textContent==='Kurd')));
  assert.ok(await f.locator('.profile-latency').evaluateAll(es=>es.every(e=>['—','-1 ms'].includes(e.textContent))));
  assert.equal(await f.locator('.profile-latency.failed').first().innerText(),'-1 ms');
  await f.locator('[data-action=latency-test]').click();await p.waitForTimeout(500);check((await f.evaluate(()=>KurdDemo.latency())).simulation,`${locale}/${theme} Latency explicitly synthetic`);
  await f.locator('[data-latency-sort]').selectOption('latency-low');
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-profiles-${locale}-${theme}.png`});
  await p.locator('[data-demo-command=grandma]').click();await f.locator('.grandma').waitFor();await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/grandma-${locale}-${theme}.png`});
  await p.close();
 }
 const large=await newPage();const f=await demo(large);
 for(const count of [100,500,1000,5000]){
  await f.evaluate(count=>{const s=KurdDemo.getState();s.profiles=ProfileView.fixtures(count);s.selected=s.profiles[0].id;s.inspected=s.selected;KurdDemo.setState(s);KurdDemo.go('profiles');},count);
  check(await f.locator('.compact-profile').count()<160,`${count} profiles have bounded rendering`);
  await f.locator('[data-action=latency-test]').click();await f.locator('[data-action=latency-cancel]').click();const before=await f.evaluate(()=>JSON.stringify(KurdDemo.latency()));await large.waitForTimeout(250);check(before===await f.evaluate(()=>JSON.stringify(KurdDemo.latency())),`${count} latency cancellation stable`);
 }
 await large.close();
 const zoom=await newPage('ckb',320);
 await zoom.evaluate(()=>document.documentElement.style.fontSize='200%');
 check(await zoom.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Sorani at 320px and 200% text has no page overflow');
 await zoom.close();
 const nojs=await browser.newPage({javaScriptEnabled:false,viewport:{width:320,height:900}});await nojs.goto(base+'en/');check(await nojs.locator('main').innerText().then(t=>t.length>1000),'Static content works without JavaScript');await nojs.close();
 assert.deepEqual(report.errors,[]);report.passed=true;
}finally{await browser.close();server.kill();await writeFile('qa/refinement-browser.json',JSON.stringify(report,null,2));console.log(JSON.stringify({passed:report.passed,routes:report.routes,layouts:report.layouts.length,journeys:report.journeys.length,errors:report.errors.slice(0,8)}));}
