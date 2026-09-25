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
  check(await f.locator('.gold-home').isVisible(),`${locale}/${theme} approved Home layout`);
  assert.equal(await f.locator('.refined-home').count(),0);
  assert.equal(await p.locator('[data-demo-notice]').count(),1);
  assert.equal(await f.locator('.prototype-stamp').count(),0);
  assert.equal(await f.locator('.brand').innerText(),'KurdistanVPN');
  assert.equal(await f.locator('.gold-sun-button polygon').count(),21);
  assert.equal(await f.locator('.device').evaluate(e=>getComputedStyle(e).getPropertyValue('--accent').trim()),'#ffba00');
  check(await f.locator('.screen-main').evaluate(e=>e.scrollWidth<=e.clientWidth+1),`${locale}/${theme} Home has no horizontal overflow`);
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-home-${locale}-${theme}.png`});
  await f.locator('[data-action=home-details]').click();
  check(await f.locator('.modal-layer').isVisible(),`${locale}/${theme} connection details`);
  await f.getByRole('button',{name:'Done',exact:true}).click();
  for(const route of ['home','profiles','settings']){
   await f.evaluate(route=>KurdDemo.go(route),route);
   check(await f.locator('.toolbar [data-go=scan-qr]').count()===1&&await f.locator('.toolbar [data-action=profiles-add]').count()===1,`${locale}/${theme} ${route} import toolbar`);
  }
  await f.evaluate(()=>KurdDemo.go('home'));
  await f.locator('.protocol-identity').click();
  check(await f.locator('.toolbar [data-action=back]').isVisible(),`${locale}/${theme} protocol navigation`);
  await f.locator('.toolbar [data-action=back]').click();
  await f.locator('.gold-sun-button').click();
  await f.locator('.gold-sun-button').click();
  await p.waitForTimeout(2800);
  check(await f.evaluate(()=>KurdDemo.getState().session.status)==='IDLE',`${locale}/${theme} cancellation prevents delayed connection`);
  await f.locator('.gold-sun-button').click();
  await p.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoState==='connected');
  check(await f.locator('.home-stat.transfer .stat-value').allTextContents().then(t=>t.join('|')==='12.4 MB/s|1.8 MB/s'),`${locale}/${theme} synthetic transfer state`);
  assert.equal(await p.locator('[data-demo-command=connected]').getAttribute('aria-pressed'),'true');
  const beforePreferences=await f.evaluate(()=>({session:KurdDemo.getState().session.status,route:KurdDemo.getUI().route}));
  await p.evaluate(t=>{document.documentElement.dataset.theme=t;document.documentElement.dataset.motion='reduce';document.documentElement.dataset.text='large';},theme==='light'?'dark':'light');
  await f.waitForFunction(dark=>document.querySelector('.device').classList.contains('dark')===dark,theme==='light');
  assert.equal(await f.locator('.device.pref-large').count(),1);
  assert.deepEqual(await f.evaluate(()=>({session:KurdDemo.getState().session.status,route:KurdDemo.getUI().route})),beforePreferences);
  await p.evaluate(t=>{document.documentElement.dataset.theme=t;delete document.documentElement.dataset.text;},theme);
  await f.waitForFunction(()=>!document.querySelector('.device').classList.contains('pref-large'));
  await f.locator('.gold-sun-button').click();
  await f.locator('.bottom-nav [data-go=profiles]').click();
  assert.equal(await f.locator('.gold-profile-row').count(),12);
  check(await f.locator('.profile-ping').evaluateAll(es=>es.every(e=>getComputedStyle(e).whiteSpace==='nowrap')),`${locale}/${theme} latency stays on one line`);
  assert.equal(await f.locator('.profile-ping.failed span').first().innerText(),'-1 ms');
  await f.locator('[data-action=gold-test]').click();
  await f.locator('[data-action=gold-cancel-test]').click();
  const cancelled=await f.locator('.profile-ping').allTextContents();
  await p.waitForTimeout(1750);
  assert.deepEqual(await f.locator('.profile-ping').allTextContents(),cancelled,`${locale} latency cancellation`);
  await f.locator('[data-action=gold-test]').click();
  await f.locator('[data-action=gold-test]').waitFor();
  await f.locator('select[data-ui=profileSort]').selectOption('latency');
  await f.locator('#profile-search').fill('Zurich');
  assert.equal(await f.locator('.gold-profile-row').count(),1);
  await f.locator('.profile-favorite').click();
  assert.equal(await f.locator('.profile-favorite').getAttribute('aria-pressed'),'true');
  await f.locator('#profile-search').fill('');
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/phone-profiles-${locale}-${theme}.png`});
  await p.locator('[data-demo-command=grandma]').click();
  await f.locator('.grandma').waitFor();
  await p.locator('[data-demo-host]').screenshot({path:`qa/screenshots/grandma-${locale}-${theme}.png`});
  await p.close();
 }
 const zoom=await newPage('ckb',320);
 await zoom.evaluate(()=>document.documentElement.style.fontSize='200%');
 check(await zoom.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Sorani at 320px and 200% text has no page overflow');
 await zoom.close();
 const nojs=await browser.newPage({javaScriptEnabled:false,viewport:{width:320,height:900}});await nojs.goto(base+'en/');check(await nojs.locator('main').innerText().then(t=>t.length>1000),'Static content works without JavaScript');await nojs.close();
 assert.deepEqual(report.errors,[]);report.passed=true;
}finally{await browser.close();server.kill();await writeFile('qa/refinement-browser.json',JSON.stringify(report,null,2));console.log(JSON.stringify({passed:report.passed,routes:report.routes,layouts:report.layouts.length,journeys:report.journeys.length,errors:report.errors.slice(0,8)}));}
