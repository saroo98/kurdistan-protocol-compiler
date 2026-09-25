import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const info=JSON.parse(await readFile('dist/build-info.json','utf8'));
const server=spawn(process.execPath,['scripts/serve.mjs','--host','127.0.0.1','--port','4196'],{stdio:['ignore','pipe','pipe']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('exit',code=>reject(Error('Preview exited '+code)));});
const browser=await chromium.launch();
try{
 const page=await browser.newPage({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:4196'+info.base+'en/');
 await page.locator('[data-demo]').scrollIntoViewIfNeeded();
 await page.waitForFunction(()=>document.querySelector('[data-demo]').dataset.demoReady==='true');
 const frame=page.frames().find(f=>f.url().includes('/prototype/'));
 assert.equal(await frame.getByRole('button',{name:'Connection details All apps'}).count(),1,'Approved Home exposes routing details, not the obsolete route diagram');
 await frame.getByRole('button',{name:'Connection details All apps'}).click();
 await frame.getByRole('button',{name:'Done',exact:true}).click();
 await frame.locator('.bottom-nav [data-go=profiles]').click();
 assert.equal(await frame.getByRole('button',{name:'Test all latency',exact:true}).count(),1);
 assert.ok(await frame.getByRole('button',{name:/Favorite|Unfavorite/}).count()>0);
 await frame.locator('.bottom-nav [data-go=settings]').click();
 assert.equal(await frame.getByRole('heading',{name:'Settings',exact:true}).count(),1);
 for(const [locale,direction]of [['ckb','rtl'],['kmr','ltr']]){
  await frame.evaluate(locale=>{const s=KurdDemo.getState();s.settings.language=locale;KurdDemo.setState(s);},locale);
  assert.equal(await frame.locator('.screen-main').evaluate(e=>getComputedStyle(e).direction),direction);
  if(locale==='ckb')assert.match(await frame.locator('.device').evaluate(e=>getComputedStyle(e).fontFamily),/Kurd Reading/);
 }
 assert.deepEqual(errors,[]);
 console.log('Approved demo navigation and controls passed.');
}finally{await browser.close();server.kill();}
