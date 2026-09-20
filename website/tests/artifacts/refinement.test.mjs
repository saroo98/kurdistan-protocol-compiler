import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import path from 'node:path';

test('published demo contains no private planning records or navigation',async()=>{
 for(const file of await readdir('dist/prototype')){
  if(!/\.(js|html|json)$/.test(file))continue;
  const text=await readFile(path.join('dist/prototype',file),'utf8');
  assert.doesNotMatch(text,/ORS-\d|OBLIGATIONS|SCOPE_GROUPS|SCOPE_ROUTES|Phase 2\.7|phase18\/|data-go=["'](?:roadmap|scope-register|source-map)|page\(['"](?:roadmap|scope-detail|obligation-detail)/i,file);
 }
});
test('each generated page has unique anchor IDs',async()=>{
 const info=JSON.parse(await readFile('dist/build-info.json','utf8'));
 for(const route of info.routes){
  const html=await readFile(path.join('dist',route.file),'utf8');
  const ids=[...html.matchAll(/\sid="([^"]+)"/g)].map(m=>m[1]);
  assert.equal(new Set(ids).size,ids.length,route.path);
 }
});
test('protocol search resolves to localized method anchors',async()=>{
 for(const locale of ['en','ckb','kmr']){
  const records=JSON.parse(await readFile(`dist/search-index-${locale}.json`,'utf8'));
  const html=await readFile(`dist/${locale}/index.html`,'utf8');
  for(const name of ['WireGuard','VLESS','Hysteria2','Multi-hop','Kurd']){
   const record=records.find(r=>r.title===name);
   assert.ok(record,name);assert.ok(record.url.includes(`/${locale}/#method-`));
   assert.ok(html.includes(`id="${record.url.split('#')[1]}"`));
  }
 }
});
