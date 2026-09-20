import test from 'node:test';import assert from 'node:assert/strict';import {readFile} from 'node:fs/promises';
import {t} from '../../src/i18n/translate.mjs';import {principles,dedication} from '../../src/components/document.mjs';
const info=JSON.parse(await readFile('dist/build-info.json'));const dict=JSON.parse(await readFile('src/i18n/messages.json'));
const plain=h=>h.replace(/<[^>]*>/g,'').replaceAll('&amp;','&').replaceAll('&#39;',"'").replaceAll('&quot;','"');
test('all public English routes have real Sorani and Kurmanji equivalents and matching alternatives',async()=>{
 const routes=info.routes.filter(r=>r.locale==='en');assert.equal(routes.length,41);
 for(const r of routes)for(const l of ['en','ckb','kmr']){const target=info.routes.find(x=>x.locale===l&&x.slug===r.slug);assert.ok(target,`${l}/${r.slug}`);const h=await readFile('dist/'+target.file,'utf8');assert.ok(h.includes(`lang="${l}"`));assert.ok(h.includes(`dir="${l==='ckb'?'rtl':'ltr'}"`));
 for(const [lc,tag]of [['en','en'],['ckb','ku-Arab'],['kmr','ku-Latn']]){assert.ok(h.includes('hreflang="'+tag+'"'));assert.ok(h.includes(info.routes.find(x=>x.locale===lc&&x.slug===r.slug).path));}
 assert.ok(!/hreflang="(?:fa|ar)"|href="[^\"]+\/(?:fa|ar)\//.test(h));assert.ok(!/Translation coming soon|English content below/.test(h));}
});
test('translation catalogue contains genuine target strings and fails closed for missing content',()=>{
 assert.ok(dict.length>1000);const keys=new Set();for(const row of dict){assert.equal(row.length,3);assert.ok(!keys.has(row[0]),row[0]);keys.add(row[0]);for(const s of row.slice(1)){assert.ok(s.trim().length>0,row[0]);assert.ok(!/\bTODO\b|\bTBD\b/.test(s));}if(row[0].split(' ').length>3){assert.notEqual(row[1],row[0],row[0]);assert.notEqual(row[2],row[0],row[0]);}}
 assert.throws(()=>t('A deliberately missing translation regression sentinel.','ckb'),/translation/i);
});
test('four required English principles and the creator dedication remain exact',async()=>{
 const h=plain(await readFile('dist/en/index.html','utf8'));for(const [title,copy]of principles){assert.ok(h.includes(title));assert.ok(h.includes(copy));}assert.ok(h.includes(dedication));
});
test('locale search indices remain in their locale; public assets contain no hidden extra language',async()=>{
 for(const l of ['en','ckb','kmr']){const list=JSON.parse(await readFile(`dist/search-index-${l}.json`));assert.ok(list.length>=35);for(const r of list)assert.ok(r.url.startsWith(info.base+l+'/'));}
 assert.deepEqual([...new Set(info.routes.filter(r=>r.locale).map(r=>r.locale))].sort(),['ckb','en','kmr']);
});
test('all eighteen localized social assets exist and Sorani alone requests its font stylesheet',async()=>{
 for(const l of ['en','ckb','kmr']){for(const c of ['product','self-host','security','simple','releases','docs']){const b=await readFile(`dist/assets/social-${c}-${l}.png`);assert.equal(b.subarray(1,4).toString(),'PNG');}
 const h=await readFile(`dist/${l}/index.html`,'utf8');assert.equal(h.includes(info.assets.fonts),l==='ckb');}
});
test('responsive hidden heading breaks retain a readable space between sentences in all locales',async()=>{
 for(const locale of ['en','ckb','kmr']){
  const html=await readFile(`dist/${locale}/docs/profile/index.html`,'utf8');
  const heading=html.match(/<h1>([\s\S]*?)<\/h1>/)?.[1];assert.ok(heading);
  // Narrow and print layouts hide editorial <br> elements, leaving their text siblings adjacent.
  assert.ok(!/\.\p{L}/u.test(plain(heading)),`${locale}: hidden breaks must not concatenate sentences`);
 }
});
