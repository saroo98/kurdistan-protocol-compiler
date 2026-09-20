import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,stat} from 'node:fs/promises';
test('all refinement strings exist in each public locale',async()=>{
 const copy=JSON.parse(await readFile('src/refinement/copy.json','utf8'));
 assert.deepEqual(Object.keys(copy).sort(),['ckb','en','kmr']);
 for(const locale of ['ckb','kmr'])for(const key of Object.keys(copy.en))assert.ok(typeof copy[locale][key]==='string'&&copy[locale][key].trim(),`${locale}:${key}`);
});
test('private reference folders are absent from the portable source',async()=>{
 assert.equal(await stat('references').catch(()=>null),null);
 for(const name of ['docs/IMPLEMENTATION_PLAN.md','docs/PHASE2_PLAN.md'])assert.equal(await stat(name).catch(()=>null),null);
});
test('README npm commands exist in delivered package',async()=>{
 const readme=await readFile('README.md','utf8'),pkg=JSON.parse(await readFile('package.json','utf8'));
 for(const match of readme.matchAll(/npm run ([a-z][a-z0-9:-]*)/g))assert.ok(pkg.scripts[match[1]],match[1]);
});
