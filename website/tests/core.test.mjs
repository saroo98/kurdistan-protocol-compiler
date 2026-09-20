import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Behavioural red/green tests. Dynamic import lets the initial missing implementation fail clearly.
const core = await import('../src/lib/core.mjs').catch(() => null);
test('required shared implementation exists', () => assert.ok(core, 'core module must be implemented'));
test('HTML values are escaped, not interpreted', () => {
  assert.equal(core.escape('<a "x">&\'test'), '&lt;a &quot;x&quot;&gt;&amp;&#39;test');
});
test('base paths work both at a domain root and a GitHub Pages prefix', () => {
  assert.equal(core.pathFor('trust', 'en', '/project/'), '/project/en/trust/');
  assert.equal(core.pathFor('', 'ckb', '/'), '/ckb/');
  assert.throws(() => core.pathFor('../escape', 'en', '/'));
});
test('sun has 21 equal tips with a vertical first ray', () => {
  const p = core.sunPoints();
  assert.equal(p.length, 42);
  assert.deepEqual(p[0], [120, 20]);
  p.forEach(([x,y],i)=>assert.ok(Math.abs(Math.hypot(x-120,y-120)-(i%2?50:100))<0.00001));
});
test('site search is diacritic-insensitive and does not run markup', () => {
  assert.equal(core.normalize('Kurmancî'), 'kurmanci');
  assert.ok(core.rankSearch('expired', [{title:'Profile expired',description:'Replace with an owner-issued profile',category:'Help',url:'/help/'}]).length);
  assert.equal(core.rankSearch('<script>', [{title:'Help',description:'Setup',category:'Help',url:'/help/'}]).length,0);
});
test('claim status is a controlled vocabulary and evidence is required', () => {
  assert.throws(()=>core.validateClaim({id:'test',status:'perfect',wording:'Works'}));
  assert.throws(()=>core.validateClaim({id:'test',status:'AVAILABLE',wording:'Works',evidence:[]}));
  assert.equal(core.validateClaim({id:'test',status:'EXPERIMENTAL',wording:'A design demonstration',evidence:['references/prototype']}),true);
});
test('public prototype source excludes private planning and preserves the app state model', async () => {
  const source=await readFile(new URL('../src/prototype/app.html',import.meta.url),'utf8');
  assert.doesNotMatch(source,/ORS-\d|OBLIGATIONS|SCOPE_GROUPS|SCOPE_ROUTES|Phase 2\.7|phase18\//i);
  for(const token of ['KurdState','importProfile','canConnect','grandma-home','profile-details','encryptSnapshot','cancelSessionTimer'])assert.ok(source.includes(token),token);
});
