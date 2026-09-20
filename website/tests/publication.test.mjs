import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
test('publication boundary allows public templates and rejects private staged plans',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'website-boundary-'));
 const site=path.join(root,'website');
 const script=path.resolve('scripts/publication-boundary.mjs');
 try{
  await mkdir(path.join(site,'src/social'),{recursive:true});
  execFileSync('git',['init','--quiet',root]);
  await writeFile(path.join(site,'src/social/product.html'),'<h1>Public product</h1>');
  execFileSync('git',['add','.'],{cwd:root});
  assert.equal(spawnSync(process.execPath,[script,'--staged'],{cwd:site}).status,0);
  await writeFile(path.join(site,'ROADMAP.md'),'Private fixture');
  execFileSync('git',['add','.'],{cwd:root});
  assert.equal(spawnSync(process.execPath,[script,'--staged'],{cwd:site}).status,1);
 }finally{await rm(root,{recursive:true,force:true});}
});
