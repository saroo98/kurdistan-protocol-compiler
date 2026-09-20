/** Never archive stale, changed or unverified source/build/evidence. */
import {readFile,readdir} from 'node:fs/promises';import {spawnSync} from 'node:child_process';import path from 'node:path';
import {sourceSnapshot,evidenceSnapshot,buildSnapshot,sha256} from './integrity.mjs';
const receipt=JSON.parse(await readFile('qa/verification-receipt.json','utf8'));
if(receipt.passed!==true||receipt.schema!=='kurdistan-website-local-verification-v1')throw Error('A successful local verification receipt is required. Run npm run verify.');
if(Date.now()-Date.parse(receipt.finished)>24*3600000)throw Error('Receipt is older than 24 hours. Reverify.');
if((await sourceSnapshot()).sha256!==receipt.source.sha256)throw Error('Source changed after verification. Reverify.');
if(await buildSnapshot()!==receipt.buildManifestSha256)throw Error('Production manifest changed. Reverify.');
const manifest=JSON.parse(await readFile('dist/BUILD_MANIFEST.json','utf8'));
async function outputFiles(dir='dist'){const rows=[];for(const entry of await readdir(dir,{withFileTypes:true})){const name=path.join(dir,entry.name);if(entry.isSymbolicLink())throw Error('Unexpected production symlink: '+name);if(entry.isDirectory())rows.push(...await outputFiles(name));else rows.push(path.relative('dist',name).replaceAll('\\','/'));}return rows;}
const files=await outputFiles();if(files.length!==manifest.length+1||files.some(f=>f!=='BUILD_MANIFEST.json'&&!manifest.some(x=>x.path===f)))throw Error('Unexpected production files. Rebuild and reverify.');
for(const item of manifest){const bytes=await readFile(path.join('dist',item.path));if(sha256(bytes)!==item.sha256||bytes.length!==item.bytes)throw Error('Production output changed: '+item.path);}
if((await evidenceSnapshot()).sha256!==receipt.evidence.sha256)throw Error('QA evidence changed after verification. Reverify.');
const python=process.env.QA_PYTHON||(process.platform==='win32'?'python':'python3');
const output=path.resolve(process.argv[2]||'../Kurdistan_VPN_Website_Final.zip');
const result=spawnSync(python,['scripts/package_archive.py',process.cwd(),output],{stdio:'inherit'});
if(result.status!==0)throw Error('ZIP creation or integrity check failed');
console.log('Portable website project: '+output);
