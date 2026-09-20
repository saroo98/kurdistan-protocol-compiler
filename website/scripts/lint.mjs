/** Dependency-free syntax and source-boundary lint. Not a substitute for a security audit. */
import {readdir,readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const roots=['src','scripts','tests'];let count=0;const errors=[];
async function visit(dir){for(const item of await readdir(dir,{withFileTypes:true})){const f=path.join(dir,item.name);if(item.isDirectory()){if(!item.name.startsWith('__'))await visit(f);continue}if(!/\.(mjs|js)$/.test(f))continue;
 const result=spawnSync(process.execPath,['--check',f],{encoding:'utf8'});if(result.status!==0)errors.push(f+': '+result.stderr);count++;
 const source=await readFile(f,'utf8');if(f.startsWith('src/client/')&&/\beval\s*\(|new\s+Function\s*\(|document\.write\s*\(/.test(source))errors.push(f+': executable string evaluation is not allowed');
 if(f.startsWith('src/')&&/sourceMappingURL=data:|\bTODO\b|\bFIXME\b/.test(source))errors.push(f+': unresolved marker or embedded map');
}}
for(const root of roots)await visit(root);
const cfg=JSON.parse(await readFile('package.json','utf8'));
for(const name of ['build','dev','preview','verify','package'])if(!cfg.scripts[name])errors.push('Missing command '+name);
if(errors.length){console.error(errors.join('\n'));process.exitCode=1}else console.log(`Syntax and source-boundary lint passed for ${count} JavaScript modules.`);
