/** Source and evidence digests are local integrity checks, not a signature. */
import {readdir,readFile} from 'node:fs/promises';import path from 'node:path';import {createHash} from 'node:crypto';
export const sha256=b=>createHash('sha256').update(b).digest('hex');
const sourceDirs=['src','public','scripts','tests','docs','deploy'];
const sourceFiles=['package.json','package-lock.json','site.config.mjs','requirements-qa.txt','README.md','LICENSE','NOTICE','.gitignore','.env.example','performance-budgets.json'];
async function walk(dir){let result=[];for(const e of await readdir(dir,{withFileTypes:true})){if(['__pycache__','.venv','node_modules','tmp'].includes(e.name))continue;const f=path.join(dir,e.name);if(e.isSymbolicLink())throw Error('Symlink not allowed in project inputs: '+f);if(e.isDirectory())result.push(...await walk(f));else if(e.isFile())result.push(f);}return result;}
async function digestFiles(files){const rows=[];for(const file of [...new Set(files)].sort()){const bytes=await readFile(file);rows.push({path:file.replaceAll('\\','/'),bytes:bytes.length,sha256:sha256(bytes)})}return {sha256:sha256(JSON.stringify(rows)),files:rows};}
export async function sourceSnapshot(){let files=[...sourceFiles];for(const dir of sourceDirs)files.push(...await walk(dir));return digestFiles(files);}
export async function evidenceSnapshot(){return digestFiles((await walk('qa')).filter(f=>!f.endsWith('verification-receipt.json')));}
export async function buildSnapshot(){return sha256(await readFile('dist/BUILD_MANIFEST.json'));}
