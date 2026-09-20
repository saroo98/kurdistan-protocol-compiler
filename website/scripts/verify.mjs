/** Final fail-fast verification. A success receipt binds the actual source and build. */
import {spawnSync} from 'node:child_process';
import {mkdir,writeFile,rm,readdir} from 'node:fs/promises';
import {sourceSnapshot,evidenceSnapshot,buildSnapshot} from './integrity.mjs';
if(process.env.I18N_COLLECT)throw Error('Editorial collection mode cannot be verified for delivery.');
const started=new Date().toISOString();
await mkdir('qa/evidence',{recursive:true});await rm('qa/verification-receipt.json',{force:true});
const original=await sourceSnapshot();
await writeFile('qa/verification-inputs.json',JSON.stringify(original,null,2));
const units=(await readdir('tests')).filter(f=>f.endsWith('.test.mjs')).map(f=>'tests/'+f);
const artifacts=(await readdir('tests/artifacts')).filter(f=>f.endsWith('.test.mjs')).map(f=>'tests/artifacts/'+f);
const steps=[
 ['lint',['scripts/lint.mjs']],
 ['unit',['--test',...units]],
 ['build',['scripts/build.mjs']],
 ['reproducibility',['scripts/reproducibility.mjs']],
 ['artifacts',['--test',...artifacts]],
 ['browser',['tests/refinement.browser.mjs']],
 ['performance',['scripts/python.mjs','tests/performance.py']],
 ['criteria',['scripts/requirements.mjs']],
 ['report',['scripts/report.mjs']],
];
const runs=[];
for(const [name,args]of steps){
 console.log(`\n=== ${name} ===`);const start=performance.now();
 const result=spawnSync(process.execPath,args,{encoding:'utf8',maxBuffer:32*1024*1024,env:process.env});
 const log=(result.stdout||'')+(result.stderr||'');process.stdout.write(log);await writeFile(`qa/evidence/${name}.log`,log);
 runs.push({name,command:'node '+args.join(' '),status:result.status,durationMs:Math.round(performance.now()-start)});
 if(result.error||result.status!==0){await writeFile('qa/last-failed-verification.json',JSON.stringify({started,runs,error:result.error?.message||'Verification step failed'},null,2));console.error('No success receipt created. Packaging is blocked.');process.exit(1)}
}
const finalSource=await sourceSnapshot();
if(finalSource.sha256!==original.sha256){
 const before=new Map(original.files.map(x=>[x.path,x.sha256]));
 const after=new Map(finalSource.files.map(x=>[x.path,x.sha256]));
 const changed=[...new Set([...before.keys(),...after.keys()])].filter(p=>before.get(p)!==after.get(p)).map(path=>({path,before:before.get(path),after:after.get(path)}));
 await writeFile('qa/source-mutation.json',JSON.stringify({started,changed},null,2));
 throw Error('Editable source changed during verification. See qa/source-mutation.json and rerun from an unchanged tree.');
}
await rm('qa/source-mutation.json',{force:true});
await rm('qa/last-failed-verification.json',{force:true});
const receipt={schema:'kurdistan-website-local-verification-v1',passed:true,scope:'Available local website suite only; mandatory external limitations are in QA_REPORT.md and docs/LIMITATIONS.md.',started,finished:new Date().toISOString(),source:finalSource,buildManifestSha256:await buildSnapshot(),runs,evidence:await evidenceSnapshot()};
await writeFile('qa/verification-receipt.json',JSON.stringify(receipt,null,2));
console.log('\nLOCAL VERIFICATION PASSED. Source, build and evidence are bound. External launch gates remain explicit.');
