import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

async function port(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;}
async function start(p,args=[]){
 const c=spawn(process.execPath,['scripts/serve.mjs',...args],{env:{...process.env,HOST:'127.0.0.1',PORT:String(p)},stdio:['ignore','pipe','pipe']});
 const text={out:'',err:''};c.stdout.on('data',b=>text.out+=b);c.stderr.on('data',b=>text.err+=b);
 await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{c.kill();reject(Error('Preview start timed out: '+text.err))},3500);c.stdout.once('data',()=>{clearTimeout(timer);resolve()});c.once('exit',code=>{clearTimeout(timer);reject(Error('Preview exited: '+code+' '+text.err))})});
 return {c,text,stop:()=>new Promise(r=>{c.once('exit',r);c.kill('SIGTERM')})};
}
function get(p,path){return new Promise((resolve,reject)=>{http.get({host:'127.0.0.1',port:p,path,timeout:1500},res=>{res.resume();res.on('end',()=>resolve(res))}).on('error',reject).on('timeout',function(){this.destroy(Error('HTTP timeout'))})});}

test('preview identifies its actual build and project directory in terminal and response headers',async()=>{
 const p=await port(),s=await start(p);
 try{const info=JSON.parse(await readFile('dist/build-info.json','utf8'));const r=await get(p,info.base+'en/');
 assert.equal(r.statusCode,200);assert.equal(r.headers['x-kurdistan-website-version'],info.websiteVersion);
 assert.equal(r.headers['x-kurdistan-build'],createHash('sha256').update(await readFile('dist/BUILD_MANIFEST.json')).digest('hex').slice(0,16));
 assert.match(s.text.out,/Project directory:/);assert.ok(s.text.out.includes(process.cwd()));assert.ok(s.text.out.includes(info.base+'en/'));
 }finally{await s.stop();}
});

test('preview refuses an occupied port with actionable instructions rather than appearing to serve an old version',async()=>{
 const p=await port(),s=await start(p);
 try{const other=spawn(process.execPath,['scripts/serve.mjs'],{env:{...process.env,HOST:'127.0.0.1',PORT:String(p)},stdio:['ignore','pipe','pipe']});let stderr='';other.stderr.on('data',b=>stderr+=b);
 const status=await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>{other.kill();reject(Error('Second server did not fail'))},3000);other.once('exit',code=>{clearTimeout(timeout);resolve(code)})});
 assert.notEqual(status,0);assert.match(stderr,/already in use/i);assert.match(stderr,/No new preview was started/);assert.match(stderr,/--port/);
 }finally{await s.stop();}
});

test('explicit --port overrides PORT so a clean browser origin can be used',async()=>{
 const envPort=await port(),cliPort=await port();const s=await start(envPort,['--port',String(cliPort)]);
 try{assert.ok(s.text.out.includes(':'+cliPort+'/'),'Printed address must use --port');const info=JSON.parse(await readFile('dist/build-info.json','utf8'));assert.equal((await get(cliPort,info.base+'en/')).statusCode,200);}finally{await s.stop();}
});

test('npm preview rebuilds before serving instead of silently displaying an obsolete dist',async()=>{
 const p=JSON.parse(await readFile('package.json','utf8'));assert.match(p.scripts.preview,/scripts\/build\.mjs\s*&&\s*node scripts\/serve\.mjs/);
});
