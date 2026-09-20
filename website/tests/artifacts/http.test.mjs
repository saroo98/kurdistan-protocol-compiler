import test,{after} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import {readFile,writeFile,symlink,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {gunzipSync,brotliDecompressSync} from 'node:zlib';
const info=JSON.parse(await readFile('dist/build-info.json','utf8'));
const temp=net.createServer();await new Promise(r=>temp.listen(0,'127.0.0.1',r));const port=temp.address().port;await new Promise(r=>temp.close(r));
const child=spawn(process.execPath,['scripts/serve.mjs'],{env:{...process.env,HOST:'127.0.0.1',PORT:String(port)},stdio:['ignore','pipe','pipe']});
let err='';child.stderr.on('data',b=>err+=b);
await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(Error('Server timeout '+err)),5000);child.stdout.once('data',()=>{clearTimeout(timeout);resolve()});child.once('exit',code=>{clearTimeout(timeout);reject(Error('Server exited '+code+' '+err))})});
after(()=>child.kill('SIGTERM'));
function request(path,method='GET',headers={}){return new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port,path,method,headers},res=>{const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}))});req.on('error',reject);req.end()})}
test('real HTTP route serves the built document and its security headers',async()=>{
 const r=await request(info.base+'en/');assert.equal(r.status,200);assert.match(r.headers['content-type'],/text\/html/);assert.equal(r.headers['x-content-type-options'],'nosniff');assert.equal(r.headers['referrer-policy'],'no-referrer');assert.ok(r.headers['content-security-policy'].includes("frame-ancestors 'none'"));assert.equal(r.body.toString(),await readFile('dist/en/index.html','utf8'));assert.equal(r.headers['strict-transport-security'],undefined,'Do not send HSTS from HTTP local preview');
});
test('HEAD, gzip, Brotli and ETag operate on the same production bytes',async()=>{
 const plain=await request(info.base+'en/');for(const encoding of ['gzip','br']){const r=await request(info.base+'en/','GET',{'accept-encoding':encoding});assert.equal(r.headers['content-encoding'],encoding);assert.deepEqual(encoding==='gzip'?gunzipSync(r.body):brotliDecompressSync(r.body),plain.body);assert.equal(Number(r.headers['content-length']),r.body.length);const cached=await request(info.base+'en/','GET',{'accept-encoding':encoding,'if-none-match':r.headers.etag});assert.equal(cached.status,304);assert.equal(cached.body.length,0);}
 const head=await request(info.base+'en/','HEAD');assert.equal(head.status,200);assert.equal(head.body.length,0);assert.equal(Number(head.headers['content-length']),plain.body.length);
});
test('invalid paths, unsupported methods and absent resources fail clearly',async()=>{
 for(const p of [info.base+'%2e%2e/LICENSE',info.base+'%00',info.base+'%ZZ',info.base+'bad%5cpath'])assert.equal((await request(p)).status,400,p);
 const r=await request(info.base+'no-such-page/');assert.equal(r.status,404);assert.match(r.body.toString(),/This page is not here/);assert.equal((await request(info.base+'en/','POST')).status,405);
});
test('prefix redirects and root robots resolve without a blanket SPA fallback',async()=>{
 if(info.base!=='/'){for(const p of ['/',info.base.slice(0,-1)]){const r=await request(p);assert.equal(r.status,308);assert.equal(r.headers.location,info.base);}}
 assert.equal((await request('/robots.txt')).status,200);assert.equal((await request(info.base+'en/trust')).status,308);
});
test('hashed assets are immutable; prototype and worker have separate boundaries',async()=>{
 const js=await request(info.base+info.assets.js);assert.match(js.headers['cache-control'],/immutable/);assert.match(js.headers['content-type'],/javascript/);
 const p=await request(info.base+'prototype/index.html');assert.equal(p.status,200);assert.ok(p.headers['content-security-policy'].includes("connect-src 'none'"));assert.equal(p.headers['x-robots-tag'],'noindex, nofollow');
 const sw=await request(info.base+'service-worker.js');assert.equal(sw.headers['service-worker-allowed'],info.base);assert.match(sw.headers['cache-control'],/no-cache/);
});

test('server refuses a symlink that escapes the published output root',async()=>{
 const outside=path.join(os.tmpdir(),`kurd-qa-outside-${process.pid}.txt`),entry='dist/__qa_symlink';
 try{await writeFile(outside,'QA-only marker, never served');await symlink(outside,entry);const r=await request(info.base+'__qa_symlink');assert.equal(r.status,403);assert.ok(!r.body.toString().includes('QA-only marker'));}
 finally{await rm(entry,{force:true});await rm(outside,{force:true});}
});
test('missing localized URLs serve the matching error document and matching CSP',async()=>{
 const allHeaders=JSON.parse(await readFile('dist/security-headers.json','utf8'));
 for(const locale of ['en','ckb','kmr']){
  const r=await request(info.base+locale+'/does-not-exist/');assert.equal(r.status,404);
  assert.equal(r.body.toString(),await readFile(`dist/${locale}/404/index.html`,'utf8'));
  assert.equal(r.headers['content-security-policy'],allHeaders[info.base+locale+'/404/']['Content-Security-Policy']);
 }
});
