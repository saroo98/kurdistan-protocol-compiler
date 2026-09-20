import http from 'node:http';
import {parseArgs} from 'node:util';
import {gzipSync,brotliCompressSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {readFile,stat,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../dist');
const info=JSON.parse(await readFile(path.join(root,'build-info.json'),'utf8'));
const headers=JSON.parse(await readFile(path.join(root,'security-headers.json'),'utf8'));
const {values}=parseArgs({options:{port:{type:'string'},host:{type:'string'}},strict:true});
const port=Number(values.port??process.env.PORT??4174),host=values.host??process.env.HOST??'127.0.0.1';
if(!Number.isInteger(port)||port<1||port>65535)throw Error('Choose a whole-number port between 1 and 65535, for example --port 4174.');
const buildId=createHash('sha256').update(await readFile(path.join(root,'BUILD_MANIFEST.json'))).digest('hex').slice(0,16);
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp','.ico':'image/x-icon','.xml':'application/xml; charset=utf-8','.txt':'text/plain; charset=utf-8','.md':'text/plain; charset=utf-8'};
function basic(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-cache');}
const server=http.createServer(async(req,res)=>{
 basic(res);res.setHeader('X-Kurdistan-Website-Version',info.websiteVersion);res.setHeader('X-Kurdistan-Build',buildId);if(!['GET','HEAD'].includes(req.method)){res.writeHead(405,{Allow:'GET, HEAD'});res.end('Read-only static website.');return}
 let pathname;try{const raw=(req.url||'/').split('?')[0];pathname=decodeURIComponent(raw);if(pathname.includes('\0')||pathname.includes('\\')||pathname.split('/').includes('..'))throw Error('Invalid path')}catch{res.writeHead(400);res.end('Invalid path. Nothing was changed. Return to the website homepage.');return}
 if((pathname==='/'&&info.base!=='/')||(info.base!=='/'&&pathname===info.base.slice(0,-1))){res.writeHead(308,{Location:info.base});res.end();return}
 let relative=pathname==='/robots.txt'?'robots.txt':pathname.startsWith(info.base)?pathname.slice(info.base.length):null;
 const locale=pathname.startsWith(info.base)?pathname.slice(info.base.length).split('/')[0]:'en';
 const errorLocale=['en','ckb','kmr'].includes(locale)?locale:'en';
 const notFoundRelative=errorLocale+'/404/index.html';
 let status=200;
 if(relative===null){relative=notFoundRelative;status=404;}
 if(relative===''||relative.endsWith('/'))relative+='index.html';
 let filename=path.resolve(root,relative);
 if(!filename.startsWith(root+path.sep)){res.writeHead(400);res.end('Invalid path.');return}
 try{const st=await stat(filename);if(st.isDirectory()){res.writeHead(308,{Location:pathname+'/'});res.end();return}if(!st.isFile())throw Error('Not file');const canonical=await realpath(filename);if(!canonical.startsWith(root+path.sep)){res.writeHead(403,{'Content-Type':'text/plain; charset=utf-8'});res.end('This resource is outside the published website. Return to the homepage.');return}}
 catch{filename=path.join(root,notFoundRelative);status=404;}
 try{
 const body=await readFile(filename),ext=path.extname(filename);
 let route=status===404?info.base+errorLocale+'/404/':pathname;
 if(relative==='prototype/index.html')route=info.base+'prototype/index.html';
 const h=headers[route]||headers[route.replace(/index\.html$/,'')];
 for(const [key,value]of Object.entries(h||{}))res.setHeader(key,value);
 if(/\.[a-f0-9]{12}\.(css|js)$/.test(filename))res.setHeader('Cache-Control','public, max-age=31536000, immutable');
 if(filename.endsWith('service-worker.js'))res.setHeader('Service-Worker-Allowed',info.base);
 let payload=body;const accept=req.headers['accept-encoding']||'';
 if(body.length>1024&&['.html','.css','.js','.json','.svg','.xml','.txt'].includes(ext)){res.setHeader('Vary','Accept-Encoding');if(/\bbr\b/.test(accept)){payload=brotliCompressSync(body);res.setHeader('Content-Encoding','br')}else if(/\bgzip\b/.test(accept)){payload=gzipSync(body);res.setHeader('Content-Encoding','gzip')}}
 const etag='\"'+createHash('sha256').update(payload).digest('hex').slice(0,24)+'\"';res.setHeader('ETag',etag);
 if(req.headers['if-none-match']===etag&&status===200){res.writeHead(304);res.end();return}
 res.writeHead(status,{'Content-Type':types[ext]||'application/octet-stream','Content-Length':payload.length});res.end(req.method==='HEAD'?undefined:payload);
 }catch{res.writeHead(500,{'Content-Type':'text/plain; charset=utf-8'});res.end('The page could not be read. Your data was not changed. Try reloading or return to the website homepage.');}
});
server.on('error',error=>{
 if(error.code==='EADDRINUSE')console.error(`Port ${port} is already in use. No new preview was started.
Stop the older server with Ctrl+C, or run: npm run preview -- --port ${port<65535?port+1:4174}
Do not open the old tab and assume it is this build.`);
 else console.error('Preview could not start: '+error.message);
 process.exitCode=1;
});
server.listen(port,host,()=>console.log(`Kurdistan VPN website ${info.websiteVersion}
Project directory: ${path.dirname(root)}
Build ID: ${buildId}
Open this exact address: http://${host}:${port}${info.base}en/
Stop with Ctrl+C.`));
for(const signal of ['SIGTERM','SIGINT'])process.on(signal,()=>server.close(()=>process.exit(0)));
