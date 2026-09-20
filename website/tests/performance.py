"""Measure the production output, not dev mode. Explicitly separate budgets/local HTTP
from field CWV. Optional --live runs real browser navigation and records lab LCP/CLS.
No field INP or percentile claims are inferred from a local render.
"""
import argparse,json,gzip,time,statistics,socket,subprocess,urllib.request,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];DIST=ROOT/'dist';Q=ROOT/'qa'
info=json.loads((DIST/'build-info.json').read_text(encoding='utf-8'));p=argparse.ArgumentParser();p.add_argument('--live',action='store_true');p.add_argument('--base-url');args=p.parse_args()
BUDGET=json.loads((ROOT/'performance-budgets.json').read_text(encoding='utf-8'))
report={'scope':'production artifact budgets and loopback HTTP; not network CWV','passed':False,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'browserCWV':'not measured','fieldLCP':None,'fieldINP':None,'fieldCLS':None,'limits':['No real-user 75th-percentile data.','No mobile network or physical-device performance established.','Loopback HTTP excludes DNS, TLS, device rendering and public hosting.']}
files=list(DIST.rglob('*'));assets=[]
for f in files:
 if f.is_file() and f.suffix in ('.js','.css') and 'prototype' not in f.parts:
  raw=f.read_bytes();assets.append({'path':str(f.relative_to(DIST)),'bytes':len(raw),'gzipBytes':len(gzip.compress(raw,mtime=0))})
report['assets']=assets;report['cssGzipBytes']=sum(x['gzipBytes'] for x in assets if x['path'].endswith('.css'));report['javascriptGzipBytes']=sum(x['gzipBytes'] for x in assets if x['path'].endswith('.js') and x['path']!='service-worker.js');report['portableFontFiles']=sum(1 for f in files if f.suffix in ('.woff','.woff2','.ttf','.otf'));report['thirdPartyResourceRequestsDesigned']=0
sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
server=subprocess.Popen(['node','scripts/serve.mjs'],cwd=ROOT,env={**os.environ,'PORT':str(port),'HOST':'127.0.0.1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(60):
  try:urllib.request.urlopen(f'http://127.0.0.1:{port}'+info['base'],timeout=.3).read();break
  except Exception:time.sleep(.08)
 else:raise RuntimeError('Production server did not become ready')
 samples=[]
 for route in [l+'/'+s for l in ['en','ckb','kmr'] for s in ['','download','docs']]:
  url=f'http://127.0.0.1:{port}'+info['base']+route.rstrip('/')+'/'
  timings=[];size=0
  for n in range(12):
   req=urllib.request.Request(url,headers={'Accept-Encoding':'gzip'});start=time.perf_counter()
   with urllib.request.urlopen(req,timeout=5) as response:
    body=response.read();size=len(body)
    if response.headers.get('Content-Encoding')!='gzip':raise AssertionError('No gzip on HTML')
   timings.append(round((time.perf_counter()-start)*1000,3))
  samples.append({'route':route or 'home','gzipHTMLBytes':size,'coldLoopbackMs':timings[0],'warmMedianLoopbackMs':round(statistics.median(timings[1:]),3),'allLoopbackMs':timings})
 report['http']=samples
 assert report['cssGzipBytes']<BUDGET['cssGzipBytes'],'CSS budget exceeded'
 assert report['javascriptGzipBytes']<BUDGET['javascriptGzipBytes'],'JavaScript budget exceeded'
 assert all(x['gzipHTMLBytes']<BUDGET['htmlGzipBytes'] for x in samples),'Landing HTML budget exceeded'
 assert (DIST/'assets/prototype-home.webp').stat().st_size<BUDGET['posterBytes'],'Poster budget exceeded'
 # Optional real-navigation lab mode: errors must remain failures, never replace with memory metrics.
 if args.live:
  from playwright.sync_api import sync_playwright
  report['lab']=[]
  with sync_playwright() as pw:
   options={'headless':True}
   if Path('/usr/bin/chromium').exists():options.update(executable_path='/usr/bin/chromium',args=['--no-sandbox'])
   browser=pw.chromium.launch(**options)
   for route in ['','download','docs']:
    page=browser.new_page(viewport={'width':390,'height':844},device_scale_factor=1)
    page.add_init_script("window.__vitals={lcp:0,cls:0};new PerformanceObserver(l=>{for(const e of l.getEntries())window.__vitals.lcp=e.startTime}).observe({type:'largest-contentful-paint',buffered:true});new PerformanceObserver(l=>{for(const e of l.getEntries())if(!e.hadRecentInput)window.__vitals.cls+=e.value}).observe({type:'layout-shift',buffered:true});")
    session=page.context.new_cdp_session(page);session.send('Emulation.setCPUThrottlingRate',{'rate':4});session.send('Network.enable');session.send('Network.emulateNetworkConditions',{'offline':False,'latency':150,'downloadThroughput':200000,'uploadThroughput':100000})
    target=(args.base_url or f'http://127.0.0.1:{port}'+info['base'])+'en/'+(route+'/' if route else '')
    page.goto(target,wait_until='networkidle');page.wait_for_timeout(700);v=page.evaluate('window.__vitals');v.update(route=route or 'home',browser=browser.version,scope='single lab observation; simulated CPU/network, not field data');report['lab'].append(v)
    assert v['lcp']>0 and v['lcp']<=2500,'Lab LCP target not met';assert v['cls']<=.1,'Lab CLS target not met';page.close()
   browser.close()
  report['browserCWV']='lab LCP/CLS only; no field INP';report['scope']+='; optional real-browser lab observations'
 report['passed']=True
except Exception as exc:
 report['failure']=str(exc);print('PERFORMANCE CHECK FAILED:',exc,file=sys.stderr)
finally:
 server.terminate()
 try:server.wait(timeout=3)
 except subprocess.TimeoutExpired:server.kill()
 (Q/('performance-live.json' if args.live else 'performance-report.json')).write_text(json.dumps(report,indent=2));print(json.dumps({k:report[k] for k in ['passed','cssGzipBytes','javascriptGzipBytes','browserCWV']}))
 if not report['passed']:sys.exit(1)
