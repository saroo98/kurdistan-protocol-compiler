"""Record what is actually available. A blocked/missing engine is not counted as a pass."""
import json,time,subprocess,socket,os,urllib.request,platform
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1];info=json.loads((ROOT/'dist/build-info.json').read_text());sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
server=subprocess.Popen(['node','scripts/serve.mjs'],cwd=ROOT,env={**os.environ,'HOST':'127.0.0.1','PORT':str(port)},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
report={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'platform':platform.platform(),'python':platform.python_version(),'node':subprocess.check_output(['node','--version'],text=True).strip(),'npm':subprocess.check_output(['npm','--version'],text=True).strip(),'engines':{},'urlPolicy':'No policy was disabled or bypassed.'}
try:
 url=f'http://127.0.0.1:{port}'+info['base']+'en/'
 for _ in range(60):
  try:
   with urllib.request.urlopen(url,timeout=.4) as r:report['httpStatus']=r.status
   break
  except Exception:time.sleep(.08)
 with sync_playwright() as p:
  for name in ['chromium','firefox','webkit']:
   try:
    opts={'headless':True}
    if name=='chromium' and Path('/usr/bin/chromium').exists():opts.update(executable_path='/usr/bin/chromium',args=['--no-sandbox'])
    b=getattr(p,name).launch(**opts);entry={'installed':True,'version':b.version};report['engines'][name]=entry;page=b.new_page()
    try:page.goto(url,wait_until='load',timeout=8000);entry['httpNavigation']='available'
    except Exception as e:entry['httpNavigation']='blocked or failed';entry['error']=str(e)[:1400]
    page.close();page=b.new_page();page.set_content('<main><h1>In-memory render check</h1></main>');entry['memoryRender']=page.locator('h1').inner_text()=='In-memory render check';b.close();report['engines'][name]=entry
   except Exception as e:report['engines'][name]={'installed':False,'error':str(e)[:600]}
finally:
 server.terminate();server.wait(timeout=4);(ROOT/'qa/environment-report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
