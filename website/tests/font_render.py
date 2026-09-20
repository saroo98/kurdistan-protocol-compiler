"""Optional private original-font rendering. No font bytes are written to outputs.
Usage: python tests/font_render.py --font-dir /path/with/originals
This is a rendering test, not a licence or native-language approval.
"""
import argparse,base64,json,hashlib
from pathlib import Path
from playwright.sync_api import sync_playwright
from harness import ROOT,open_memory
P=argparse.ArgumentParser();P.add_argument('--font-dir',required=True);args=P.parse_args()
fonts=[('Kurd Display','k-magroon.woff2','ff8fbd8a47e349dbbcff768acab4d8d66f27961c9288135ea4041efcca873ca4'),('Kurd Reading','shasenem-kiteb.woff2','1598bddc4f79386c9975342f9a39b2f18ded7994d3e60a992b3107dc3ad9fbd0')]
css='';hashes={};memory_faces=[]
for family,name,digest in fonts:
 data=(Path(args.font_dir)/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest;hashes[name]=digest
 memory_faces.append({'family':family,'bytes':base64.b64encode(data).decode()})
 css+="@font-face{font-family:'"+family+"';src:url(data:font/woff2;base64,"+base64.b64encode(data).decode()+") format('woff2');font-weight:400;font-style:normal;font-display:swap}"
rows=[]
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
 for width,route in [(320,'ckb'),(360,'ckb'),(390,'ckb/trust'),(430,'ckb/self-host'),(1440,'ckb'),(360,'ckb/simple')]:
  page=b.new_page(viewport={'width':width,'height':1000},reduced_motion='reduce');open_memory(page,route);page.evaluate("document.querySelectorAll('style').forEach(s=>{if(s.textContent.includes('@font-face'))s.textContent=s.textContent.replace(/@font-face\\{[^}]*\\}/g,'')})")
  page.evaluate("""async faces=>{for(const item of faces){const f=new FontFace(item.family,Uint8Array.from(atob(item.bytes),c=>c.charCodeAt(0)).buffer,{weight:'400'});await f.load();document.fonts.add(f);}}""",memory_faces)
  loaded=page.evaluate('''async()=>{const a=await document.fonts.load('32px "Kurd Display"'),b=await document.fonts.load('18px "Kurd Reading"');await document.fonts.ready;return a.length>0&&b.length>0;}''');assert loaded,'Both supplied faces must actually load'
  assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'),f'{route}@{width}'
  if width in [360,1440] and route=='ckb':page.screenshot(path=str(ROOT/f'qa/screenshots/private-font-ckb-{width}.png'))
  rows.append({'route':route,'width':width,'bothFontsLoaded':loaded,'overflow':False});page.close()
 b.close()
report={'passed':True,'scope':'Supplied original fonts injected privately into current built Sorani bodies. Not the binary-free portable build, not hosted font networking and not human review.','fontHashes':hashes,'cases':rows,'templateCSSSha256':hashlib.sha256((ROOT/'src/styles/phase2.css').read_bytes()).hexdigest()}
(ROOT/'qa/font-render-report.json').write_text(json.dumps(report,indent=2));print('Private supplied-font rendering:6 layouts passed, both faces loaded. No font bytes written to screenshots/reports.')
