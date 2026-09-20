"""Render the authored three-locale social image family without remote assets.
Optional PRIVATE_FONT_DIR is for local QA rendering only; font bytes are never
written to HTML templates or distributed. Public templates use local() families.
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
import math,html,json,base64,os
ROOT=Path(__file__).resolve().parents[1]
POINTS=' '.join(f'{120+math.sin(i*math.pi/21)*(50 if i%2 else 100):.4f},{120-math.cos(i*math.pi/21)*(50 if i%2 else 100):.4f}' for i in range(42))
DATA={
'product': [('OWNERSHIP','Know who holds\nthe keys.','A profile-driven, self-hosted system.'),('خاوەندارێتی','بزانە کلیلەکان\nلە دەستی کێن.','سیستەمێکی خۆبەڕێوەبردوو کە بە پرۆفایل کار دەکات.'),('XWEDÎTÎ','Bizane mifte\ndi destê kê de ne.','Pergaleke xwemêvandar ku bi profîlan dixebite.')],
'self-host':[('SELF-HOSTING','Run your own\ndeployment.','Installation, operation and recovery.'),('خۆبەڕێوەبردن','سیستەمی خۆت\nبەڕێوە ببە.','دامەزراندن، بەڕێوەبردن و گەڕاندنەوە.'),('XWEMÊVANDARÎ','Sazkirina xwe\nbirêve bibe.','Sazkirin, birêvebirin û vegerandin.')],
'security':[('TRUST & EVIDENCE','Read the claim.\nInspect the evidence.','The mechanism, its limits and its source.'),('متمانە و بەڵگە','بانگەشەکە بخوێنەوە.\nبەڵگەکە بپشکنە.','چۆن کار دەکات، سنوورەکانی و سەرچاوەکەی.'),('BAWERÎ Û BELGE','Îdiayê bixwîne.\nBelgeyê lêkolîn bike.','Şêwaza xebatê, sînor û çavkaniya wê.')],
'simple':[('GRANDMA MODE','A simpler website.\nA clear next step.','Larger text and fewer choices.'),('دۆخی سادە','ماڵپەڕێکی سادەتر.\nهەنگاوێکی ڕوون.','نووسینی گەورەتر و هەڵبژاردەی کەمتر.'),('MODA SADE','Malpereke hêsantir.\nGaveke zelal.','Nivîsa mezintir û vebijêrkên kêmtir.')],
'releases':[('RELEASES','Check the\nrelease evidence.','Read availability, source and verification.'),('بڵاوکردنەوەکان','بەڵگەکانی بڵاوکردنەوە\nبپشکنە.','بەردەستبوون، سەرچاوە و پشتڕاستکردنەوە بخوێنەوە.'),('WEŞAN','Belgeyên weşanê\nkontrol bike.','Berdestbûn, çavkanî û piştrastkirinê bixwîne.')],
'docs':[('DOCUMENTATION','Start with the job\nyou need to do.','Profiles, deployment and recovery.'),('بەڵگەنامەکان','لەو کارەوە دەست پێ بکە\nکە پێویستتە.','پرۆفایل، دامەزراندن و گەڕاندنەوە.'),('BELGE','Bi karê ku divê bikî\ndest pê bike.','Profîl, sazkirin û vegerandin.')]
}
CSS="""*{box-sizing:border-box}body{margin:0;background:#fafaf6;color:#202820;font-family:Arial,Helvetica,sans-serif;padding:54px 68px;height:630px}.brand{display:flex;align-items:center;gap:13px;font-size:23px}.brand svg{width:34px;height:34px}.eyebrow{font-size:13px;letter-spacing:1px;color:#596356;margin-top:66px}h1{font-size:62px;letter-spacing:-2.7px;line-height:1.13;font-weight:500;margin:25px 0;max-width:880px}p{font-size:22px;color:#596356;max-width:860px}.sun{position:absolute;inset-inline-end:65px;top:65px;width:86px;height:86px;fill:#febd11;stroke:#755005;stroke-width:.5}.foot{position:absolute;bottom:38px;inset-inline-start:68px;inset-inline-end:68px;padding-top:18px;font-size:13px;color:#596356}body[dir=rtl]{font-family:'shasenem-kiteb',Tahoma,sans-serif}body[dir=rtl] h1{font-family:'Unikurd Magroon',Tahoma,sans-serif;font-size:66px;font-weight:400;line-height:1.4;letter-spacing:0;margin:15px 0}body[dir=rtl] .eyebrow{margin-top:30px;font-size:18px;letter-spacing:0}body[dir=rtl] p{font-size:25px}.brand span{font-family:Arial,sans-serif}body[dir=rtl] .foot{font-size:17px}"""
def private_css():
 folder=Path(os.environ.get('PRIVATE_FONT_DIR','/nonexistent'))
 rules=[]
 for family,name in [('Unikurd Magroon','k-magroon.woff2'),('shasenem-kiteb','shasenem-kiteb.woff2')]:
  f=folder/name
  if f.is_file():rules.append("@font-face{font-family:'"+family+"';src:url(data:font/woff2;base64,"+base64.b64encode(f.read_bytes()).decode()+") format('woff2');font-weight:400}")
 return ''.join(rules)
def main():
 (ROOT/'src/social').mkdir(exist_ok=True)
 mark=(ROOT/'public/assets/kurdistan-mark.svg').read_text().replace('fill="#16BFAE"','fill="#202820"')
 with sync_playwright() as p:
  b=p.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH','/usr/bin/chromium'),headless=True,args=['--no-sandbox'])
  page=b.new_page(viewport={'width':1200,'height':630},device_scale_factor=1)
  for key,variants in DATA.items():
   for i,locale in enumerate(['en','ckb','kmr']):
    eyebrow,title,sub=variants[i];direction='rtl' if locale=='ckb' else 'ltr'
    foot=['Documentation and source at Kurdistan VPN','بەڵگەنامە و سەرچاوە لە Kurdistan VPN','Belge û çavkanî li Kurdistan VPN'][i]
    doc=f'<!doctype html><html lang="{locale}" dir="{direction}"><head><meta charset="utf-8"><title>{html.escape(title.replace(chr(10)," "))}</title><style>{CSS}</style></head><body dir="{direction}"><div class="brand">{mark}<span>Kurdistan <b>VPN</b></span></div><div class="eyebrow">{eyebrow}</div><h1>{html.escape(title).replace(chr(10),"<br>")}</h1><p>{sub}</p><svg class="sun" viewBox="0 0 240 240" aria-hidden="true"><polygon points="{POINTS}"/></svg><div class="foot">{foot}</div></body></html>'
    (ROOT/f'src/social/{key}-{locale}.html').write_text(doc)
    page.set_content(doc)
    if locale=='ckb':
     folder=Path(os.environ.get('PRIVATE_FONT_DIR','/nonexistent'));faces=[]
     for family,filename in [('Unikurd Magroon','k-magroon.woff2'),('shasenem-kiteb','shasenem-kiteb.woff2')]:
      font=folder/filename
      if font.is_file():faces.append({'family':family,'bytes':base64.b64encode(font.read_bytes()).decode()})
     if faces:page.evaluate("""async faces=>{for(const item of faces){const f=new FontFace(item.family,Uint8Array.from(atob(item.bytes),c=>c.charCodeAt(0)).buffer,{weight:'400'});await f.load();document.fonts.add(f);}}""",faces)
    page.evaluate('document.fonts.ready');page.screenshot(path=ROOT/f'public/assets/social-{key}-{locale}.png')
  b.close()
 print('Rendered 18 authored 1200 × 630 locale-specific social images; no font binaries in templates.')
if __name__=='__main__':main()
