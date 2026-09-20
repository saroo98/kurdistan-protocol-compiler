"""Production-body browser QA. Default memory transport is explicitly NOT live E2E.
Run --live --base-url https://host/path/ for real HTTP navigation and CSP execution.
Run --all-engines --live to require Chromium, Firefox and WebKit. Missing engines fail.
No browser policy is disabled. No claim of physical-device or screen-reader testing.
"""
import argparse,json,time,hashlib,sys,os
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from harness import ROOT,DIST,INFO,open_memory,inline_document
P=argparse.ArgumentParser();P.add_argument('--live',action='store_true');P.add_argument('--all-engines',action='store_true');P.add_argument('--base-url',default='http://127.0.0.1:4174'+INFO['base']);P.add_argument('--quick',action='store_true');P.add_argument('--update-baselines',action='store_true');P.add_argument('--captures-only',action='store_true');P.add_argument('--journeys-only',action='store_true');args=P.parse_args()
REPORT={'transport':'HTTP production navigation' if args.live else 'in-memory production bodies; index transport and iframe srcdoc substituted','started':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'browser':{},'layout':[],'journeys':[],'limitations':['No physical devices or human screen-reader/native-writer sessions.','Memory mode does not prove HTTP navigation, CSP, module loading, service workers or network Core Web Vitals.'],'errors':[]}
QA=ROOT/'qa';(QA/'screenshots').mkdir(exist_ok=True,parents=True)
CONTRAST=r'''() => {
 const rgb=s=>{const m=(s.match(/[\d.]+/g)||[]).map(Number),scale=s.startsWith('color(srgb ')?255:1;return [(m[0]||0)*scale,(m[1]||0)*scale,(m[2]||0)*scale,m.length>3?m[3]:1]};
 const blend=(a,b)=>[...a.slice(0,3).map((c,i)=>c*a[3]+b[i]*(1-a[3])),1];
 const lum=c=>c.slice(0,3).map(x=>x/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4).reduce((s,x,i)=>s+x*[.2126,.7152,.0722][i],0);
 const background=el=>{let chain=[];while(el){chain.push(rgb(getComputedStyle(el).backgroundColor));el=el.parentElement;}return chain.reverse().reduce((a,c)=>blend(c,a),[255,255,255,1]);};
 let failures=[],sampled=0;
 for(const el of document.querySelectorAll('body *')){
  if(['SCRIPT','STYLE','SVG','PATH','POLYGON'].includes(el.tagName)||el.closest('svg,dialog:not([open]),[hidden]'))continue;
  if(![...el.childNodes].some(n=>n.nodeType===3&&n.textContent.trim()))continue;
  if(!el.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}))continue;
  const st=getComputedStyle(el),bg=background(el),fg=blend(rgb(st.color),bg),a=lum(fg),b=lum(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05),size=parseFloat(st.fontSize),large=size>=24||(size>=18.66&&+st.fontWeight>=700),need=large?3:4.5;
  sampled++;if(ratio+.03<need)failures.push({text:el.textContent.trim().slice(0,90),ratio:+ratio.toFixed(2),need,color:st.color,background:bg});
 }
 return {sampled,failures};
}'''
LAYOUT=r'''() => ({width:innerWidth,scrollWidth:document.documentElement.scrollWidth,overflow:document.documentElement.scrollWidth>innerWidth+1,h1:document.querySelectorAll('main h1').length,brokenImages:[...document.images].filter(i=>i.getAttribute('src')&&!i.complete||i.complete&&i.naturalWidth===0).map(i=>i.alt),unnamed:[...document.querySelectorAll('button,a,summary')].filter(e=>e.checkVisibility({checkVisibilityCSS:true})&&!e.textContent.trim()&&!e.getAttribute('aria-label')&&!e.querySelector('img[alt]:not([alt=""])')).map(e=>e.outerHTML.slice(0,120))})'''
def expect(ok,msg):
 if not ok:raise AssertionError(msg)
def load(page,route='',interactive=True):
 if args.live:
  suffix=route.strip('/')
  target=args.base_url+(suffix+'/' if suffix.split('/')[0] in ('en','ckb','kmr') else 'en/'+(suffix+'/' if suffix else ''))
  page.goto(target,wait_until='networkidle');return page
 return open_memory(page,route,interactive)
def new(browser,route='',w=1280,h=900,dark=False,interactive=True):
 page=browser.new_page(viewport={'width':w,'height':h},color_scheme='dark' if dark else 'light',reduced_motion='reduce',java_script_enabled=interactive or not args.live)
 page.set_default_timeout(3500);page.on('pageerror',lambda e:REPORT['errors'].append(str(e)));load(page,route,interactive)
 # Force authored lazy images to decode for a whole-document screenshot/asset check.
 page.evaluate('Promise.all([...document.images].map(i=>{i.loading="eager";return i.decode().catch(()=>{})}))')
 return page

def run(browser,engine):
 REPORT['browser'][engine]=browser.version
 check=browser.new_page();check.set_content('<body style="background:color(srgb 1 1 1)"><p style="color:rgb(0,0,0)">Known contrast regression</p></body>');expect(not check.evaluate(CONTRAST)['failures'],'Normalized sRGB contrast parser regression');check.close()
 # Full static-body sweep: English secondary pages receive the same layout checks as Home.
 routes=[r for r in INFO['routes'] if not r.get('alias') and r['file'] not in ['404.html','offline.html']]
 widths=[320,360,390,430,768,1024,1280,1440,1920] if not args.quick else [320,1440]
 for r in ([] if args.captures_only or args.journeys_only else routes):
  slug=r['locale']+'/'+r.get('slug','')
  for width in widths:
   page=new(browser,slug,w=width,h=900)
   l=page.evaluate(LAYOUT);expect(not l['overflow'],f'{slug}@{width}: horizontal overflow {l}');expect(l['h1']==1,f'{slug}: one main H1');expect(not l['brokenImages'],f'{slug}: broken images');expect(not l['unnamed'],f'{slug}: unnamed controls {l["unnamed"]}')
   REPORT['layout'].append({'route':slug,'width':width,'theme':'light','pass':True,'engine':engine});page.close()
 # Dark theme and solid-background text contrast on every route, not only Home.
 for r in ([] if args.captures_only or args.journeys_only else routes):
  slug=r['locale']+'/'+r.get('slug','')
  for dark in [False,True]:
   page=new(browser,slug,w=390,h=844,dark=dark)
   l=page.evaluate(LAYOUT);c=page.evaluate(CONTRAST)
   expect(not l['overflow'],f'{slug} dark layout');expect(not c['failures'],f'{slug} {"dark" if dark else "light"}: contrast {c["failures"]}')
   REPORT['layout'].append({'route':slug,'width':390,'theme':'dark' if dark else 'light','textSamples':c['sampled'],'contrast':'solid-background only','pass':True,'engine':engine});page.close()
 def journey(name,fn):
  try:fn();REPORT['journeys'].append({'name':name,'pass':True,'engine':engine});print('PASS',name,flush=True)
  except Exception as e:REPORT['journeys'].append({'name':name,'pass':False,'error':str(e),'engine':engine});raise
 def keyboard():
  p=new(browser);p.keyboard.press('Tab');expect(p.locator('.skip-link').evaluate('(e)=>e===document.activeElement'),'Skip is first focus');p.keyboard.press('Enter');expect(p.locator('#content').evaluate('(e)=>e===document.activeElement'),'Skip moves focus');
  p.locator('[data-search-open]').click();expect(p.locator('#global-search').evaluate('(e)=>e===document.activeElement'),'Search focused');p.locator('#global-search').fill('profile expired');p.wait_for_timeout(150);expect(p.locator('.search-result').count()>0,'Search finds profile expiry');p.keyboard.press('ArrowDown');expect(p.locator('.search-result').first.evaluate('(e)=>e===document.activeElement'),'Arrow moves to result');p.keyboard.press('Escape');expect(not p.locator('#site-search').is_visible(),'Escape closes');expect(p.locator('[data-search-open]').evaluate('(e)=>e===document.activeElement'),'Focus restored');p.close()
 journey('Keyboard skip, local search, result focus and dialog restoration',keyboard)
 def search():
  p=new(browser,'search');p.locator('#page-search').fill('<img src=x onerror=alert(1)>');p.wait_for_timeout(180);expect(p.locator('.search-empty').count()>0,'No-result feedback');expect(p.locator('[data-page-results] img').count()==0,'Search HTML not executable');p.locator('#page-search').fill('DNS');p.wait_for_timeout(100);expect(p.locator('[data-page-results] .search-result').count()>0,'DNS found');p.close()
 journey('Search filters locally; malicious-looking input is text, with an empty-state route',search)
 def ownership():
  p=new(browser);tabs=p.locator('#ownership [role=tab]');expect(tabs.count()==6,'Six ownership boundaries');tabs.nth(0).focus();p.keyboard.press('ArrowDown');expect(tabs.nth(1).get_attribute('aria-selected')=='true','Ownership next');p.keyboard.press('End');expect(tabs.nth(5).get_attribute('aria-selected')=='true','Ownership end');expect(p.locator('#ownership [role=tabpanel]:visible').count()==1,'One panel');p.keyboard.press('Home');expect(tabs.first.get_attribute('aria-selected')=='true','Ownership home');p.close()
 journey('Ownership explorer arrow/Home/End navigation and selected state',ownership)
 def preferences():
  p=new(browser,w=360,h=800);p.locator('.preferences summary').click();p.locator('[data-theme-choice=dark]').click();expect(p.locator('html').get_attribute('data-theme')=='dark','Dark chosen');p.locator('[data-contrast]').check();p.locator('[data-larger-text]').check();expect(not p.evaluate(LAYOUT)['overflow'],'Large-text preferences reflow');p.keyboard.press('Escape');expect(not p.locator('.preferences').get_attribute('open'),'Escape preferences');expect(p.locator('.preferences summary').evaluate('(e)=>e===document.activeElement'),'Preference focus');p.close()
 journey('Dark mode, contrast, larger text and dismissable preferences on mobile',preferences)
 def nojs():
  for route in ['','trust','docs','self-host','privacy','download','help']:
   p=new(browser,route,w=320,interactive=False);expect(len(p.locator('main').inner_text())>180,'NoJS meaningful content');expect(p.locator('main a').count()>0,'NoJS navigation');expect(not p.evaluate(LAYOUT)['overflow'],'NoJS layout');
   if route=='':expect(p.locator('.ownership-panel:visible').count()==11,'All six control and five privacy boundaries readable withoutJS')
   p.close()
 journey('Core journeys are meaningful, readable and navigable without JavaScript',nojs)
 def reflow():
  for route in ['','self-host','trust','download','verify','help','ckb','kmr']:
   for percent in [200,400]:
    p=new(browser,route,w=1280//(percent//100),h=900);p.add_style_tag(content='html{font-size:32px!important}');expect(not p.evaluate(LAYOUT)['overflow'],f'Text/reflow {route}@{percent}');p.close()
 journey('200/400%-equivalent viewport reflow with 200% text on key routes and all scripts',reflow)
 def reduced():
  p=new(browser);expect(p.evaluate('matchMedia("(prefers-reduced-motion:reduce)").matches'),'Reduced motion active');names=p.evaluate('[...document.querySelectorAll("main *")].filter(e=>getComputedStyle(e).animationName!=="none"&&parseFloat(getComputedStyle(e).animationDuration)>0.01).map(e=>e.className)');expect(not names,f'Unreduced animations {names}');p.emulate_media(forced_colors='active');expect(not p.evaluate(LAYOUT)['overflow'],'Forced colours reflow');p.close()
 journey('Reduced-motion mode and forced-colour layout resilience',reduced)
 def copy():
  p=new(browser,'self-host');p.locator('[data-copy]').first.evaluate("e=>{let p=e.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}}");p.locator('[data-copy]').first.click();expect('copy' in p.locator('#site-announcer').inner_text().lower(),'Copy announcement');expect(p.locator('#host-init').inner_text().count('\\\n')>=3,'Source-checked multiline initialization command');expect('--data-dir /var/lib/kurd-node' in p.locator('#host-init').inner_text(),'Explicit data-dir');p.close()
 journey('Code copy or manual-selection fallback preserves complete source-checked command',copy)
 def hash_validation():
  p=new(browser,'verify');p.locator('#checksum-form button[type=submit]').click();expect(p.locator('#checksum-file').get_attribute('aria-invalid')=='true','File error');p.locator('#checksum-file').set_input_files({'name':'sample.txt','mimeType':'text/plain','buffer':b'abc'});p.locator('#checksum-expected').fill('xyz');p.locator('#checksum-form button[type=submit]').click();expect(p.locator('#checksum-expected').get_attribute('aria-invalid')=='true','Hash input error');p.locator('#checksum-expected').fill(hashlib.sha256(b'abc').hexdigest());p.locator('#checksum-form button[type=submit]').click();p.wait_for_timeout(100)
  if args.live:expect('match' in p.locator('#checksum-output').inner_text().lower(),'Real Web Crypto hash matches')
  else:expect('Web Crypto' in p.locator('#checksum-error').inner_text(),'Unavailable secure context explained truthfully')
  p.close()
 journey('Local checksum form input validation and honest secure-context handling',hash_validation)
 def preview():
  p=new(browser,'product',w=1440,h=1000);expect(p.locator('[data-demo-load]').count()==0,'No click-to-load gate');p.locator('[data-demo]').scroll_into_view_if_needed();p.wait_for_function('document.querySelector("[data-demo-feedback]").textContent.includes("Preview ready")',timeout=6000);frame=p.frames[-1];expect(p.locator('iframe').get_attribute('sandbox')=='allow-scripts allow-downloads','No same-origin sandbox authority');
  for command,expected in [('connected','home-connected'),('attention','home-blocked'),('profiles','profiles'),('trust','trust-fingerprint'),('grandma','grandma-on'),('disconnected','home-disconnected')]:
   p.locator(f'[data-demo-command={command}]').click();p.wait_for_timeout(90);expect(frame.locator('#device').get_attribute('data-screen')==expected,f'Preview {command} reaches {expected}')
  p.locator('[data-demo-command=profiles]').click();p.wait_for_timeout(80);g=frame.locator('.group-toggle').first;was=g.get_attribute('aria-expanded');g.click();expect(g.get_attribute('aria-expanded')!=was,'Group expands/collapses');
  p.locator('[data-demo-command=trust]').click();p.wait_for_timeout(80);expect(frame.locator('[data-action=confirm-trust]').is_disabled(),'Trust default unconfirmed');frame.locator('#trust-check').check();expect(frame.locator('[data-action=confirm-trust]').is_enabled(),'Explicit comparison enables');frame.locator('[data-action=confirm-trust]').click();expect(frame.locator('#device').get_attribute('data-screen')=='import-confirm','Trust advances');frame.locator('[data-action=back]').click();expect(frame.locator('#device').get_attribute('data-screen')=='trust-fingerprint','Sandbox Back navigation');
  p.evaluate('scrollTo(0,0)');p.screenshot(path=str(QA/'screenshots'/'preview-trust.png'),full_page=True);p.close()
 journey('Automatically initialized opaque sandbox, six states, grouping, trust gate and Back',preview)
 def rtl():
  for language,direction in [('ckb','rtl'),('kmr','ltr')]:
   for route in ['', 'trust','self-host','docs/profile','help','simple','verify','404']:
    p=new(browser,language+'/'+route,w=390);expect(p.locator('html').get_attribute('lang')==language,'Locale metadata');expect(p.locator('html').get_attribute('dir')==direction,'Direction');expect('Draft translation' not in p.locator('main').inner_text(),'No draft fallback');expect(not p.evaluate(LAYOUT)['overflow'],'Localized page reflow');p.close()
 journey('Complete Sorani/Kurmanji website routes have correct direction and no draft fallback',rtl)
 def offline():
  p=new(browser,'offline');p.locator('[data-offline-save]').click();p.wait_for_timeout(100)
  if not args.live:expect('HTTPS' in p.locator('[data-offline-status]').inner_text(),'Offline unavailable context explained')
  else:p.wait_for_function('document.querySelector("[data-offline-status]").textContent.includes("saved on this device")',timeout=8000)
  p.close()
 journey('Public-guide saving is opt-in and reports unavailable contexts rather than false success',offline)
 def mobile_controls():
  p=new(browser,w=320,h=740);p.locator('.mobile-menu summary').click();expect(p.locator('.mobile-menu nav').is_visible(),'Mobile menu opens');expect(not p.evaluate(LAYOUT)['overflow'],'Open menu no overflow');p.keyboard.press('Escape');expect(p.locator('.mobile-menu summary').evaluate('(e)=>e===document.activeElement'),'Menu focus restored');p.locator('.preferences summary').click()
  misses=p.evaluate("[...document.querySelectorAll('button, .header-tools > a, .owner-choice, summary')].filter(e=>e.checkVisibility({checkVisibilityCSS:true})).filter(e=>{const r=e.getBoundingClientRect();return r.width<43.9||r.height<43.9}).map(e=>({text:e.textContent.slice(0,40),w:e.getBoundingClientRect().width,h:e.getBoundingClientRect().height}))")
  expect(not misses,'Important standalone target size '+str(misses));p.close()
 journey('Mobile menu, focus return and important standalone touch targets',mobile_controls)
 def failed_index():
  p=new(browser);p.evaluate("() => {window.fetch=async()=>{throw Error('Controlled index failure')}}");p.locator('[data-search-open]').click();p.wait_for_timeout(120);expect('could not be loaded' in p.locator('#global-search-status').inner_text(),'Search failure is explicit');expect(p.locator('.search-dialog-foot a').is_visible(),'Full linked-index fallback retained');p.close()
 journey('Unavailable search index retains a readable recovery destination',failed_index)
 def image_resilience():
  p=new(browser,'product',w=360);p.evaluate("document.querySelectorAll('img').forEach(i=>i.removeAttribute('src'))");expect('design' in p.locator('main').inner_text().lower(),'Product text survives missing images');expect(p.locator('.demo-state-controls').is_visible(),'State controls survive image absence');expect(not p.evaluate(LAYOUT)['overflow'],'Missing image keeps dimensions');p.close()
 journey('Broken or absent images do not remove product explanation or actions',image_resilience)
 def print_action():
  p=new(browser,'docs/profile');p.evaluate('() => {window.__printed=false;window.print=()=>{window.__printed=true}}');expect(not p.evaluate('window.__printed'),'Print not called before click');p.locator('[data-print]').click();expect(p.evaluate('window.__printed'),'Print action wired');p.emulate_media(media='print');expect(p.locator('main').is_visible(),'Print includes content');p.close()
 journey('Documentation print control is wired and print content remains readable',print_action)
 # Shared website behaviours are tested independently in every locale.
 for locale in ['en','ckb','kmr']:
  def language_navigation(locale=locale):
   p=new(browser,locale,w=360,h=800);p.locator('.language-menu summary').click();links=p.locator('.language-panel a');expect(links.count()==3,'Exactly three languages');expect(links.nth(['en','ckb','kmr'].index(locale)).get_attribute('aria-current')=='page','Current locale');links.first.focus();p.keyboard.press('End');expect(links.last.evaluate('e=>e===document.activeElement'),'End key');p.keyboard.press('Home');expect(links.first.evaluate('e=>e===document.activeElement'),'Home key');expect(p.locator('.language-panel img').count()==3,'Local SVG flags');positions=p.locator('.language-panel img').evaluate_all('(es)=>es.map(e=>e.getBoundingClientRect().x)');expect(max(positions)-min(positions)<2,'Flags share one aligned column');p.keyboard.press('Escape');expect(p.locator('.language-menu summary').evaluate('e=>e===document.activeElement'),'Language focus restored');p.close()
  journey(locale+': language selector, flags, selection and keyboard movement',language_navigation)
  def localized_search(locale=locale):
   p=new(browser,locale,w=390);p.locator('[data-search-open]').click();p.locator('#global-search').fill({'en':'profile','ckb':'پرۆفایل','kmr':'profil'}[locale]);p.wait_for_timeout(200);links=p.locator('.search-result');expect(links.count()>0,'Local-language search returns results');expect(all('/'+locale+'/' in u for u in links.evaluate_all('(es)=>es.map(e=>e.getAttribute("href"))')),'Results stay in selected locale');p.close()
  journey(locale+': local search returns same-language pages',localized_search)
  def backtop(locale=locale):
   p=new(browser,locale,w=390,h=844);p.evaluate('scrollTo(0,document.body.scrollHeight)');expect(p.evaluate('scrollY')>500,'Started below fold');p.locator('[data-back-top]').click();p.wait_for_timeout(100);expect(p.evaluate('scrollY')<2,'Back to top moved scroll');expect(p.locator('#top').evaluate('e=>e===document.activeElement'),'Top focus destination');p.close()
  journey(locale+': Back to top scrolls and restores a useful focus destination',backtop)
  def grandma(locale=locale):
   for width in [320,360,640,1440]:
    p=new(browser,locale,w=width,h=900);p.locator('.preferences summary').click();p.locator('[data-grandma]').check();p.keyboard.press('Escape');expect(p.locator('html').get_attribute('data-mode')=='simple','Website simple mode active');expect(p.locator('.site-header .simple-navigation a').count()==3,'Three simple destinations');expect(not p.locator('.desktop-nav').is_visible(),'Full navigation hidden');expect(not p.evaluate(LAYOUT)['overflow'],'Grandma layout');
    p.add_style_tag(content='html{font-size:32px!important}');expect(not p.evaluate(LAYOUT)['overflow'],'Grandma 200% text reflow');p.emulate_media(color_scheme='dark',forced_colors='active');expect(not p.evaluate(LAYOUT)['overflow'],'Grandma dark/forced colour reflow');p.emulate_media(forced_colors='none');p.locator('.preferences summary').click();p.locator('.preferences [data-full-site]').click();expect(p.locator('html').get_attribute('data-mode')!='simple','Full website restored');p.close()
  journey(locale+': Grandma Mode, fewer choices, large text, dark mode and restoration',grandma)
 # Visual baselines are controlled production bodies, reviewed separately by a human/assistant.
 from PIL import Image,ImageChops
 captures=[
 ('en',1440,960,False,'homepage-desktop-en',''),('en',360,840,False,'homepage-mobile-en',''),
 ('ckb',1440,960,False,'homepage-desktop-ckb',''),('ckb',360,840,False,'homepage-mobile-ckb',''),
 ('kmr',1440,960,False,'homepage-desktop-kmr',''),('kmr',360,840,False,'homepage-mobile-kmr',''),
 ('en',1440,960,True,'homepage-dark',''),('en',1440,960,False,'grandma-desktop','simple'),
 ('en',360,840,False,'grandma-mobile','simple'),('ckb',360,840,True,'grandma-sorani','simple'),
 ('kmr',360,840,False,'grandma-kurmanji','simple'),('en/trust',390,844,False,'trust-mobile',''),
 ('ckb/trust',390,844,True,'trust-sorani-dark','proof'),('en/self-host',1280,960,True,'selfhost-desktop-dark',''),
 ('kmr/docs/profile',390,844,False,'docs-kurmanji-mobile',''),('en',1440,1000,False,'footer-desktop','footer'),
 ('ckb',390,1000,False,'footer-mobile-sorani','footer'),('en',1440,960,False,'language-desktop','language'),
 ('ckb',360,840,False,'language-mobile-sorani','language'),('en/product',1280,960,False,'product-desktop',''),
 ('en',1440,960,False,'ownership-evidence','evidence'),('en/404',360,800,False,'error-mobile','')]
 REPORT['visual']=[]
 for slug,w,h,dark,name,mode in captures:
  p=new(browser,slug,w=w,h=h,dark=dark)
  if mode=='simple':p.locator('.preferences summary').click();p.locator('[data-grandma]').check();p.keyboard.press('Escape')
  if mode=='language':p.locator('.language-menu summary').click()
  if mode in ('proof','evidence'):
   d=p.locator('.proof').first
   if d.count():d.locator('summary').click()
  out=QA/'screenshots'/f'{name}.png'
  p.evaluate('window.scrollTo(0,0);document.activeElement?.blur()');p.mouse.move(0,0);p.wait_for_timeout(60)
  if mode=='footer':
   import io
   rect=p.locator('footer').bounding_box();shot=Image.open(io.BytesIO(p.screenshot(full_page=True)));shot.crop((round(rect['x']),round(rect['y']),round(rect['x']+rect['width']),round(rect['y']+rect['height']))).save(out)
  elif mode=='language':p.screenshot(path=str(out))
  else:p.screenshot(path=str(out),full_page=True)
  p.close();baseline=QA/'baselines'/out.name
  if args.update_baselines:baseline.write_bytes(out.read_bytes());status='candidate written, visual review required'
  elif baseline.exists():
   im_a,im_b=Image.open(out).convert('RGB'),Image.open(baseline).convert('RGB');expect(im_a.size==im_b.size,f'Visual dimensions changed: {name}');diff=ImageChops.difference(im_a,im_b);expect(diff.getbbox() is None,f'Visual baseline differs: {name}; review before replacing baseline');status='matched reviewed baseline'
  else:raise AssertionError('Missing reviewed baseline: '+name)
  REPORT['visual'].append({'name':name,'status':status,'route':slug,'width':w,'theme':'dark' if dark else 'light','mode':mode})

try:
 with sync_playwright() as p:
  for engine in (['chromium','firefox','webkit'] if args.all_engines else ['chromium']):
   launcher=getattr(p,engine);options={'headless':True}
   if engine=='chromium' and Path('/usr/bin/chromium').exists():options['executable_path']='/usr/bin/chromium';options['args']=['--no-sandbox']
   browser=launcher.launch(**options)
   try:run(browser,engine)
   finally:browser.close()
 expect(not REPORT['errors'],'Page JavaScript errors: '+str(REPORT['errors']))
 REPORT['passed']=True
except Exception as exc:
 REPORT['passed']=False;REPORT['failure']=str(exc);print('FAIL',exc,file=sys.stderr)
finally:
 REPORT['ended']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());(QA/'browser-report.json').write_text(json.dumps(REPORT,ensure_ascii=False,indent=2));print(json.dumps({'passed':REPORT['passed'],'layoutConfigurations':len(REPORT['layout']),'journeys':len(REPORT['journeys']),'errors':REPORT['errors']}),flush=True)
 if not REPORT['passed']:sys.exit(1)
