from pathlib import Path
import zipfile,json,re,sys,base64,math
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import tempfile
R=Path(__file__).resolve().parents[1];temp=tempfile.TemporaryDirectory(prefix='kurd-baseline-');base=Path(temp.name)/'baseline'
if not base.exists():
 base.mkdir()
 with zipfile.ZipFile(R/'references/BASELINE_WEBSITE_PROJECT.zip') as z:
  for n in z.namelist():
   if n.startswith('KurdistanVPN_Website/dist/'):
    rel=n.split('KurdistanVPN_Website/dist/',1)[1];p=base/rel
    if not n.endswith('/'):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(z.read(n))
sys.path.insert(0,str(R/'tests'));import harness
# Count geometry actually painted, not the number of CSS declarations.
MEASURE='''()=>{const out=[];for(const e of document.querySelectorAll('body *')){if(!e.checkVisibility({checkVisibilityCSS:true})||e.closest('svg'))continue;const b=e.getBoundingClientRect(),s=getComputedStyle(e);if(b.width<200||b.width<(e.parentElement?.clientWidth||b.width)*.65)continue;for(const edge of ['Top','Bottom']){const width=parseFloat(s['border'+edge+'Width']);if(width>0&&s['border'+edge+'Style']!=='none'&&s['border'+edge+'Color']!=='rgba(0, 0, 0, 0)')out.push({tag:e.tagName,selector:e.className,edge,width:Math.round(b.width)});}}return out;}'''
def html_file(path):
 soup=BeautifulSoup(path.read_text(),'html.parser')
 for script in soup(['script']):script.decompose()
 for link in list(soup.find_all('link',rel='stylesheet')):
  f=base/link['href'].split('/kurdistan-protocol-compiler/',1)[-1];tag=soup.new_tag('style');tag.string=f.read_text();link.replace_with(tag)
 for img in soup.find_all('img'):
  u=img.get('src','');f=base/u.split('/kurdistan-protocol-compiler/',1)[-1]
  if f.is_file():img['src']='data:image/'+('svg+xml' if f.suffix=='.svg' else 'webp')+';base64,'+base64.b64encode(f.read_bytes()).decode()
 return str(soup)
records=[]
with sync_playwright() as p:
 b=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox']);page=b.new_page(viewport={'width':1440,'height':950},reduced_motion='reduce')
 for route in ['','product','trust','self-host','docs/profile']:
  before=base/'en'/route/'index.html';after=R/'dist/en'/route/'index.html'
  page.set_content(html_file(before));old=page.evaluate(MEASURE)
  harness.open_memory(page,'en/'+route,interactive=False);new=page.evaluate(MEASURE)
  records.append({'route':route or 'home','before':len(old),'after':len(new),'remaining':new})
 b.close()
(R/'qa/line-audit.json').write_text(json.dumps({'method':'Visible non-SVG elements >=200px and >=65% parent width. Count actual top/bottom border edges separately, default collapsed disclosures;1440px, no-JS both candidates. A bounded proxy for wide rules, not a count of every decorative mark.', 'records':records},indent=2))
md=['# LINE AND SEPARATOR AUDIT — Phase 2','','Method: rendered1440px pages, no-JS in both baseline and current build, native disclosures in default state. Count top/bottom border edges on visible non-SVG elements at least200px and65% of parent width. This is a reproducible wide-rule proxy, not a claim about every painted line or subjective calmness. Source entries are in line-audit.json.','','| Page | Before | After |','|---|---:|---:|']
md += [f"| {x['route']} | {x['before']} | {x['after']} |" for x in records]
md += ['','The change removes repeated claim-row/explorer/disclosure strips. Whitespace, type scale, indentation and quiet fields now carry those relationships. The required percentage was not mechanically targeted. Native no-JS shows all ownership panels, so counts differ from the selected-panel interactive composition.','','Remaining categories: the header edge identifies persistent navigation; the footer marks the closing region; table/input edges distinguish data entry and tabular cells; code/context boundaries clarify command scope; occasional major-section rules distinguish a semantic break. Focus outlines and internal architecture connector lines have purposes and were not counted as horizontal separators.','', 'Review limitation: automated border geometry is supplementary. The final screenshots and recorded visual review determine whether grouping remains clear.']
(R/'qa/LINE_AND_SEPARATOR_AUDIT.md').write_text('\n'.join(md)+'\n')
# Compare normal authored prose, not duplicated translation/footer count inflation.
def prose(folder):
 result={}
 for f in sorted((folder/'en').rglob('index.html')):
  soup=BeautifulSoup(f.read_text(),'html.parser');m=soup.find('main')
  if not m:continue
  for n in m(['script','style','svg','code','pre']):n.decompose()
  result[str(f.relative_to(folder/'en'))]=m.get_text(' ',strip=True)
 return result
old=prose(base);new=prose(R/'dist');common=sorted(set(old)&set(new))
oldtext=' '.join(old[k] for k in common);newtext=' '.join(new[k] for k in common)
patterns=['seamlessly','cutting-edge','next-generation','empower users','unlock your','game-changing','revolutionary','at its core','underscores','stands as a testament','in today']
report={'scope':'Visible static main content across comparable English routes, including closed-disclosure text; excludes code/footer/script/metadata. Counts are editorial indicators, not an AI detector.','pages':len(common),'beforeWords':len(oldtext.split()),'afterWords':len(newtext.split()),'emDashesBefore':oldtext.count('—'),'emDashesAfter':newtext.count('—'),'clicheHits':{v:len(re.findall(re.escape(v),newtext,re.I)) for v in patterns}}
(R/'qa/copy-audit.json').write_text(json.dumps(report,indent=2))
(R/'qa/HUMAN_COPY_AUDIT.md').write_text(f'''# HUMAN COPY AUDIT — Phase 2

The provided Wikipedia “Signs of AI writing” advice page was read as a stylistic aid, not a rulebook or detector. Its caveats matter: the listed patterns are observations and are not proof of authorship. No AI-detector score is used. Reference: https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing

## Exact edits
“Explore the model” became an ownership-specific action. “App & status” became “Android & releases.” “+ Menu” became a conventional menu icon plus label. A lone evidence plus became “View evidence” with a chevron and proper disclosure semantics. Repeated pre-release/demo captions named by the brief were removed from the storytelling surface; release limits remain in the relevant Android/release documents. The demo still says no VPN traffic and does not impersonate networking.

The strongest headline remains. Owner explanations now state who controls a component and where that control ends, rather than repeatedly using “X. Not Y.” slogans. The provided4principles and creator dedication are deliberately not rewritten. Technical commands/identifiers are unchanged; detailed mechanisms stay within disclosure/source material.

## Bounded counts
Comparable routes: {len(common)}. Main prose words: {report['beforeWords']} before, {report['afterWords']} after. Em dashes: {report['emDashesBefore']} before, {report['emDashesAfter']} after. Count scope excludes footer/code/metadata but includes authored closed-disclosure text. These are not token-count performance metrics or a claim every sentence became shorter. A new hero explanation and complete site-level simple-mode copy legitimately add information; total word count alone is not the acceptance test. Counts and cliché flags are in copy-audit.json.

## Editorial decisions
Repetition is reduced where it merely restates labels. Necessary security caveats remain, even when they cannot be turned into a short slogan. No testimonials, performance measurements, releases or audits were invented to make copy persuasive. Button labels predict an actual route/action. Help starts with ordinary user questions and preserves explicit recovery guidance.

Sorani and Kurmanji were authored as complete target text rather than English-filled placeholder keys. Repeated terminology is documented in docs/LOCALIZATION.md. Machine-completeness and a bilingual editorial pass do not establish native-human approval. Actual native readers must still check grammar, register, technical equivalence and dedication meaning using HUMAN_VALIDATION.md.

The remaining risk is technical prose density on reference pages and translations that a native editor may improve. It is documented, not hidden behind a fake “human-written” certificate.
''')
print('Audits',records,report)

temp.cleanup()
