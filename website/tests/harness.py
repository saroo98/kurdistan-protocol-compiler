"""Offline rendering harness for managed environments that block all browser URLs.

This does NOT bypass browser policies. It uses Playwright's supported in-memory
set_content API on about:blank, with supplied local assets. HTTP/CSP/navigation
and field/network performance are separately reported and are NOT proven here.
Only local static-index transport and iframe srcdoc transport are substituted.
"""
from pathlib import Path
import re,json,base64,mimetypes
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[1]
DIST=ROOT/'dist'
INFO=json.loads((DIST/'build-info.json').read_text())
BASE=INFO['base']

def local_path(url):
    return DIST/(url[len(BASE):] if url.startswith(BASE) else url.lstrip('/'))

def script_bundle(path,seen=None):
    seen=seen if seen is not None else set()
    path=path.resolve()
    if path in seen:return ''
    seen.add(path)
    text=path.read_text()
    imported=[]
    for match in re.finditer(r"import\s+[^;]+?\s+from\s+['\"]([^'\"]+)['\"];?",text):
        imported.append(script_bundle(path.parent/match[1],seen))
    text=re.sub(r"import\s+[^;]+?\s+from\s+['\"]([^'\"]+)['\"];?",'',text)
    text=re.sub(r'(?m)^export\s+','',text)
    return '\n'.join(imported)+'\n'+text

def inline_document(file,prototype=False,interactive=True,fixture_transport=True):
    html=Path(file).read_text()
    soup=BeautifulSoup(html,'html.parser')
    for link in list(soup.find_all('link',rel='stylesheet')):
        url=link.get('href','')
        path=(Path(file).parent/url) if prototype else local_path(url)
        style=soup.new_tag('style');style.string=path.read_text();link.replace_with(style)
    for img in soup.find_all('img'):
        url=img.get('src','')
        if not url or url.startswith('data:'):continue
        path=(Path(file).parent/url) if prototype else local_path(url)
        if path.is_file():
            mime=mimetypes.guess_type(path)[0] or 'application/octet-stream'
            img['src']='data:'+mime+';base64,'+base64.b64encode(path.read_bytes()).decode()
    modules=[]
    for script in list(soup.find_all('script')):
        if script.get('type')=='application/ld+json':continue
        if not interactive:script.decompose();continue
        src=script.get('src')
        if not src:continue
        file_path=Path(file).parent/src if prototype else local_path(src)
        if script.get('type')=='module':
            modules.append(script_bundle(file_path));script.decompose()
        else:script.attrs={};script.string=file_path.read_text().replace('</script>','<\\/script>')
    if not prototype and interactive:
        transport=''
        if fixture_transport:
            index_url=soup.body.get('data-search-index',BASE+'search-index-en.json')
            data=local_path(index_url).read_text()
            transport=f"const __index={data};window.fetch=async(input)=>{{if(String(input).includes('search-index-'))return new Response(JSON.stringify(__index),{{status:200,headers:{{'Content-Type':'application/json'}}}});throw Error('Offline harness: no network requests permitted');}};"
        bundle='\n'.join(modules)
        if 'data-demo' in html:
            doc=inline_document(DIST/'prototype/index.html',prototype=True)
            # QA-only in-memory document transport: never weaken the production sandbox.
            bundle=bundle.replace("frame.src=document.body.dataset.base+'prototype/index.html';","frame.srcdoc=window.__prototypeDoc;")
            transport+='window.__prototypeDoc='+json.dumps(doc).replace('<','\\u003c')+';'
        tag=soup.new_tag('script');tag.string='(function(){'+transport+'\n'+bundle+'\n})();';soup.body.append(tag)
    return str(soup)

def open_memory(page,route='',interactive=True):
    route=route.strip('/')
    file=DIST/'en'/route/'index.html'
    if route.split('/')[0] in ('en','ckb','kmr'):file=DIST/route/'index.html'
    page.set_content(inline_document(file,interactive=interactive),wait_until='load')
    page.wait_for_timeout(80)
    return page
