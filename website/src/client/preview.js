import {msg} from './locale.js';
const COMMANDS=new Set(['disconnected','connecting','connected','attention','profiles','trust','grandma']);
export function setupPreview(){
 document.querySelectorAll('[data-demo]').forEach(root=>{
  const host=root.querySelector('[data-demo-host]'),feedback=root.querySelector('[data-demo-feedback]');
  let frame=null,ready=false,loadTimeout=0,pending=COMMANDS.has(root.dataset.demoInitial)?root.dataset.demoInitial:'disconnected';
  const appearance=matchMedia('(prefers-color-scheme: dark)'),motion=matchMedia('(prefers-reduced-motion: reduce)');
  const preferences=()=>({locale:document.body.dataset.locale,theme:document.documentElement.dataset.theme||(appearance.matches?'dark':'light'),reduced:document.documentElement.dataset.motion==='reduce'||document.documentElement.dataset.mode==='simple'||motion.matches,largeText:document.documentElement.dataset.text==='large',contrast:document.documentElement.dataset.contrast==='strong'});
  function send(command){if(ready&&COMMANDS.has(command))frame.contentWindow.postMessage({type:'kurd-preview-v1',command,...preferences()},'*');}
  const sync=()=>{if(ready)frame.contentWindow.postMessage({type:'kurd-preview-preferences',...preferences()},'*');};
  new MutationObserver(sync).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme','data-motion','data-mode','data-text','data-contrast']});
  appearance.addEventListener('change',sync);motion.addEventListener('change',sync);
  function mount(){
   if(frame)return;frame=document.createElement('iframe');frame.title=msg('Kurdistan VPN app demo. No network protection.');
   frame.sandbox='allow-scripts allow-downloads';frame.referrerPolicy='no-referrer';frame.src=document.body.dataset.base+'prototype/index.html';
   feedback.textContent=msg('Loading the local design preview…');host.append(frame);root.dataset.demoReady='loading';
   loadTimeout=setTimeout(()=>{if(!ready){feedback.replaceChildren(document.createTextNode(msg('The preview did not become ready. The product explanation and help links still work.')));const retry=document.createElement('button');retry.type='button';retry.className='text-link';retry.textContent=msg('Retry preview');retry.addEventListener('click',()=>{frame?.remove();frame=null;mount();},{once:true});feedback.append(retry);root.dataset.demoReady='error';}},10000);
  }
  if('IntersectionObserver' in window){const observer=new IntersectionObserver(entries=>{if(entries.some(e=>e.isIntersecting)){mount();observer.disconnect();}},{rootMargin:'800px 0px'});observer.observe(root);}else mount();
  root.querySelectorAll('[data-demo-command]').forEach(button=>{button.setAttribute('aria-pressed',String(button.dataset.demoCommand===pending));button.addEventListener('click',()=>{
   pending=button.dataset.demoCommand;mount();send(pending);root.querySelectorAll('[data-demo-command]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));
   feedback.textContent=msg('App demo: {state}. No VPN traffic.',{state:button.textContent.trim()});
  });});
  window.addEventListener('message',event=>{
   if(!frame||event.source!==frame.contentWindow||event.data?.type!=='kurd-preview-state')return;
   const {state,screen}=event.data;
   if(!['disconnected','connecting','connected','attention'].includes(state)||typeof screen!=='string'||screen.length>80)return;
   const selected=screen.startsWith('grandma')?'grandma':screen==='profiles'?'profiles':screen.startsWith('trust')?'trust':screen.startsWith('home')?state:null;
   root.dataset.demoState=state;
   root.querySelectorAll('[data-demo-command]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.demoCommand===selected)));
   const label=root.querySelector(`[data-demo-command="${state}"]`)?.textContent.trim();
   if(label)feedback.textContent=msg('App demo: {state}. No VPN traffic.',{state:label});
  });
  window.addEventListener('message',event=>{
   if(!frame||event.source!==frame.contentWindow||event.data?.type!=='kurd-preview-ready')return;
   clearTimeout(loadTimeout);ready=true;root.dataset.demoReady='true';host.querySelector('.demo-poster')?.remove();feedback.textContent=msg('Preview ready. All data and VPN activity are simulated.');send(pending);
  });
  window.addEventListener('message',event=>{
   if(!frame||event.source!==frame.contentWindow||event.data?.type!=='kurd-preview-source')return;
   feedback.replaceChildren(document.createTextNode(msg('This reference points outside the app demo. ')));const a=document.createElement('a');a.href='https://github.com/saroo98/kurdistan-protocol-compiler';a.textContent=msg('View on GitHub');a.target='_blank';a.rel='noopener noreferrer';feedback.append(a);
  });
 });
}
