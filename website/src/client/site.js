import {setupPhase3} from './phase3.js';
import {setupPreferences} from './preferences.js';
import {setupOwnership} from './ownership.js';
import {setupSearch} from './search.js';
import {setupChecksum} from './checksum.js';
import {setupPreview} from './preview.js';
import {msg,announce} from './locale.js';
setupPreferences();setupPhase3();setupOwnership();setupSearch();setupChecksum();setupPreview();document.documentElement.classList.add('enhanced');
document.querySelectorAll('[data-back-top]').forEach(a=>a.addEventListener('click',event=>{event.preventDefault();const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches||document.documentElement.dataset.motion==='reduce'||document.documentElement.dataset.mode==='simple';window.scrollTo({top:0,behavior:reduced?'instant':'smooth'});document.getElementById('top')?.focus({preventScroll:true});}));
async function copy(button){const source=document.getElementById(button.dataset.copy);if(!source)return;let success=false;try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(source.textContent);success=true;}}catch{}
 if(!success){const selection=getSelection(),range=document.createRange();range.selectNodeContents(source);selection.removeAllRanges();selection.addRange(range);announce(msg('Automatic copy is unavailable. The command is selected for manual copying.'));return;}
 const label=button.querySelector('span');if(label)label.textContent=msg('Copied');button.setAttribute('aria-label',msg('Command copied'));announce(msg('Command copied. Read the prerequisites before running it.'));setTimeout(()=>{if(label)label.textContent=msg('Copy');button.removeAttribute('aria-label');},1800);
}
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',()=>copy(b)));
document.querySelectorAll('[data-print]').forEach(b=>b.addEventListener('click',()=>window.print()));
const status=document.querySelector('[data-offline-status]');
document.querySelector('[data-offline-save]')?.addEventListener('click',async event=>{const button=event.currentTarget;
 if(!('serviceWorker' in navigator)||!window.isSecureContext){status.textContent=msg('Offline saving needs HTTPS or localhost. Use your browser’s Save page or Print instead.');return;}
 button.disabled=true;status.textContent=msg('Saving public guides on this device…');
 try{await navigator.serviceWorker.register(document.body.dataset.base+'service-worker.js',{scope:document.body.dataset.base});await navigator.serviceWorker.ready;status.textContent=msg('Guides saved on this device. They are dated copies, not live release information.');}
 catch{status.textContent=msg('The guides could not be saved. Your VPN is unchanged. Check the connection or use Save page.');}
 finally{button.disabled=false;}
});
document.querySelector('[data-offline-remove]')?.addEventListener('click',async()=>{try{if('serviceWorker' in navigator){const scope=new URL(document.body.dataset.base,location.origin).href;for(const r of await navigator.serviceWorker.getRegistrations())if(r.scope===scope)await r.unregister();}if('caches' in window)for(const name of await caches.keys())if(name.startsWith('kurdistan-guides-'+encodeURIComponent(document.body.dataset.base)+'-'))await caches.delete(name);status.textContent=msg('Saved website guides removed. No VPN or profile settings changed.');}catch{status.textContent=msg('Browser storage settings prevented removal. Remove this website’s data in your browser settings.');}});
