import {msg,announce} from './locale.js';
export function setupPreferences(){
 const root=document.documentElement;const key='kurdistan-site-preferences';
 function save(){try{localStorage.setItem(key,JSON.stringify({theme:root.dataset.theme||'system',largeText:root.dataset.text==='large',contrast:root.dataset.contrast==='strong',simple:root.dataset.mode==='simple',reducedMotion:root.dataset.motion==='reduce'}));}catch{announce(msg('Your browser did not save this preference. It still applies to this page.'));}}
 function reflect(){
  document.querySelectorAll('[data-theme-choice]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.themeChoice===(root.dataset.theme||'system'))));
  for(const [selector,field,value]of [['[data-contrast]','contrast','strong'],['[data-larger-text]','text','large'],['[data-grandma]','mode','simple'],['[data-reduced-motion]','motion','reduce']])document.querySelectorAll(selector).forEach(c=>c.checked=root.dataset[field]===value);
  document.querySelectorAll('[data-simple-depth]').forEach(d=>d.open=root.dataset.mode!=='simple');
 }
 document.querySelectorAll('[data-theme-choice]').forEach(b=>b.addEventListener('click',()=>{if(b.dataset.themeChoice==='system')delete root.dataset.theme;else root.dataset.theme=b.dataset.themeChoice;reflect();save();announce(msg('Website appearance changed. Your VPN is unchanged.'));}));
 for(const [selector,field,value]of [['[data-contrast]','contrast','strong'],['[data-larger-text]','text','large'],['[data-grandma]','mode','simple'],['[data-reduced-motion]','motion','reduce']])document.querySelectorAll(selector).forEach(c=>c.addEventListener('change',()=>{if(c.checked)root.dataset[field]=value;else delete root.dataset[field];reflect();save();announce(msg('Reading preferences updated. Your VPN is unchanged.'));}));
 document.querySelectorAll('[data-full-site]').forEach(b=>b.addEventListener('click',()=>{delete root.dataset.mode;reflect();save();document.querySelectorAll('.preferences[open]').forEach(d=>{d.open=false;d.querySelector('summary').focus();});announce(msg('Full website restored. Your VPN is unchanged.'));}));
 document.querySelectorAll('[data-language-choice]').forEach(a=>a.addEventListener('click',()=>{try{localStorage.setItem('kurdistan-site-language',a.dataset.languageChoice);}catch{}}));
 // Only an explicit previously stored choice can change the root entry document.
 if(document.body.hasAttribute('data-locale-entry'))try{const l=localStorage.getItem('kurdistan-site-language');if(['ckb','kmr'].includes(l))location.replace(document.body.dataset.base+l+'/');}catch{}
 reflect();
 const menus=[...document.querySelectorAll('.preferences,.language-menu,.mobile-menu')];
 menus.forEach(d=>d.addEventListener('toggle',()=>{if(d.open)menus.filter(x=>x!==d).forEach(x=>x.open=false);}));
 document.addEventListener('click',e=>menus.filter(d=>d.open&&!d.contains(e.target)).forEach(d=>d.open=false));
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!document.querySelector('dialog[open]')){const d=menus.find(x=>x.open);if(d){d.open=false;d.querySelector('summary').focus();e.preventDefault();}}});
 document.querySelectorAll('.language-panel').forEach(nav=>nav.addEventListener('keydown',e=>{const links=[...nav.querySelectorAll('a')],i=links.indexOf(document.activeElement);let next;if(e.key==='ArrowDown')next=(i+1)%links.length;else if(e.key==='ArrowUp')next=(i+links.length-1)%links.length;else if(e.key==='Home')next=0;else if(e.key==='End')next=links.length-1;else return;e.preventDefault();links[next].focus();}));
}
