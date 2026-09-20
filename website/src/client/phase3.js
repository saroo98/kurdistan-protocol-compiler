/** Small, no-network enhancements: one session entrance, one accessible capability dialog. */
export function setupPhase3(){
 const dialog=document.getElementById('protocol-dialog');let opener=null;
 const buttons=[...document.querySelectorAll('[data-protocol-open]')];
 const close=()=>{if(dialog?.open)dialog.close();};
 buttons.forEach(button=>button.addEventListener('click',event=>{event.preventDefault();if(!dialog)return;opener=button;buttons.forEach(b=>b.setAttribute('aria-expanded','true'));dialog.showModal();dialog.querySelector('[data-protocol-close]')?.focus();}));
 dialog?.querySelector('[data-protocol-close]')?.addEventListener('click',close);
 dialog?.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)close();}});
 dialog?.addEventListener('close',()=>{buttons.forEach(b=>b.setAttribute('aria-expanded','false'));opener?.focus({preventScroll:true});});
 const search=dialog?.querySelector('[data-protocol-search]');
 search?.addEventListener('input',()=>{const q=search.value.normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase().trim();let count=0;dialog.querySelectorAll('[data-protocol-id]').forEach(row=>{row.hidden=!row.querySelector('h3').textContent.normalize('NFKD').replace(/\p{M}/gu,'').toLowerCase().includes(q);if(!row.hidden)count++;});dialog.querySelector('[data-protocol-empty]').hidden=count>0;});
 const media=matchMedia('(prefers-reduced-motion: reduce)');
 const reduce=()=>media.matches||document.documentElement.dataset.motion==='reduce'||document.documentElement.dataset.mode==='simple';
 const emblem=document.querySelector('[data-sun-entrance]');
 if(emblem){let seen=false,timer=0;try{seen=sessionStorage.getItem('kurd-sun-entrance-v3')==='seen';sessionStorage.setItem('kurd-sun-entrance-v3','seen');}catch{}
  const settle=()=>{clearTimeout(timer);emblem.dataset.sunState='on';};
  const play=()=>{settle();if(reduce())return;emblem.dataset.sunState='waking';timer=setTimeout(settle,2600);};
  if(!seen)play();else settle();
  document.querySelector('[data-sun-replay]')?.addEventListener('click',()=>{settle();requestAnimationFrame(()=>requestAnimationFrame(play));});
  media.addEventListener('change',()=>{if(reduce())settle();});new MutationObserver(()=>{if(reduce())settle();}).observe(document.documentElement,{attributes:true,attributeFilter:['data-mode','data-motion']});
 }
 const field=document.querySelector('[data-hero-selection]');
 document.querySelectorAll('[data-hero-info]').forEach(a=>a.addEventListener('click',()=>{
  if(field)field.dataset.heroSelection=a.dataset.heroInfo;
  document.querySelectorAll('[data-hero-info]').forEach(b=>b.setAttribute('aria-pressed',String(a===b)));
  document.querySelectorAll('[data-hero-panel]').forEach(panel=>panel.hidden=panel.dataset.heroPanel!==a.dataset.heroInfo);
 }));
}
