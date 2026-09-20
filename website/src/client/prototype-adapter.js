/* Hosted adapter for the sanitized public demo.
   Keep the preview isolated and label synthetic states; never claim a live VPN. */
(function(){
 'use strict';
 const safe = text => String(text).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function exactSun(){const points=Array.from({length:42},(_,i)=>{const a=i*Math.PI/21,r=i%2?50:100;return (120+Math.sin(a)*r).toFixed(4)+','+(120-Math.cos(a)*r).toFixed(4)}).join(' ');return '<svg class="kurd-sun-svg hosted-sun" viewBox="0 0 240 240" aria-hidden="true"><polygon points="'+points+'"/></svg>';}
 function polish(){
  const s=KurdDemo.getState(),on=['ACTIVE_KURD_LIVE','ACTIVE_KURD_LOOPBACK'].includes(s.session.status),busy=['CONNECTING','RECONNECTING','FALLING_BACK','RECOVERING'].includes(s.session.status);
  document.querySelectorAll('.sun-control,.path-sun').forEach(el=>{el.classList.remove('is-on','is-off','is-error','is-connecting');el.classList.add(on?'is-on':busy?'is-connecting':'is-off');el.innerHTML=exactSun();if(el.tagName==='BUTTON')el.setAttribute('aria-checked',String(on));});
  // An active fallback selection is NOT an established tunnel.
  document.querySelector('.prototype-stamp')?.remove();
  const gm=document.querySelector('.gm-appliance');if(gm&&!gm.querySelector('.hosted-gm-sun')){const el=document.createElement('div');el.className='hosted-gm-sun '+(on?'is-on':busy?'is-connecting':'is-off');el.innerHTML=exactSun();gm.querySelector('.gm-appliance-content')?.prepend(el);}
  document.querySelectorAll('select[data-pref=language] option').forEach(o=>{if(['fa','ar'].includes(o.value))o.remove();});
  document.documentElement.dataset.previewState=s.session.status;
  const screen=KurdDemo.getUI().route;
  parent.postMessage({type:'kurd-preview-state',state:on?'connected':busy?'connecting':s.session.status==='IDLE'?'disconnected':'attention',screen},'*');
 }
 const original=render;render=function(preserve=false){original(preserve);polish()};
 // The legacy listener reads location.hash, unavailable in the opaque in-memory
 // router. Restore the route from the bounded history entry instead.
 window.addEventListener('popstate',event=>{
  if(window.parent===window)return;
  event.stopImmediatePropagation();
  const route=event.state?.route;
  ui.historyDepth=event.state?.depth||0;
  ui.route=typeof route==='string'&&validRoute(route)?route:'home';
  render();
 },true);
 document.body.classList.add('hosted-preview');
 document.addEventListener('click',event=>{const a=event.target.closest('a[href^="https:"]');if(a){event.preventDefault();event.stopImmediatePropagation();parent.postMessage({type:'kurd-preview-source'},'*')}},true);
 function applyPreferences(data){
  const state=KurdDemo.getState();
  if(['en','ckb','kmr'].includes(data.locale))state.settings.language=data.locale;
  if(['light','dark'].includes(data.theme))state.settings.theme=data.theme;
  state.settings.reducedMotion=data.reduced===true;state.settings.textSize=data.largeText===true?'large':'default';state.settings.highContrast=data.contrast===true;
  KurdDemo.setState(state);
 }
 window.addEventListener('message',event=>{
  if(event.source!==parent||!event.data)return;
  if(event.data.type==='kurd-preview-preferences'){applyPreferences(event.data);render(true);return;}
  if(event.data.type!=='kurd-preview-v1')return;
  const command=event.data.command;
  if(!['disconnected','connecting','connected','attention','profiles','trust','grandma'].includes(command))return;
  KurdDemo.reset();
  applyPreferences(event.data);
  if(command==='grandma')KurdDemo.scenario('grandma');
  else if(command==='profiles')KurdDemo.go('profiles');
  else if(command==='trust')KurdDemo.explore('trust-fingerprint');
  else if(command==='connecting'){
   KurdDemo.explore('home-connecting');
   // A manually selected preview state stays visible until the visitor changes it.
   cancelSessionTimer();
  }
  else KurdDemo.scenario(command==='attention'?'revoked':command);
  render();
 });
 try{KurdDemo.reset()}catch{render()}
 polish();parent.postMessage({type:'kurd-preview-ready'},'*');
})();
