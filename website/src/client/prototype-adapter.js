/* Hosted adapter for the sanitized public demo.
   Keep the preview isolated and label synthetic states; never claim a live VPN. */
(function(){
 'use strict';
 function polish(){
  const s=KurdDemo.getState(),on=['ACTIVE_KURD_LIVE','ACTIVE_KURD_LOOPBACK'].includes(s.session.status),busy=['CONNECTING','RECONNECTING','FALLING_BACK','RECOVERING'].includes(s.session.status);
  // An active fallback selection is NOT an established tunnel.
  document.querySelector('.prototype-stamp')?.remove();
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
 render();
 polish();parent.postMessage({type:'kurd-preview-ready'},'*');
})();
