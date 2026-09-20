/* Browser-only presentation. All measurements are deterministic synthetic examples. */
(function(){
 'use strict';
 const words={
  en:{test:'Test all latency',cancel:'Cancel test',testing:'Testing',sort:'Sort by latency',low:'Lowest first',high:'Highest first',untested:'Not tested',timeout:'Timeout',invalid:'Invalid',cancelled:'Cancelled',simulated:'Simulated latency. No network requests.',search:'Search profiles or groups',groups:'Groups',details:'Profile details',fresh:'Last simulated test',none:'No test yet',done:'Test complete',skipped:'Not usable'},
  ckb:{test:'دواکەوتنی هەموویان تاقی بکەرەوە',cancel:'تاقیکردنەوە هەڵبوەشێنەوە',testing:'تاقیدەکرێتەوە',sort:'ڕیزکردن بەپێی دواکەوتن',low:'کەمترین سەرەتا',high:'زۆرترین سەرەتا',untested:'تاقی نەکراوەتەوە',timeout:'کات تەواو بوو',invalid:'نایەکسان',cancelled:'هەڵوەشێنرایەوە',simulated:'دواکەوتنی نموونەییە. هیچ داواکارییەک بۆ تۆڕ نانێردرێت.',search:'لە پرۆفایل و گرووپەکان بگەڕێ',groups:'گرووپەکان',details:'وردەکاریی پرۆفایل',fresh:'دوا تاقیکردنەوەی نموونەیی',none:'هێشتا تاقی نەکراوەتەوە',done:'تاقیکردنەوە تەواو بوو',skipped:'بەکارنایەت'},
  kmr:{test:'Derengiya hemûyan biceribîne',cancel:'Ceribandinê betal bike',testing:'Tê ceribandin',sort:'Li gor derengiyê rêz bike',low:'Kêmtirîn pêşî',high:'Zêdetirîn pêşî',untested:'Nehatiye ceribandin',timeout:'Dem qediya',invalid:'Nederbasdar',cancelled:'Betalkirî',simulated:'Derengiya simulekirî. Daxwazên torê nayên şandin.',search:'Li profîl û koman bigere',groups:'Kom',details:'Hûrguliyên profîlê',fresh:'Ceribandina simulekirî ya dawî',none:'Hêj nehat ceribandin',done:'Ceribandin qediya',skipped:'Nayê bikaranîn'}
 };
 const c=()=>DemoCopy[app.settings.language]||DemoCopy.en;
 const w=key=>(words[app.settings.language]||words.en)[key];
 const label=key=>E(c()[key]);
 const activityCopy={en:{latency:'Latency',download:'Download',upload:'Upload'},ckb:{latency:'دواکەوتن',download:'داگرتن',upload:'بارکردن'},kmr:{latency:'Derengî',download:'Daxistin',upload:'Barkirin'}};
 const activityLabel=key=>E((activityCopy[app.settings.language]||activityCopy.en)[key]);
 function homeLatency(p,on){
  const result=results.get(p.id);
  if(!ProfileView.usable(p)||['timeout','invalid'].includes(result?.state))return '-1 ms';
  if(result?.state==='ok')return result.ms+' ms';
  if(result?.state==='testing')return '…';
  if(!on)return '—';
  const hash=[...p.id].reduce((a,c)=>((a*31+c.charCodeAt(0))>>>0),7);
  return (18+hash%240)+' ms';
 }
 const originalBrand=brand;
 brand=small=>originalBrand(small).replace('Kurdistan VPN','KurdistanVPN').replace(/(<img[^>]*>)/,'<span class="demo-logo-mark">$1</span>');
 let selectedMethod='kurd';
 const method=()=>DemoMethods.find(p=>p.id===selectedMethod)||DemoMethods[0];
 const originalToolbar=toolbar;
 toolbar=function(spec,gm){
  if(!gm&&(spec.id.startsWith('home-')||['home','profiles','settings'].includes(spec.id)))return `<header class="toolbar profiles-toolbar">${brand()}<div class="profile-top-actions"><button class="icon-button" data-go="scan-qr" aria-label="${label('scanQr')}">${I('qr')}</button><button class="icon-button primary-icon" data-action="profiles-add" aria-label="${label('add')}">${I('plus')}</button></div></header>`;
  return originalToolbar(spec,gm);
 };
 const sun=()=>'<span class="refined-mini-sun" aria-hidden="true"><svg viewBox="-56 -56 112 112">'+Array.from({length:21},(_,i)=>{const a=-Math.PI/2+i*Math.PI*2/21,d=Math.PI/21/2.8;return '<polygon points="'+[[(Math.cos(a-d)*22),(Math.sin(a-d)*22)],[Math.cos(a)*46,Math.sin(a)*46],[Math.cos(a+d)*22,Math.sin(a+d)*22]].map(p=>p.map(n=>n.toFixed(2)).join(',')).join(' ')+'"/>'}).join('')+'<circle class="sun-core" r="20"/></svg></span>';
 const stateName=()=>connected(app)?'connected':isBusy()?'connecting':app.session.status==='IDLE'?'disconnected':'attention';
 const protocolMark=()=>method().id==='kurd'?sun():method().logo?`<img class="protocol-project-logo" src="protocol-logos/${E(method().logo)}" width="30" height="30" alt="" decoding="async">`:'';
 function detailButton(key,body){return `<button type="button" data-refine-screen="${key}" data-focus-key="home-${key}${body.includes('protocol-lockup')?'-metric':''}" aria-label="${label('detailTitle'+key[0].toUpperCase()+key.slice(1))}">${body}${I('chevron')}</button>`;}
 function home(s){
  const p=KurdState.active(s);if(!p)return ROUTES.get('home-empty').render(s,ui);
  const state=stateName(),on=connected(s),busy=isBusy();
  return `<div class="refined-home" data-connection="${state}"><div class="refined-state"><h1>${label(state)}</h1><button class="refined-connect" data-action="${on?'disconnect':busy?'cancel-connect':'connect'}" aria-label="${label(on?'disconnect':busy?'cancel':'connect')}" aria-pressed="${on}">${sun()}</button></div><p class="refined-helper">${label(on?'active':busy?'working':state==='attention'?'problem':'ready')}</p>
   <button class="refined-profile" data-go="profiles"><span class="current-profile-name"><small>${label('using')}</small><strong>${E(p.alias)}</strong><small>${E(p.condition==='valid'?c().verified:p.condition==='expired'?c().expired:w('invalid'))}</small></span><span class="current-profile-latency"><small>${activityLabel('latency')}</small><b dir="ltr" data-home-latency>${homeLatency(p,on)}</b></span>${I('chevron')}</button>
   <div class="refined-route">${detailButton('device',I('phone')+'<span>'+label('phone')+'</span>')}<span aria-hidden="true"></span>${detailButton('protocol',protocolMark()+'<span dir="ltr">'+E(method().name)+'</span>')}<span aria-hidden="true"></span>${detailButton('server',I('nodes')+'<span>'+label('server')+'</span>')}</div>
   <div class="refined-metrics">${detailButton('session','<span>'+label('duration')+'</span><strong class="mono" data-duration dir="ltr">'+duration(s)+'</strong>')}${detailButton('protocol','<span>'+label('protocol')+'</span><strong class="protocol-lockup" dir="ltr">'+E(method().name)+'</strong>')}</div>
   <dl class="refined-transfer"><div><dt>${activityLabel('download')}</dt><dd dir="ltr" data-transfer="download">${on?'1.24 <small>MB/s</small>':'—'}</dd></div><div><dt>${activityLabel('upload')}</dt><dd dir="ltr" data-transfer="upload">${on?'86 <small>KB/s</small>':'—'}</dd></div></dl>
   <div class="refined-primary"><button class="btn" data-action="${on?'disconnect':busy?'cancel-connect':'connect'}">${label(on?'disconnect':busy?'cancel':'connect')}</button></div></div>`;
 }
 for(const route of ROUTES.values())if(route.id.startsWith('home-')&&route.id!=='home-empty')route.render=home;
 let returnFocus='';
 const familyKey={native:'Native',tunnels:'Tunnels',proxy:'Proxy',quic:'Quic',standards:'Standards'};
 const profileCount=id=>{const p=DemoMethods.find(p=>p.id===id),count=app.profiles.filter(profile=>[id,p.name.toLowerCase()].includes(String(profile.protocol).trim().toLowerCase())).length;const forms={en:['profile','profiles'],ckb:['پرۆفایل','پرۆفایل'],kmr:['profîl','profîl']}[app.settings.language]||['profile','profiles'];return new Intl.NumberFormat(app.settings.language).format(count)+' '+forms[count===1?0:1];};
 page('protocol-picker','Protocol','home','Connection',()=>`<div class="protocol-picker"><div class="protocol-picker-heading"><h1>${label('protocol')}</h1><button class="icon-button" data-go="protocol-guide" aria-label="${label('detailTitleProtocol')}">${I('info')}</button></div><p class="small">${label('methodBoundary')}</p><div class="protocol-options">${DemoMethods.map(p=>`<button type="button" data-action="choose-demo-protocol" data-value="${E(p.id)}" aria-pressed="${selectedMethod===p.id}"><strong dir="ltr">${E(p.name)}</strong><span class="protocol-profile-count">${E(profileCount(p.id))}</span><span class="radio ${selectedMethod===p.id?'selected':''}" aria-hidden="true"></span></button>`).join('')}</div></div>`);
 page('protocol-guide','Protocol','protocol-picker','Connection',()=>`<div class="protocol-guide"><h1>${label('detailTitleProtocol')}</h1><p class="small">${label('methodBoundary')}</p>${DemoMethods.map(p=>`<section><h2 dir="ltr">${E(p.name)}</h2><p>${label('family'+familyKey[p.family]+'Body')}</p></section>`).join('')}</div>`);
 // Selection changes only this browser preview, never a signed profile.
 HANDLERS['choose-demo-protocol']=button=>{const id=button.dataset.value;if(!DemoMethods.some(p=>p.id===id))return;if(connected(app))HANDLERS.disconnect();else if(isBusy())HANDLERS['cancel-connect']();selectedMethod=id;navTo('home');device.querySelector('[data-focus-key="home-protocol-metric"]')?.focus({preventScroll:true});};
 for(const key of ['session','device','server']){
  const suffix=key[0].toUpperCase()+key.slice(1);
  page('detail-'+key,'Details','home','Connection',()=>`<div class="refined-detail"><h1>${label('detailTitle'+suffix)}</h1>${key==='protocol'?'<div class="detail-emblem">'+sun()+'<strong>Kurd</strong><span>'+label('nativeLabel')+'</span></div>':I(key==='server'?'nodes':key==='device'?'phone':'info')}<p>${label('detailBody'+suffix)}</p>${key==='session'?'<strong class="session-readout mono" data-duration dir="ltr">'+duration(app)+'</strong>':''}<div class="note"><p>${label('detailNote'+suffix)}</p></div><button class="btn outline" data-refine-back>${label('backHome')}</button></div>`);
 }
 document.addEventListener('click',event=>{
  const trigger=event.target.closest('[data-refine-screen]');
  if(trigger){returnFocus=trigger.dataset.focusKey;navTo(trigger.dataset.refineScreen==='protocol'?'protocol-picker':'detail-'+trigger.dataset.refineScreen);}
  if(event.target.closest('[data-refine-back]')){navTo('home');device.querySelector(`[data-focus-key="${returnFocus}"]`)?.focus({preventScroll:true});}
 },true);
 const priorBack=HANDLERS.back;
 HANDLERS.back=()=>{if(ui.route.startsWith('detail-')){navTo('home');device.querySelector(`[data-focus-key="${returnFocus}"]`)?.focus({preventScroll:true});}else priorBack();};

 // Result storage is deliberately separate from profile authority and selection.
 const results=new Map();let timer=0,run=0,testing=false,done=0,total=0,queue=[],frozenOrder=null;
 const oldBuild=ProfileView.build;
 ProfileView.build=function(profiles,options={}){
  let ordered=profiles;
  if(testing&&frozenOrder)ordered=[...profiles].sort((a,b)=>(frozenOrder.get(a.id)??Infinity)-(frozenOrder.get(b.id)??Infinity));
  else if(['latency-low','latency-high'].includes(options.sort)){
   ordered=[...profiles].sort((a,b)=>{const x=results.get(a.id),y=results.get(b.id),ax=x?.state==='ok',by=y?.state==='ok';if(ax!==by)return ax?-1:1;if(!ax)return 0;return options.sort==='latency-low'?x.ms-y.ms:y.ms-x.ms;});
  }
  return oldBuild(ordered,{...options,sort:testing?'original':options.sort});
 };
 const oldItem=renderProfileItem;
 renderProfileItem=function(item,index,totalRows,virtual,rowHeight){
  if(item.kind==='group')return oldItem(item,index,totalRows,virtual,rowHeight);
  const p=item.profile,r=results.get(p.id),usable=ProfileView.usable(p),failed=!usable||['timeout','invalid'].includes(r?.state),status=failed?'-1 ms':r?.state==='ok'?r.ms+' ms':r?.state==='testing'?'…':'—',description=!usable?(p.condition==='expired'?c().expired:w('invalid')):w(r?.state||'untested');
  return `<div class="compact-profile ${p.id===app.selected?'is-selected':''}" role="listitem" aria-posinset="${index+1}" aria-setsize="${totalRows}" data-profile-key="${E(p.id)}" ${virtual?`style="position:absolute;inset-inline:0;top:${index*rowHeight}px;height:${rowHeight}px"`:''}>
   <button class="compact-profile-body" data-go="profile-details" data-profile-id="${E(p.id)}" data-focus-key="profile:${E(p.id)}" ${p.id===app.selected?'aria-current="true"':''} aria-label="${E(p.alias)}, ${E(status==='—'?description:status)}, ${E(w('details'))}"><span class="profile-name">${E(p.alias)}</span><span class="profile-metadata" dir="ltr">${E(p.protocol)}</span></button>
   <span class="profile-latency ${failed?'failed':usable&&r?.state==='ok'?'measured':''}" title="${E(failed||status==='—'?description:w('simulated'))}" aria-label="${E(failed?description:status)}" dir="ltr">${E(status)}</span>
   <button class="profile-row-action" data-go="profile-details" data-profile-id="${E(p.id)}" data-focus-key="info:${E(p.id)}" aria-label="${E(w('details'))}: ${E(p.alias)}">${I('info')}</button></div>`;
 };
 const oldProfiles=ROUTES.get('profiles').render;
 ROUTES.get('profiles').render=(s,u)=>oldProfiles(s,u).replace('<div class="profile-summary-line">',`<div class="latency-tools"><button data-action="${testing?'latency-cancel':'latency-test'}">${E(w(testing?'cancel':'test'))}</button><select aria-label="${E(w('sort'))}" data-latency-sort ${testing?'disabled':''}><option value="original">${E(w('sort'))}</option><option value="latency-low" ${u.profileSort==='latency-low'?'selected':''}>${E(w('low'))}</option><option value="latency-high" ${u.profileSort==='latency-high'?'selected':''}>${E(w('high'))}</option></select></div><p class="latency-note">${E(w('simulated'))}</p><p class="latency-progress" role="status" aria-live="polite">${total?E(w(testing?'testing':done===total?'done':'cancelled'))+' '+done+' / '+total:''}</p><div class="profile-summary-line">`);
 const oldDetails=ROUTES.get('profile-details').render;
 ROUTES.get('profile-details').render=(s,u)=>{const result=results.get(pFor(s).id);return oldDetails(s,u)+D([[w('fresh'),result?.at?new Intl.DateTimeFormat(s.settings.language,{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(result.at):w('none')],[w('simulated'),result?.state==='ok'?result.ms+' ms':w(result?.state||'untested')]]);};
 function refresh(){if(device.dataset.screen==='profiles')render(true);}
 function cancel(){run++;clearTimeout(timer);testing=false;for(const id of queue){if(results.get(id)?.state==='testing')results.set(id,{state:'cancelled'});}queue=[];frozenOrder=null;refresh();}
 function next(token){
  if(token!==run||!testing)return;
  for(const id of queue.splice(0,Math.min(20,Math.max(4,Math.ceil(total/30))))){
   const p=app.profiles.find(p=>p.id===id);if(p){const hash=[...id].reduce((a,c)=>((a*31+c.charCodeAt(0))>>>0),7);results.set(id,!ProfileView.usable(p)?{state:'invalid',at:Date.now()}:hash%13===0?{state:'timeout',at:Date.now()}:{state:'ok',ms:18+hash%240,at:Date.now()});}done++;
  }
  if(!queue.length){testing=false;frozenOrder=null;}refresh();
  if(testing)timer=setTimeout(()=>next(token),160);
 }
 HANDLERS['latency-test']=()=>{if(testing)return;run++;done=0;total=app.profiles.length;queue=app.profiles.map(p=>p.id);frozenOrder=new Map(profileView(app,ui).rows.filter(r=>r.kind==='profile').map((r,i)=>[r.profile.id,i]));testing=true;for(const p of app.profiles)results.set(p.id,{state:'testing'});refresh();timer=setTimeout(()=>next(run),160);};
 HANDLERS['latency-cancel']=cancel;
 document.addEventListener('change',event=>{if(!event.target.matches('[data-latency-sort]')||testing)return;const value=event.target.value;if(['original','latency-low','latency-high'].includes(value)){ui.profileSort=value;profileUI.scroll=0;render(true);}});
 const reset=KurdDemo.reset;KurdDemo.reset=()=>{cancel();results.clear();total=done=0;selectedMethod='kurd';reset();};
 // Keep new labels translated in the inherited list, without altering user names.
 const previousRender=render;
 render=function(preserve=false){previousRender(preserve);const input=device.querySelector('#profile-search');if(input){input.placeholder=w('search');input.setAttribute('aria-label',w('search'));}device.querySelectorAll('.locale-note').forEach(n=>{if(device.dataset.screen.startsWith('home-')||device.dataset.screen.startsWith('detail-'))n.remove();});};
 KurdDemo.latency=()=>({testing,done,total,results:[...results],simulation:true});
 KurdDemo.render=()=>render();
})();
