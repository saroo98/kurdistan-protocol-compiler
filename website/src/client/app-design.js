window.kurdProtocolLogos=Object.fromEntries(DemoMethods.filter(p=>p.logo).map(p=>[p.id,"protocol-logos/"+p.logo]));
(() => {
'use strict';
const initialRoute=decodeURIComponent(location.hash.slice(1));
const collapsed=new Set();
let filtersOpen=false, testTimer=0;
let previewOffline=!navigator.onLine;
window.addEventListener('online',()=>{previewOffline=false});
const profileContextKey='kurdistan-standalone-list-context-v1';
let profileScroll=0;
try{const saved=JSON.parse(localStorage.getItem(profileContextKey)||'null');if(saved){for(const name of saved.collapsed||[])collapsed.add(name);ui.search['profile-search']=saved.search||'';ui.profileSort=['latency','name','original'].includes(saved.sort)?saved.sort:'latency';ui.profileFilter=saved.filter||'all';profileScroll=Number(saved.scroll)||0}else ui.profileSort='latency'}catch{ui.profileSort='latency'}
function saveListContext(){try{localStorage.setItem(profileContextKey,JSON.stringify({collapsed:[...collapsed],search:ui.search['profile-search']||'',sort:ui.profileSort,filter:ui.profileFilter,scroll:profileScroll}))}catch{}}
const subscriptionUpdates=new Map();
try{for(const [name,value]of JSON.parse(localStorage.getItem('kurdistan-subscription-updates-v1')||'[]'))subscriptionUpdates.set(name,{...value,status:value.status==='updating'?'failed':value.status})}catch{}
function saveSubscriptionUpdates(){try{localStorage.setItem('kurdistan-subscription-updates-v1',JSON.stringify([...subscriptionUpdates]))}catch{}}
document.addEventListener('scroll',e=>{if(e.target?.classList?.contains('screen-main')&&e.target.querySelector('.gold-profiles')){profileScroll=e.target.scrollTop;saveListContext()}},true);
document.addEventListener('input',e=>{if(e.target?.id==='profile-search'){profileScroll=0;saveListContext()}});
const pingResults=new Map();
const latencyLifetime=5*60*1000;
let latencyMeasuredAt=Date.now(),latencyExpiry;
function scheduleLatencyExpiry(){clearTimeout(latencyExpiry);latencyExpiry=setTimeout(()=>render(true),latencyLifetime+50)}
scheduleLatencyExpiry();
// Reconcile the small persistent presentation regions, not the inherited route engine.
function syncNode(current,next){
 if(current.nodeType!==next.nodeType||current.nodeName!==next.nodeName){current.replaceWith(next.cloneNode(true));return}
 if(current.nodeType!==1){if(current.nodeValue!==next.nodeValue)current.nodeValue=next.nodeValue;return}
 for(const a of [...current.attributes])if(!next.hasAttribute(a.name))current.removeAttribute(a.name);
 for(const a of next.attributes)if(current.getAttribute(a.name)!==a.value)current.setAttribute(a.name,a.value);
 const old=[...current.childNodes],fresh=[...next.childNodes];
 for(let i=0;i<Math.max(old.length,fresh.length);i++){
  if(!fresh[i])old[i].remove();else if(!old[i])current.append(fresh[i].cloneNode(true));else syncNode(old[i],fresh[i]);
 }
}
window.kurdSetMarkup=(target,html)=>{
 const template=document.createElement('template');template.innerHTML=html;
 const next=template.content.firstElementChild,current=target.querySelector('.app-screen');
 if(!current||!next){target.innerHTML=html;return}
 // Retain the toolbar and Home controls so CSS transitions have an old state.
 for(const a of [...current.attributes])if(!next.hasAttribute(a.name))current.removeAttribute(a.name);
 for(const a of next.attributes)current.setAttribute(a.name,a.value);
 for(const selector of ['.statusbar','.toolbar','.screen-main','.bottom-nav','.gesture']){
  const old=current.querySelector(selector),fresh=next.querySelector(selector);
  if(!old||!fresh){target.innerHTML=html;return}
  if(selector==='.toolbar'||(selector==='.screen-main'&&old.querySelector('.gold-home')&&fresh.querySelector('.gold-home')))syncNode(old,fresh);
  else old.replaceWith(fresh);
 }
};
const connectionAnnouncement=document.createElement('div');
connectionAnnouncement.className='sr-only';connectionAnnouncement.setAttribute('role','status');
connectionAnnouncement.setAttribute('aria-live','polite');connectionAnnouncement.setAttribute('aria-atomic','true');
document.body.append(connectionAnnouncement);
let lastConnectionAnnouncement='';
Object.assign(ICONS,{
 'subscription-refresh':'<path d="M20 7a8 8 0 0 0-14-2L3 8m0-5v5h5M4 17a8 8 0 0 0 14 2l3-3m0 5v-5h-5"/>',
 'latency-pulse':'<path d="M3 12h4l3-7 4 14 3-7h4"/>',
 'arrow-down':'<path d="M12 3v18m-8-8 8 8 8-8"/>',
 'arrow-up':'<path d="M12 21V3m-8 8 8-8 8 8"/>',
 'clock':'<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
 'more':'<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>'
});
// Demo names are presentation fixtures. All connectable records retain the source's Kurd-only boundary.
const seedKey='kurdistan-standalone-seeded-v1';
let seeded=false;try{seeded=localStorage.getItem(seedKey)==='yes'}catch{}
function seed(){
 const state=KurdState.initial(),basis=state.profiles[0];
 state.profiles=[['home','Home','Personal','valid',34],['frankfurt','Frankfurt','Personal','valid',42],['amsterdam','Amsterdam','Personal','valid',48],['paris','Paris','Personal','valid',55],['backup','Backup','Personal','expired',null],['office','Office','Imported','valid',null],['helsinki','Helsinki','Imported','valid',61]].map(([id,alias,provider,condition,latency])=>({...basis,id,alias,provider,condition,latency,favorite:id==='home',expiry:condition==='expired'?'10 Sep 2026':'30 Sep 2027'}));
 state.selected='home';state.inspected='home';return state;
}
if(!seeded){app=seed();store();try{localStorage.setItem(seedKey,'yes')}catch{}}
const studioSamples=[['studio-zurich','Zurich',28],['studio-london','London',164],['studio-singapore','Singapore',326],['studio-oslo','Oslo',-1],['studio-vienna','Vienna',-1]];
const studioLatencies=new Map(studioSamples.map(([id,,latency])=>[id,latency]));
// Offline country markers are inferred only from synthetic profile labels.
const countryNames={DE:'Germany',NL:'Netherlands',FR:'France',FI:'Finland',CH:'Switzerland',GB:'United Kingdom',SG:'Singapore',NO:'Norway',AT:'Austria',AU:'Australia',US:'United States'};
const countryAliases=[
 ['US',/\b(?:United States(?: of America)?|America|American|New York|Los Angeles)\b/i],
 ['AU',/\b(?:Australia|Australian|Sydney|Melbourne)\b/i],
 ['AT',/\b(?:Austria|Austrian|Vienna|Wien)\b/i],
 ['DE',/\b(?:Germany|German|Frankfurt|Berlin)\b/i],
 ['NL',/\b(?:Netherlands|Dutch|Amsterdam)\b/i],
 ['FR',/\b(?:France|French|Paris)\b/i],
 ['FI',/\b(?:Finland|Finnish|Helsinki)\b/i],
 ['CH',/\b(?:Switzerland|Swiss|Zurich|Zürich)\b/i],
 ['GB',/\b(?:United Kingdom|Britain|British|England|London)\b/i],
 ['SG',/\b(?:Singapore)\b/i],
 ['NO',/\b(?:Norway|Norwegian|Oslo)\b/i]
];
function countryCodeFromName(name){
 if(typeof name!=='string')return null;
 // Explicit upper-case country tokens beat ambiguous city names ("AU Vienna" means AU).
 const tokens=name.match(/(?:^|[^A-Za-z])(?:USA|UK|US|GB|AT|AU|DE|NL|FR|FI|CH|SG|NO)(?=$|[^A-Za-z])/g)||[];
 for(const token of tokens){const code=token.trim().replace(/^[^A-Za-z]+/,'');const canonical=code==='USA'?'US':code==='UK'?'GB':code;if(countryNames[canonical])return canonical}
 return countryAliases.find(([,pattern])=>pattern.test(name))?.[0]||null;
}
function profileCountryCode(p){const raw=typeof p.exitCountry==='string'?p.exitCountry.toUpperCase():'';const explicit=raw==='USA'?'US':raw==='UK'?'GB':raw;return countryNames[explicit]?explicit:countryCodeFromName(p.alias)}
function profileCountryLabel(p){const code=profileCountryCode(p);return code?`estimated country ${countryNames[code]}`:'country unknown'}
function countryMarker(p){
 const code=profileCountryCode(p),name=countryNames[code];
 if(!name)return '<svg class="country-unknown" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c-5 5-5 11 0 16m0-16c5 5 5 11 0 16"/></svg>';
 const rect=(x,y,w,h,fill)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}"/>`;
 const stripes=(colors,vertical=false)=>colors.map((color,i)=>vertical?rect(i*8,0,8,16,color):rect(0,i*16/3,24,16/3,color)).join('');
 const cross=(field,outer,inner)=>rect(0,0,24,16,field)+rect(0,6,24,4,outer)+rect(8,0,4,16,outer)+(inner?rect(0,7,24,2,inner)+rect(9,0,2,16,inner):'');
 const art={DE:()=>stripes(['#202124','#bf3035','#eab844']),NL:()=>stripes(['#ba3743','#fff','#31578e']),FR:()=>stripes(['#315590','#fff','#bd3c46'],true),FI:()=>cross('#fff','#315482'),CH:()=>rect(0,0,24,16,'#bb3541')+rect(10,3,4,10,'#fff')+rect(6,6,12,4,'#fff'),GB:()=>rect(0,0,24,16,'#304976')+'<path d="M0 0 24 16M24 0 0 16" stroke="#fff" stroke-width="4"/><path d="M0 0 24 16M24 0 0 16" stroke="#c33e4b" stroke-width="1.7"/>'+rect(0,6,24,4,'#fff')+rect(10,0,4,16,'#fff')+rect(0,7,24,2,'#c33e4b')+rect(11,0,2,16,'#c33e4b'),SG:()=>rect(0,0,24,8,'#c93e49')+rect(0,8,24,8,'#fff')+'<circle cx="6" cy="4" r="2.5" fill="#fff"/><circle cx="7" cy="3.5" r="2.3" fill="#c93e49"/>',NO:()=>cross('#bd3542','#fff','#344b80'),AT:()=>stripes(['#c3424d','#fff','#c3424d']),US:()=>rect(0,0,24,16,'#fff')+Array.from({length:7},(_,i)=>rect(0,i*32/13,24,16/13,'#bf3541')).join('')+rect(0,0,11,9,'#304b7a')+'<g fill="#fff"><circle cx="2" cy="2" r=".6"/><circle cx="5" cy="2" r=".6"/><circle cx="8" cy="2" r=".6"/><circle cx="3.5" cy="5" r=".6"/><circle cx="6.5" cy="5" r=".6"/><circle cx="9.5" cy="5" r=".6"/></g>',AU:()=>rect(0,0,24,16,'#253d80')+'<path d="M0 0 12 8M12 0 0 8" stroke="#fff" stroke-width="2"/>'+rect(0,3,12,2,'#fff')+rect(5,0,2,8,'#fff')+rect(0,3.6,12,.8,'#bd3946')+rect(5.6,0,.8,8,'#bd3946')+'<g fill="#fff"><circle cx="17" cy="4" r=".9"/><circle cx="20" cy="8" r=".9"/><circle cx="15" cy="12" r=".9"/><circle cx="21" cy="13" r=".9"/></g>'}[code]();
 return `<svg class="country-flag" viewBox="0 0 24 16" aria-hidden="true">${art}</svg>`;
}
const studioSeedKey='kurdistan-standalone-studio-v1';
let studioSeeded=false;try{studioSeeded=localStorage.getItem(studioSeedKey)==='yes'}catch{}
if(!studioSeeded){
 const basis=KurdState.initial().profiles[0];
 for(const [id,alias,latency]of studioSamples)if(!app.profiles.some(p=>p.id===id))app.profiles.push({...basis,id,alias,provider:'Studio',condition:'valid',favorite:false,expiry:'30 Sep 2027',latency:latency<0?null:latency});
 store();try{localStorage.setItem(studioSeedKey,'yes')}catch{}
}
// Timeout is a probe outcome, not an expired or invalid profile.
for(const [id,,latency]of studioSamples)if(latency<0&&app.profiles.some(p=>p.id===id))pingResults.set(id,latency);
// Host state controls reset to the same synthetic showcase as the standalone app.
const showcase=KurdState.clone(app),resetDemo=KurdDemo.reset;
KurdDemo.reset=()=>{clearTimeout(testTimer);testTimer=0;pingResults.clear();for(const [id,,latency]of studioSamples)if(latency<0)pingResults.set(id,latency);resetDemo();app=KurdState.clone(showcase);store();render();};
// Exact 21-ray geometry from the live prototype; explicit coordinates also preserve reduced-motion rendering.
function sun(){const rays=Array.from({length:21},(_,i)=>{const a=-Math.PI/2+i*Math.PI*2/21,spread=Math.PI/21;const point=(angle,r)=>`${(Math.cos(angle)*r).toFixed(2)},${(Math.sin(angle)*r).toFixed(2)}`;return `<polygon points="${point(a-spread/2.8,22)} ${point(a,46)} ${point(a+spread/2.8,22)}"/>`}).join('');return `<svg viewBox="-56 -56 112 112" aria-hidden="true"><g class="sun-rays">${rays}</g><circle class="sun-core sun-fill" r="20"/></svg>`}
function sourceName(p){return p.provider==='My deployment'?'Personal':p.provider||'Imported'}
function ping(p){const r=pingResults.get(p.id);if(r==='testing')return '…';if(r!==undefined)return r<0?'-1 ms':r+' ms';return p.condition!=='valid'?'-1 ms':Number.isFinite(p.latency)?p.latency+' ms':'—'}
function pingHTML(p){const value=ping(p),n=parseFloat(value),state=n<0?'failed':Number.isFinite(n)?n<=100?'fast':n<300?'moderate':'slow':'unknown';const label={failed:studioLatencies.get(p.id)===-1?'Timed out':'Unreachable',fast:'Low latency',moderate:'Moderate latency',slow:'High latency',unknown:value==='…'?'Testing':'Untested'}[state];return `<span class="profile-ping ${state}" aria-label="${label}: ${E(value)}" title="${label}">${state==='failed'?'<svg class="ping-cross" viewBox="0 0 10 10" aria-hidden="true"><path d="m2 2 6 6M8 2 2 8"/></svg>':`<span class="ping-dot" aria-hidden="true"></span>`}<span>${E(value)}</span></span>`}
function routingSummary(s){const count=s.routing.apps.length;return s.routing.mode==='include'?`Selected apps only · ${count}`:s.routing.mode==='exclude'?`Excluded apps · ${count}`:'All apps'}
function lowestLatency(s){
 if(testTimer||Date.now()-latencyMeasuredAt>=latencyLifetime)return null;
 return s.profiles.filter(p=>KurdState.canConnect({...s,selected:p.id,storage:'ready',platform:{...s.platform,permission:true,unlocked:true}}).ok)
  .map(p=>({p,value:parseFloat(ping(p))})).filter(x=>Number.isFinite(x.value)&&x.value>=0)
  .sort((a,b)=>a.value-b.value||(a.p.id===s.selected?-1:b.p.id===s.selected?1:0))[0]?.p||null;
}
function lowestLatencyRow(s){
 const p=lowestLatency(s),current=p&&p.id===s.selected&&connected(s);
 return `<button class="home-lowest" data-action="home-lowest" ${testTimer?'disabled':''} aria-label="${testTimer?'Testing latency':p?`${current?'Already using':'Connect to'} lowest latency profile, ${ping(p)}`:'Test latency'}"><span>${testTimer?'Testing latency…':p?'Lowest latency':'Test latency'}</span>${p?pingHTML(p):''}${I(current?'check':'arrow')}</button>`;
}
HANDLERS['home-lowest']=()=>{if(testTimer)return;const p=lowestLatency(app);if(p)HANDLERS['gold-connect'](null,p.id);else HANDLERS['gold-test']()};
HANDLERS['home-edit-routing']=()=>{closeModal(false);navTo('routing')};
function connectionNotice(s){
 const status=s.session.status;
 if(connected(s)||status==='IDLE')return '';
 const working={CONNECTING:'Connecting…',RECONNECTING:'Reconnecting…',RECOVERING:'Restoring connection…',FALLING_BACK:'Trying another connection method…',STOPPING:'Disconnecting…'}[status];
 const offline=s.session.failure==='OFFLINE'||s.session.failure==='NETWORK';
 const timeout=s.session.failure==='SERVER_TIMEOUT';
 return `<div class="home-notice" role="status"><span>${E(offline?'No internet connection. Check Wi-Fi or mobile data.':timeout?'Server did not respond. Try another profile.':working||'Connection needs attention')}</span>${offline?'<button data-action="connect">Retry</button>':timeout?'<button data-go="profiles">Choose profile</button>':working?'':`<button data-go="troubleshooting">Review ${I('chevron')}</button>`}</div>`;
}
HANDLERS['home-details']=()=>{
 const p=KurdState.active(app);if(!p)return;
 ask('Connection details','Preview values, not a live VPN session.','Done',false,D([
  ['Profile',p.alias],['Source',sourceName(p)],['Protocol',p.protocol],
  ['Routing',routingSummary(app)],['DNS policy',app.settings.dns],
  ['Server / exit location','Not available in this prototype'],['VPN IP','Not available in this prototype'],
  ...(app.session.failure?[['Last event',app.session.failure.replaceAll('_',' ').toLowerCase()]]:[])
 ])+`<button class="home-details" data-action="home-edit-routing"><span>Edit routing</span>${I('chevron')}</button>`);
 device.querySelector('.modal-layer [data-action="modal-cancel"]')?.remove();
};
function protocolMark(name){
 const id=String(name||'').toLowerCase().replace(/[^a-z0-9]/g,'');
 const source=id==='kurd'?LOGO_DATA:window.kurdProtocolLogos?.[id];
 return source?`<img src="${source}" alt="">`:`<span class="protocol-generic-mark">${I('connection')}</span>`;
}
function home(s,u){const p=KurdState.active(s);if(!p)return ROUTES.get('home-empty').render(s,u);const on=connected(s),busy=isBusy();const action=busy?'cancel-connect':on?'disconnect':'connect';
 return `<div class="gold-home"><div class="home-identity"><button class="protocol-identity" data-go="protocols" aria-label="Protocol: ${E(p.protocol)}. View protocol"><small>Protocol</small><span class="protocol-wordmark">${protocolMark(p.protocol)}<span>${E(p.protocol)}</span>${I('chevron')}</span></button><button class="gold-sun-button ${busy?'busy':on?'on':'off'}" data-action="${action}" aria-label="${busy?'Connecting. Cancel connection':on?'VPN simulation on. Disconnect':'VPN off. Connect'}" aria-pressed="${on}">${sun()}</button></div><span class="sr-only" role="status">${busy?'Connecting':on?'Connected':'Disconnected'}</span>
 <button class="home-profile-line" data-go="profiles" aria-label="Choose profile, current ${E(p.alias)}"><span><h1>${E(p.alias)}</h1><small>${E(sourceName(p))}${sourceName(p)==='Imported'?' profile':' subscription'}</small></span>${I('chevron')}</button>
 <div class="home-stats"><div class="home-stat">${I('clock')}<div><span class="stat-label">Session time</span><span class="stat-value" data-duration>${duration(s)}</span></div></div><div class="home-stat latency">${I('latency-pulse')}<div><span class="stat-label">Latency</span><span class="stat-value">${pingHTML(p)}</span></div></div><div class="home-stat transfer">${I('arrow-down')}<div><span class="stat-label">Download</span><span class="stat-value">${on?'12.4 MB/s':'—'}</span></div></div><div class="home-stat transfer">${I('arrow-up')}<div><span class="stat-label">Upload</span><span class="stat-value">${on?'1.8 MB/s':'—'}</span></div></div></div>
 <div class="home-context">${lowestLatencyRow(s)}<button class="home-details" data-action="home-details"><span>Connection details<small>${E(routingSummary(s))}</small></span>${I('chevron')}</button></div>
 <div class="home-action" data-state="${busy?'connecting':on?'connected':'disconnected'}">${connectionNotice(s)}${B(busy?'Cancel connection':on?'Disconnect':'Connect',action,'')}</div></div>`;
}
for(const [id,spec]of ROUTES)if(id.startsWith('home-')&&id!=='home-empty')spec.render=home;
const originalToolbar=toolbar;
toolbar=function(spec,gm){if(gm||spec.back)return originalToolbar(spec,gm);return `<header class="toolbar">${brand()}<div class="profile-top-actions"><button class="icon-button" data-go="scan-qr" aria-label="Scan a profile QR">${I('qr')}</button><button class="icon-button primary-icon" data-action="profiles-add" aria-label="Add profile">${I('plus')}</button></div></header>`};
brand=function(small=false){return `<span class="brand ${small?'small-brand':''}"><img src="${LOGO_DATA}" alt="">KurdistanVPN</span>`};
function profileRows(){
 const q=(ui.search['profile-search']||'').trim().toLocaleLowerCase();
 let list=app.profiles.filter(p=>(!q||[p.alias,p.protocol,sourceName(p)].join(' ').toLocaleLowerCase().includes(q))&&(ui.profileFilter!=='favorites'||p.favorite)&&(ui.profileFilter!=='valid'||p.condition==='valid'));
 if(ui.profileSort==='name')list.sort((a,b)=>a.alias.localeCompare(b.alias));
 if(ui.profileSort==='latency')list.sort((a,b)=>{const score=p=>{const n=parseFloat(ping(p));return n>=0?n:Infinity};return score(a)-score(b)});
 const visibleGroups=new Set(list.map(sourceName));
 const groups=[...new Set(app.profiles.map(sourceName))].filter(name=>visibleGroups.has(name)).sort((a,b)=>(a==='Imported')-(b==='Imported'));
 if(!list.length)return `<div class="gold-empty"><h2>${app.profiles.length?'No matching profiles':'Add your first profile'}</h2><p>${app.profiles.length?'Try another name or clear your filters.':'Import a profile from someone you trust.'}</p>${app.profiles.length?B('Clear search and filters','gold-clear','outline'):G('Add profile','import-methods','')}</div>`;
 return groups.map(name=>{const rows=list.filter(p=>sourceName(p)===name),open=!!q||!collapsed.has(name);return `<section class="profile-section"><div class="profile-section-head"><button class="group-fold" data-action="gold-fold" data-value="${E(name)}" aria-expanded="${open}"><strong>${E(name==='Imported'?'Imported':name)}</strong><span>${name==='Imported'?'': 'Subscription · '}${rows.length} ${rows.length===1?'profile':'profiles'}</span></button><button class="icon-button" data-action="gold-group" data-value="${E(name)}" aria-label="${E(name)} details">${I('more')}</button></div>${open?rows.map(p=>`<div class="gold-profile-row ${p.id===app.selected?'current':''}"><button class="profile-pick" data-action="gold-connect" data-value="${E(p.id)}" aria-pressed="${p.id===app.selected}" aria-label="${E(p.alias)}, ${E(profileCountryLabel(p))}, ${E(p.protocol)}, ${E(ping(p))}. ${p.id===app.selected?'Current profile. ':''}Connect"><span class="gold-radio" aria-hidden="true">${countryMarker(p)}</span><span class="profile-title-wrap"><strong>${E(p.alias)}</strong><small>${E(p.protocol)}</small></span>${pingHTML(p)}</button><button class="profile-favorite" data-action="gold-favorite" data-value="${E(p.id)}" aria-pressed="${p.favorite}" aria-label="${p.favorite?'Unfavorite':'Favorite'} ${E(p.alias)}">${I(p.favorite?'star-filled':'star')}</button><button class="profile-inspect" data-go="profile-details" data-profile-id="${E(p.id)}" aria-label="Details for ${E(p.alias)}">${I('chevron')}</button></div>`).join(''):''}</section>`}).join('');
}
ROUTES.get('profiles').render=()=>`<div class="gold-profiles">${H('Profiles')}<div class="search-line"><label class="search">${I('search')}<input type="search" data-search="profile-search" id="profile-search" aria-label="Search profiles and subscriptions" placeholder="Search profiles" autocomplete="off" value="${E(ui.search['profile-search']||'')}"></label><button class="filter-trigger" data-action="gold-filters" aria-label="Filter and sort profiles" aria-expanded="${filtersOpen}">${I('sliders')}</button></div>${filtersOpen?`<div class="filter-panel"><label>Sort by<select data-ui="profileSort"><option value="original" ${ui.profileSort==='original'?'selected':''}>Import order</option><option value="name" ${ui.profileSort==='name'?'selected':''}>Name</option><option value="latency" ${ui.profileSort==='latency'?'selected':''}>Latency</option></select></label><div class="chips">${chip('All','filter-profiles','all',ui.profileFilter==='all')}${chip('Favorites','filter-profiles','favorites',ui.profileFilter==='favorites')}${chip('Usable','filter-profiles','valid',ui.profileFilter==='valid')}</div>${B(testTimer?'Cancel latency test':'Test all latency',testTimer?'gold-cancel-test':'gold-test','outline')}</div>`:''}<div id="gold-profile-list" aria-live="polite">${profileRows()}</div><button class="profile-footer" data-go="providers"><span>Sources and updates</span>${I('chevron')}</button></div>`;
mountProfiles=function(){};
searchProfiles=function(){const list=device.querySelector('#gold-profile-list');if(list){list.innerHTML=profileRows();decorateProfiles();iconFill(list)}};
HANDLERS['gold-filters']=()=>{filtersOpen=!filtersOpen;render(true);device.querySelector('.filter-trigger')?.focus()};
HANDLERS['gold-clear']=()=>{ui.search['profile-search']='';ui.profileFilter='all';render(true);device.querySelector('#profile-search')?.focus()};
HANDLERS['gold-fold']=(_,v)=>{collapsed.has(v)?collapsed.delete(v):collapsed.add(v);render(true);[...device.querySelectorAll('.group-fold')].find(e=>e.dataset.value===v)?.focus()};
HANDLERS['gold-group']=(_,v)=>{ui.profileGroup=v;ui.provider=v;navTo('profile-group')};
HANDLERS['gold-favorite']=(_,id)=>{const p=app.profiles.find(p=>p.id===id);if(!p)return;p.favorite=!p.favorite;store();render(true);[...device.querySelectorAll('.profile-favorite')].find(e=>e.dataset.value===id)?.focus({preventScroll:true})};
HANDLERS['gold-connect']=(_,id)=>{
 const p=app.profiles.find(p=>p.id===id);if(!p)return;
 app.inspected=p.id;
 if(p.condition!=='valid'){navTo(p.condition==='expired'?'profile-expired':'profile-revoked');return}
 if(app.selected===id&&connected(app))return;
 const stayOnProfiles=ui.route==='profiles';
 cancelSessionTimer();app=KurdState.transition(app,'STOP');app.selected=p.id;store();
 // Preserve the existing consent/recovery paths when connection authority is missing.
 if(!stayOnProfiles||!KurdState.canConnect(app).ok){start();return}
 app=KurdState.transition(app,'CONNECT');
 eventLog('Info','Runtime','Opening synthetic signed session.');
 render(true);
 [...device.querySelectorAll('.profile-pick')].find(el=>el.dataset.value===id)?.focus({preventScroll:true});
 finishConnection();
};
HANDLERS['use-profile']=()=>HANDLERS['gold-connect'](null,pFor(app).id);
HANDLERS['gold-test']=()=>{if(testTimer)return;for(const p of app.profiles)pingResults.set(p.id,'testing');testTimer=setTimeout(()=>{testTimer=0;for(const p of app.profiles)pingResults.set(p.id,p.condition==='valid'?(studioLatencies.get(p.id)??24+[...p.id].reduce((n,c)=>n+c.charCodeAt(0),0)%60):-1);latencyMeasuredAt=Date.now();scheduleLatencyExpiry();render(true);toast('Latency test complete. Synthetic sample results.');},1600);render(true)};
HANDLERS['gold-cancel-test']=()=>{clearTimeout(testTimer);testTimer=0;for(const [id,v]of pingResults)if(v==='testing')pingResults.delete(id);render(true)};
finishConnection=function(delay=2600){cancelSessionTimer();const selected=app.selected;sessionTimer=setTimeout(()=>{
 if(app.selected!==selected||!isBusy())return;
 const p=KurdState.active(app);
 if(previewOffline||!navigator.onLine||app.session.failure==='NETWORK'||app.session.failure==='OFFLINE')app.session={...app.session,status:'FAILED',started:0,failure:'OFFLINE'};
 else if(studioLatencies.get(p?.id)===-1)app.session={...app.session,status:'FAILED',started:0,failure:'SERVER_TIMEOUT'};
 else app=KurdState.transition(app,'CONNECTED');
 eventLog(connected(app)?'Info':'Warning','Runtime',connected(app)?'Synthetic Kurd session established.':app.session.failure==='OFFLINE'?'Internet unavailable. Check network and retry.':'Synthetic server did not respond. Choose another profile.');store();render(true);
 },delay)};
window.addEventListener('offline',()=>{previewOffline=true;if(connected(app)||isBusy()){cancelSessionTimer();app.session={...app.session,status:'FAILED',started:0,failure:'OFFLINE'};store();render(true)}});
HANDLERS['subscription-refresh']=(_,name)=>{
 if(subscriptionUpdates.get(name)?.status==='updating')return;
 const old=subscriptionUpdates.get(name)||{};subscriptionUpdates.set(name,{...old,status:'updating'});saveSubscriptionUpdates();render(true);
 setTimeout(()=>{const offline=previewOffline||!navigator.onLine;subscriptionUpdates.set(name,{...old,status:offline?'failed':'updated',...(offline?{}:{updatedAt:Date.now()})});saveSubscriptionUpdates();render(true);toast(offline?'Update failed. Existing profiles are unchanged.':'Subscription checked. Synthetic sample, no network request.');},1300);
};
HANDLERS['subscription-status']=(_,name)=>{
 const update=subscriptionUpdates.get(name)||{};
 ask(name,'Subscription updates in this prototype are simulated.','Done',false,D([['Status',update.status==='updating'?'Updating…':update.status==='failed'?'Update failed. Existing profiles retained.':update.status==='updated'?'Up to date':'Not checked yet'],['Last successful update',update.updatedAt?new Date(update.updatedAt).toLocaleString():'Not yet updated'],['Profiles',app.profiles.filter(p=>sourceName(p)===name).length]]) );device.querySelector('.modal-layer [data-action="modal-cancel"]')?.remove();
};
ROUTES.get('settings').render=(s,u)=>`<div class="gold-settings">${H('Settings')}${SEARCH('settings-search','Search settings',u.search['settings-search'])}${[['Appearance',SETTINGS_ROWS.slice(0,1)],['Network',SETTINGS_ROWS.slice(1,4)],['Data',SETTINGS_ROWS.slice(4,6)],['Advanced',SETTINGS_ROWS.slice(6)]].map(([title,rows])=>`<section class="settings-group">${SEC(title)}${rows.map(([a,b,c,d])=>`<div data-filter-text="${E(a+' '+c)}">${N(a==='Profile updates and probes'?'Profile updates':a,b,c,d)}</div>`).join('')}</section>`).join('')}<p class="empty-result" hidden>No settings match this search.</p></div>`;
const baseApply=applySearch;applySearch=function(){baseApply();device.querySelectorAll('.settings-group').forEach(g=>g.hidden=![...g.querySelectorAll('[data-filter-text]')].some(r=>!r.hidden))};
const detailRender=ROUTES.get('profile-details').render;
ROUTES.get('profile-details').render=(s,u)=>detailRender(s,u).replace(/Selected profile|Use profile/g,'Connect to profile');
const baseRender=render;
function decorateProfiles(){
 const profiles=device.querySelector('.gold-profiles');
 if(profiles&&!profiles.querySelector('.profile-tools')){
  profiles.querySelector('.filter-panel label')?.remove();profiles.querySelector('.filter-panel .btn')?.remove();
  profiles.querySelector('.search-line').insertAdjacentHTML('afterend',`<div class="profile-tools"><button data-action="${testTimer?'gold-cancel-test':'gold-test'}">${I('latency-pulse')}<span>${testTimer?'Cancel latency test':'Test all latency'}</span></button><label><span class="sr-only">Sort profiles</span><select data-ui="profileSort" aria-label="Sort profiles"><option value="latency" ${ui.profileSort==='latency'?'selected':''}>Fastest first</option><option value="name" ${ui.profileSort==='name'?'selected':''}>Name</option><option value="original" ${ui.profileSort==='original'?'selected':''}>Import order</option></select></label></div>`);
  if(app.session.failure==='OFFLINE'||app.session.failure==='NETWORK'||app.session.failure==='SERVER_TIMEOUT')profiles.querySelector('.profile-tools').insertAdjacentHTML('afterend',connectionNotice(app));
 }
 device.querySelectorAll('.profile-section-head').forEach(el=>el.classList.toggle('subscription-surface',el.querySelector('.group-fold')?.dataset.value!=='Imported'));
 device.querySelectorAll('.subscription-surface').forEach(el=>{
  if(el.querySelector('.subscription-refresh'))return;
  const name=el.querySelector('.group-fold').dataset.value,state=subscriptionUpdates.get(name)||{};
 const status=state.status==='updating'?'Updating…':state.status==='failed'?'Update failed':state.status==='updated'?'Checked · demo':'Not checked yet';
  el.insertAdjacentHTML('beforeend',`<button class="icon-button subscription-refresh" data-action="subscription-refresh" data-value="${E(name)}" aria-label="Update ${E(name)}" ${state.status==='updating'?'disabled':''}>${I('subscription-refresh')}</button>`);
  const more=el.querySelector('[data-action="gold-group"]');if(more){more.dataset.action='subscription-status';more.setAttribute('aria-label',`${name} subscription status`)}
  el.querySelector('.group-fold>span').insertAdjacentHTML('beforeend',`<span class="subscription-status ${state.status==='failed'?'update-failed':''}">${status}</span>`);
 });
 const state=connected(app)?'connected':isBusy()?'connecting':'disconnected';
 const profile=KurdState.active(app),name=profile?.alias||'profile';
 const current=device.querySelector('.gold-profile-row.current');
 if(current){current.dataset.connection=state;current.querySelector('.profile-pick').setAttribute('aria-label',`${name}, ${profileCountryLabel(profile)}, ${profile.protocol}, ${ping(profile)}. ${state==='connected'?'Connected':state==='connecting'?'Connecting':'Selected. Connect'}`);current.querySelector('.gold-radio').setAttribute('aria-busy',String(state==='connecting'));if(state==='connecting'){current.querySelector('.profile-title-wrap small').textContent=profile.protocol+' · Connecting…'}}
 device.querySelectorAll('.group-fold').forEach(el=>{if(!el.querySelector('.fold-cue'))el.insertAdjacentHTML('beforeend',`<span class="fold-cue" aria-hidden="true">${I('chevron')}</span>`);iconFill(el)});
 if(profiles)iconFill(profiles);
}
render=function(preserve=false){
 const oldProfiles=device.querySelector('.gold-profiles');if(oldProfiles)profileScroll=device.querySelector('.screen-main').scrollTop;
 saveListContext();
 const previous=device.dataset.connection,sunCore=device.querySelector('.sun-core');
 const oldRotation=device.querySelector('.sun-rays')?.getAnimations().find(a=>a.animationName==='solar-turn');
 const phase=oldRotation?Number(oldRotation.currentTime)/Number(oldRotation.effect.getTiming().duration):null;
 const fill=sunCore?getComputedStyle(sunCore).clipPath:'none';
 baseRender(preserve);
 // Keep the exact yellow plus, backed by a high-contrast edge in light mode.
 const plus=device.querySelector('.primary-icon svg');
 if(plus&&!plus.querySelector('.gold-plus-core')){const core=plus.querySelector('path')?.cloneNode(true);if(core){core.classList.add('gold-plus-core');plus.append(core)}}
 const state=connected(app)?'connected':isBusy()?'connecting':'disconnected';
 device.dataset.connection=state;
 const newRotation=device.querySelector('.sun-rays')?.getAnimations().find(a=>a.animationName==='solar-turn');
 if(phase!==null&&newRotation)newRotation.currentTime=phase*Number(newRotation.effect.getTiming().duration);
 const name=KurdState.active(app)?.alias||'profile';
 const announcement=state==='connecting'?`Connecting to ${name}.`:state==='connected'?`Connected to ${name}.`:'Disconnected.';
 if(announcement!==lastConnectionAnnouncement){connectionAnnouncement.textContent=announcement;lastConnectionAnnouncement=announcement}
 device.querySelectorAll('.brand').forEach(el=>el.setAttribute('aria-label',`KurdistanVPN. ${announcement}`));
 if(previous==='connecting'&&state==='connected'&&sunCore?.isConnected&&!app.settings.reducedMotion&&!matchMedia('(prefers-reduced-motion:reduce)').matches){sunCore.animate([{clipPath:fill},{clipPath:'inset(0% 0 0)'}],{duration:280,easing:'ease-out'})}
 decorateProfiles();
 if(device.querySelector('.gold-profiles'))device.querySelector('.screen-main').scrollTop=profileScroll;
 document.title='KurdistanVPN · '+(ROUTES.get(resolveRoute(ui.route))?.name||'App');
 device.querySelectorAll('.bottom-nav button').forEach(b=>{if(['home','profiles','settings'].includes(ui.route)){b.classList.toggle('active',b.dataset.go===ui.route);if(b.dataset.go===ui.route)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current')}});
};
document.addEventListener('visibilitychange',()=>device.classList.toggle('motion-paused',document.hidden));
window.KurdDemo.render=()=>render();
window.KurdStandalone={version:1,profileRows,countryCodeFromName,profileCountryCode,countryMarker,resourceBoundary:'Offline. Synthetic data only.'};
navTo(validRoute(initialRoute)?initialRoute:'home',{replace:true});
})();
