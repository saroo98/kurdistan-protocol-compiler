/** Shared deterministic helpers. No browser or file-system state. */
export function escape(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
export function pathFor(route = '', locale = 'en', base = '/') {
  if (!/^[a-z0-9/-]*$/.test(route) || route.includes('..') || !['en','ckb','kmr'].includes(locale)) throw new Error('Invalid local route');
  if (!base.startsWith('/') || !base.endsWith('/') || /[?#\\]/.test(base)) throw new Error('Invalid base path');
  return `${base}${locale}/${route ? route.replace(/^\/+|\/+$/g, '') + '/' : ''}`;
}
export function sunPoints() {
  return Array.from({length:42}, (_,i) => {
    const angle=i*Math.PI/21, r=i%2?50:100;
    return [120+Math.sin(angle)*r,120-Math.cos(angle)*r];
  });
}
export function normalize(value) {
  return String(value).normalize('NFKD').replace(/\p{M}/gu,'').replace(/[ك]/g,'ک').replace(/[يى]/g,'ی').replace(/[ـ\u200c\u200d]/g,'').toLocaleLowerCase().trim();
}
export function rankSearch(query, items) {
  const terms=normalize(query).split(/\s+/).filter(Boolean).slice(0,12);
  if(!terms.length) return items;
  return items.map(item=>{
    const title=normalize(item.title), body=normalize([item.title,item.description,item.category,item.keywords||''].join(' '));
    return {...item,score:terms.every(t=>body.includes(t))?terms.reduce((s,t)=>s+(title.includes(t)?5:1),0):0};
  }).filter(x=>x.score>0).sort((a,b)=>b.score-a.score);
}
export const CLAIM_STATES=Object.freeze(['AVAILABLE','VERIFIED','EXPERIMENTAL','PLANNED','UNQUALIFIED']);
export function validateClaim(claim) {
  if(!claim || !/^[a-z][a-z0-9-]*$/.test(claim.id) || !CLAIM_STATES.includes(claim.status) || !claim.wording || !claim.evidence?.length) throw new Error('Claim needs an ID, controlled status, wording and evidence');
  return true;
}
export function validateSiteUrl(raw) {
  const u=new URL(raw);
  if(u.protocol!=='https:' || u.search || u.hash || u.username || u.password || !u.pathname.endsWith('/')) throw new Error('SITE_URL must be an HTTPS URL ending in /, without credentials, query or fragment');
  return u;
}
