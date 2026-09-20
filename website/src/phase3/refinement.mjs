import {readFileSync} from 'node:fs';
import {escape as e} from '../lib/core.mjs';
import {icon} from '../components/primitives.mjs';
import {config} from '../../site.config.mjs';
export const refinementCopy=JSON.parse(readFileSync(new URL('../refinement/copy.json',import.meta.url),'utf8'));
export const methods=JSON.parse(readFileSync(new URL('../refinement/methods.json',import.meta.url),'utf8'));
const sun=readFileSync(new URL('../refinement/kurd-sun.svg',import.meta.url),'utf8');
const ring=readFileSync(new URL('../refinement/sun-instrument-ring.svg',import.meta.url),'utf8');
const logos=JSON.parse(readFileSync(new URL('../refinement/protocol-logos.json',import.meta.url),'utf8'));
const t=locale=>key=>e(refinementCopy[locale][key]);
export function refinedHero(locale){const x=t(locale);return `<div class="connection-visual refined-connection" data-hero-selection="kurd" aria-label="${x('connection')}">
 <div class="connection-meta">${x('connection')}</div><p class="connection-instruction">${x('inspectPart')}</p>
 <div class="connection-route">
 <button type="button" class="connection-end" data-hero-info="phone" aria-pressed="false">${icon('phone')}<span>${x('phone')}</span></button>
 <span class="connection-wire" aria-hidden="true"></span>
 <button type="button" class="kurd-control" data-hero-info="kurd" aria-pressed="true"><span class="sun-instrument" data-sun-entrance><span class="instrument-ring" aria-hidden="true">${ring}</span><span class="instrument-sun" aria-hidden="true">${sun}</span></span><strong dir="ltr">Kurd</strong><span>${x('nativeLabel')}</span></button>
 <span class="connection-wire" aria-hidden="true"></span>
 <button type="button" class="connection-end" data-hero-info="server" aria-pressed="false">${icon('server')}<span>${x('server')}</span></button>
 </div>
 <div class="hero-explanation" aria-live="polite">${['Kurd','Phone','Server'].map((key,i)=>`<section data-hero-panel="${key.toLowerCase()}" ${i?'hidden':''}><h2>${x('hero'+key+'Title')}</h2><p>${x('hero'+key+'Body')}</p></section>`).join('')}</div>
 <div class="connection-bottom"><p class="connection-boundary">${x('diagramNote')}</p><button type="button" class="sun-replay" data-sun-replay aria-label="${x('replay')}">${icon('refresh')}</button></div>
 </div>`;}
function methodLink(p,id=false){const file=p.id==='kurd'?'kurd.svg':logos[p.id]?.file;const mark=file?`<img class="method-logo" src="${e(new URL(config.siteUrl).pathname)}prototype/protocol-logos/${e(file)}" width="16" height="16" alt="" loading="lazy">`:icon(p.family==='tunnels'?'server':'settings','method-logo');return `<a ${id?`id="method-${e(p.id)}"`:''} class="method-link ${p.id==='kurd'?'method-native':''}" href="${e(p.url)}" target="_blank" rel="noopener noreferrer">${mark}<span dir="ltr">${e(p.name)}</span>${icon('external')}</a>`;}
export function methodFamilies(locale){const x=t(locale);return `<div class="method-families">${[['native','Native'],['tunnels','Tunnels'],['proxy','Proxy'],['quic','Quic'],['standards','Standards']].map(([id,key])=>`<section class="method-family"><header><h3>${x('family'+key)}</h3><p>${x('family'+key+'Body')}</p></header><ul class="method-links">${methods.filter(p=>p.family===id).map(p=>`<li>${methodLink(p,true)}</li>`).join('')}</ul></section>`).join('')}</div>`;}
