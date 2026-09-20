import {escape as e, sunPoints} from '../lib/core.mjs';
import {claimById,stateLabels} from '../content/claims.mjs';
export const icons={arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',chevron:'<path d="m9 5 7 7-7 7"/>',search:'<circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/>',close:'<path d="m6 6 12 12M6 18 18 6"/>',moon:'<path d="M20 14A9 9 0 0 1 10 4a9 9 0 1 0 10 10Z"/>',check:'<path d="m4 12 5 5L20 6"/>',info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',phone:'<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 18h4"/>',server:'<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="14" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 17.5h.01M12 7.5h5M12 17.5h5"/>',file:'<path d="M14 2H5v20h14V7Z M14 2v5h5M8 12h8M8 16h5"/>',copy:'<rect x="8" y="8" width="12" height="13" rx="1"/><path d="M16 8V3H3v13h5"/>',external:'<path d="M14 3h7v7M21 3 11 13M10 5H3v16h16v-7"/>',help:'<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 5M12 18h.01"/>',plus:'<path d="M12 4v16M4 12h16"/>',settings:'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',warning:'<path d="m12 3 10 18H2ZM12 9v5M12 17h.01"/>',home:'<path d="m3 10 9-7 9 7v11h-7v-7h-4v7H3Z"/>'};
icons.menu='<path d="M4 6h16M4 12h16M4 18h16"/>';
icons.refresh='<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>';
icons.up='<path d="M12 20V4m-6 6 6-6 6 6"/>';
icons.github='<path fill="currentColor" stroke="none" d="M12 .8a11.2 11.2 0 0 0-3.54 21.83c.56.1.77-.24.77-.54v-2.1c-3.12.68-3.78-1.32-3.78-1.32-.51-1.3-1.24-1.64-1.24-1.64-1.02-.7.08-.69.08-.69 1.13.08 1.72 1.16 1.72 1.16 1 1.72 2.63 1.22 3.27.93.1-.73.39-1.22.71-1.5-2.49-.28-5.11-1.25-5.11-5.54 0-1.22.43-2.22 1.15-3-.11-.29-.5-1.42.11-2.95 0 0 .94-.3 3.08 1.15A10.74 10.74 0 0 1 12 6.2c.95 0 1.9.13 2.79.37 2.14-1.45 3.07-1.15 3.07-1.15.61 1.53.23 2.66.12 2.95.72.78 1.14 1.78 1.14 3 0 4.3-2.62 5.25-5.12 5.53.4.35.76 1.03.76 2.08v3.11c0 .3.2.65.77.54A11.2 11.2 0 0 0 12 .8Z"/>';
export const icon=(name,cls='')=>`<svg class="icon ${e(cls)}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${icons[name]||icons.info}</svg>`;
export const sun=(cls='')=>`<svg class="sun ${e(cls)}" viewBox="0 0 240 240" aria-hidden="true" focusable="false" data-rays="21"><polygon points="${sunPoints().map(p=>p.map(n=>n.toFixed(4)).join(',')).join(' ')}"/></svg>`;
export const link=(label,url,kind='text-link',external=false)=>`<a class="${e(kind)}" href="${e(url)}"${external?' target="_blank" rel="noopener noreferrer"':''}>${e(label)}${icon(external?'external':'arrow','directional')}</a>`;
export const note=(title,text,kind='neutral')=>`<aside class="note note-${e(kind)}">${icon(kind==='warning'?'warning':'info')}<div><strong>${e(title)}</strong><p>${text}</p></div></aside>`;
export const table=(head,rows)=>`<div class="table-scroll" role="region" aria-label="${e(head.join(' and '))}" tabindex="0"><table><thead><tr>${head.map(x=>`<th scope="col">${e(x)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map((x,i)=>i===0?`<th scope="row">${x}</th>`:`<td>${x}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
export const technical=(body)=>`<details class="technical"><summary>Technical details ${icon('chevron','disclosure-chevron')}</summary><div class="detail-body">${body}</div></details>`;
export function proof(id,expanded=false){
 const c=claimById(id); if(!c)throw Error('Unknown claim '+id);
 return `<details class="proof" id="claim-${e(id)}"${expanded?' open':''}><summary><span>${e(c.wording)}<small class="claim-state state-${c.status.toLowerCase()}">${e(stateLabels[c.status])}</small></span><span class="evidence-affordance">View evidence ${icon('chevron','disclosure-chevron')}</span></summary><div class="detail-body"><dl class="proof-facts">${[['What this means',c.meaning],['How the design works',c.mechanism],['The limit',c.limit]].map(([a,b])=>`<div><dt>${a}</dt><dd>${e(b)}</dd></div>`).join('')}</dl><div class="source-links">${c.evidence.map((s,i)=>s.startsWith('https://')?link('Source '+(i+1),s,'source-link',true):`<span class="source-path"><code dir="ltr">${e(s)}</code></span>`).join('')}</div><p class="caption">Reviewed <time datetime="${e(c.reviewed)}">${e(c.reviewed)}</time>. Source code alone is not release qualification.</p></div></details>`;
}
/** Highlight a small command vocabulary without interpreting HTML or changing copy bytes. */
export function highlightCommand(command){
 const pattern=/#([^\n]*)|"[^"\n]*"|'[^'\n]*'|--[a-z][a-z0-9-]*|\b(?:sudo|kurdctl|kurdpackage|systemctl|go|cd)\b/g;
 let result='',offset=0;
 for(const token of command.matchAll(pattern)){
  result+=e(command.slice(offset,token.index));const value=token[0],kind=value.startsWith('#')?'comment':value.startsWith('--')?'option':/^['"]/.test(value)?'string':'command';
  result+=`<span class="code-${kind}">${e(value)}</span>`;offset=token.index+value.length;
 }
 return result+e(command.slice(offset));
}
export function code(command,id,language='sh'){
 const body=highlightCommand(command);
 return `<figure class="code-block"><figcaption><span>${e(language)} · run only after reading the prerequisites</span><button data-copy="${e(id)}" data-enhance type="button">${icon('copy')}<span>Copy</span></button></figcaption><pre tabindex="0" dir="ltr"><code id="${e(id)}" class="language-${e(language)}">${body}</code></pre></figure>`;
}
