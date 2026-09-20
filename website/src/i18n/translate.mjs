/** Build-time text localization over the site's controlled generated markup.
 * Source code, SVG paths, URLs and explicitly isolated identifiers are untouched.
 * Missing text is a build error, never a silent English fallback. */
import {readFileSync} from 'node:fs';
import {escape} from '../lib/core.mjs';
const rows=JSON.parse(readFileSync(new URL('./messages.json',import.meta.url),'utf8'));
const dictionaries={ckb:new Map(),kmr:new Map()};
for(const row of rows){
 if(row.length!==3||row.some(x=>typeof x!=='string'||!x.trim()))throw Error('Malformed translation record');
 if(dictionaries.ckb.has(row[0]))throw Error('Duplicate translation: '+row[0]);
 dictionaries.ckb.set(row[0],row[1]);dictionaries.kmr.set(row[0],row[2]);
}
export const encountered=new Set();
export const normalizeText=s=>s.replace(/\s+/g,' ').trim();
const literals=new Set(['Kurdistan','VPN','Kurdistan VPN','Kurd','Saro Xizirnijad','AGPL','AGPL-3.0-or-later','CC-BY-SA-4.0','GitHub','Android','TLS','DNS','VPS','SHA-256','QR','01 / KURD','English','کوردی (سۆرانی)','Kurdî (Kurmancî)','sh','powershell','API 26+','Web Crypto','Rojhelat']);
export function isLiteral(s){return !s||literals.has(s)||/^[\d\s./:#%(),+×→↑−–—=-]+$/.test(s)||/^[a-f\d]{12,64}$/.test(s)||/^(?:https?:\/\/|references\/|src\/|docs\/|qa\/)/.test(s);}
export function t(text,locale='en'){
 const key=normalizeText(String(text));if(isLiteral(key))return String(text);
 encountered.add(key);
 if(locale==='en')return String(text);
 const result=dictionaries[locale]?.get(key);
 if(!result){if(process.env.I18N_COLLECT==='1')return String(text);throw Error('Missing '+locale+' translation: '+key);}
 return result;
}
function decode(s){return s.replace(/&#(x[0-9a-f]+|\d+);/gi,(_,n)=>String.fromCodePoint(n[0].toLowerCase()==='x'?parseInt(n.slice(1),16):Number(n))).replace(/&quot;/g,'"').replace(/&#39;|&apos;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').replace(/&nbsp;/g,' ');}
const voids=new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
export function localizeHTML(html,locale){
 const stack=[];let output='';
 for(const token of html.match(/<!--[\s\S]*?-->|<[^>]*>|[^<]+/g)||[]){
  if(token.startsWith('<!--')||/^<!/i.test(token)){output+=token;continue;}
  if(token[0]==='<'){
   const close=token.match(/^<\/([a-z0-9-]+)/i);
   if(close){const index=stack.findLastIndex(x=>x.name===close[1].toLowerCase());if(index>=0)stack.splice(index);output+=token;continue;}
   const tag=token.match(/^<([a-z0-9-]+)/i);if(!tag){output+=token;continue;}
   const name=tag[1].toLowerCase();const skip=stack.some(x=>x.skip)||['script','style','code','pre','svg'].includes(name)||/\bdata-no-translate(?:[\s=>]|$)/.test(token);
   let next=token;
   if(!skip)next=next.replace(/\b(aria-label|alt|placeholder|title)="([^"]*)"/g,(_,attr,value)=>`${attr}="${escape(t(decode(value),locale))}"`);
   if(!voids.has(name)&&!token.endsWith('/>'))stack.push({name,skip});
   output+=next;
  }else if(stack.some(x=>x.skip)){output+=token;}
  else{const decoded=decode(token),value=decoded.trim();output+=value?token.match(/^\s*/)[0]+escape(t(value,locale))+token.match(/\s*$/)[0]:token;}
 }
 return output;
}
export function dictionaryRows(){return rows;}
