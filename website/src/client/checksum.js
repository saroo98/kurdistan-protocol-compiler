import {msg} from './locale.js';
/** A byte comparison tool, never a signature verifier or a proof of publisher identity. */
export function setupChecksum(){
 const form=document.querySelector('#checksum-form');if(!form)return;
 const fileInput=form.querySelector('#checksum-file'),expected=form.querySelector('#checksum-expected'),error=form.querySelector('#checksum-error'),output=form.querySelector('#checksum-output'),button=form.querySelector('button[type=submit]');
 let active=false;
 form.addEventListener('submit',async event=>{
  event.preventDefault();if(active)return;
  error.textContent='';output.textContent='';fileInput.removeAttribute('aria-invalid');expected.removeAttribute('aria-invalid');
  const file=fileInput.files?.[0],hash=expected.value.trim();
  function reject(message,field){error.textContent=message;field.setAttribute('aria-invalid','true');field.focus();}
  if(!file){reject(msg('Choose the local file you want to check.'),fileInput);return}
  if(file.size>64*1024*1024){reject(msg('This local tool accepts files up to 64 MiB. Use a local command-line utility for a larger file.'),fileInput);return}
  if(!/^[a-fA-F0-9]{64}$/.test(hash)){reject(msg('Enter exactly 64 hexadecimal characters for the expected SHA-256 checksum.'),expected);return}
  if(!globalThis.crypto?.subtle){error.textContent=msg('This browser context does not provide Web Crypto. Use HTTPS, localhost or a local SHA-256 utility. Nothing was uploaded.');return}
  active=true;button.disabled=true;button.setAttribute('aria-busy','true');output.textContent=msg('Computing SHA-256 locally…');
  try{
   const bytes=await file.arrayBuffer();const digest=await crypto.subtle.digest('SHA-256',bytes);const actual=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
   const match=actual===hash.toLowerCase();output.className=match?'hash-match':'hash-mismatch';
   const strong=document.createElement('strong'),text=document.createElement('p'),code=document.createElement('code');
   strong.textContent=match?msg('The checksums match.'):msg('The checksums do not match.');
   text.textContent=match?msg('The file matches the expected bytes. This does not verify the publisher’s identity, a signature or the safety of the software.'):msg('Do not treat this file as the expected artifact. Check its source and the independently obtained expected checksum.');
   code.dir='ltr';code.textContent=actual;output.replaceChildren(strong,text,code);
  }catch{error.textContent=msg('The file could not be read or hashed. Choose it again or use a local utility. Nothing was uploaded.');output.textContent=''}
  finally{active=false;button.disabled=false;button.removeAttribute('aria-busy')}
 });
}
