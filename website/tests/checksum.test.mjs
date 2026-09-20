/** Real Node Web Crypto plus small DOM doubles; separate from native-browser QA. */
import test from 'node:test';import assert from 'node:assert/strict';import {webcrypto,createHash} from 'node:crypto';
import {clientMessages} from '../src/content/interface.mjs';
import {setupChecksum} from '../src/client/checksum.js';
function element(){return {attrs:{},textContent:'',children:[],value:'',files:[],disabled:false,focus(){this.focused=true},setAttribute(k,v){this.attrs[k]=v},removeAttribute(k){delete this.attrs[k]},append(...c){this.children.push(...c)},replaceChildren(...c){this.children=c}}}
function harness(bytes,expected){const file=element(),hash=element(),error=element(),output=element(),button=element(),form=element();file.files=[{size:bytes.length,arrayBuffer:async()=>Uint8Array.from(bytes).buffer}];hash.value=expected;form.querySelector=id=>({'#checksum-file':file,'#checksum-expected':hash,'#checksum-error':error,'#checksum-output':output,'button[type=submit]':button}[id]);form.addEventListener=(_,handler)=>form.submit=handler;globalThis.document={getElementById:()=>({textContent:JSON.stringify(Object.fromEntries(clientMessages.map(x=>[x,x])))}),querySelector:()=>form,createElement:()=>element()};setupChecksum();return {file,hash,error,output,button,form};}
test('production checksum controller compares real SHA-256 bytes and never claims signature verification',async()=>{
 const bytes=Buffer.from('abc');const v=harness(bytes,createHash('sha256').update(bytes).digest('hex'));await v.form.submit({preventDefault(){}});assert.equal(v.output.children[0].textContent,'The checksums match.');assert.match(v.output.children[1].textContent,/does not verify/);assert.equal(v.output.children[2].textContent,'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');assert.equal(v.button.disabled,false);delete globalThis.document;
});
test('mismatch and oversize guards do not silently report success',async()=>{
 const v=harness(Buffer.from('abc'),'0'.repeat(64));await v.form.submit({preventDefault(){}});assert.equal(v.output.children[0].textContent,'The checksums do not match.');v.file.files[0].size=64*1024*1024+1;await v.form.submit({preventDefault(){}});assert.match(v.error.textContent,/64 MiB/);assert.equal(v.file.attrs['aria-invalid'],'true');delete globalThis.document;
});
