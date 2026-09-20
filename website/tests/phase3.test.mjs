import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {pages} from '../src/content/pages.mjs';
import {makeContext} from '../src/components/document.mjs';
const home=pages.find(p=>p.slug==='');
const html=home.custom(makeContext('en','/'));
test('Phase3 leads with restricted networks, not abstract key ownership',()=>{
 assert.match(home.title,/restricted networks/i);
 assert.doesNotMatch(html,/Know who|holds the|Start with the owner|Open a claim/);
});
test('Phase3 homepage contains protocols, privacy and automatic product demonstration',()=>{
 for(const id of ['restricted-networks','protocols','privacy-model','app-demo'])assert.ok(html.includes(`id="${id}"`),id);
 assert.doesNotMatch(html,/data-demo-load/);
 assert.match(html,/data-demo-initial="disconnected"/);
});
test('Phase3 sun is a semantic protocol chooser, initially selected without autofocus',()=>{
 assert.match(html,/data-protocol-open/);assert.match(html,/data-sun-entrance/);
 assert.doesNotMatch(html,/autofocus/);
});
test('Protocol capability data includes every requested target and forbids invented qualification',async()=>{
 const p=JSON.parse(await readFile('src/content/protocols.json','utf8'));
 for(const name of ['Kurd','WireGuard','VLESS','VMess','Trojan','Shadowsocks','ShadowsocksR','Hysteria','Hysteria2','AnyTLS','TUIC','Juicity','SOCKS','HTTP / HTTPS proxy','SSH tunnelling','OpenConnect','TrustTunnel','MASQUE','Snell','Mieru','Brook','Multi-hop'])assert.ok(p.protocols.some(x=>x.name===name),name);
 for(const x of p.protocols){assert.ok(x.evidence.length);if(!x.qualified)assert.equal(x.connectable,false);}
});
