import test from 'node:test';import assert from 'node:assert/strict';
import * as primitives from '../src/components/primitives.mjs';
test('documentation highlighting escapes text while preserving the copyable command',()=>{
 assert.equal(typeof primitives.highlightCommand,'function');
 const value='kurdctl init --name "<script>"\n# Never paste a password';
 const html=primitives.highlightCommand(value);assert.ok(html.includes('code-option'));assert.ok(html.includes('code-comment'));assert.ok(!html.includes('<script>'));assert.ok(html.includes('&lt;script&gt;'));
 const plain=html.replace(/<\/?span\b[^>]*>/g,'').replaceAll('&lt;','<').replaceAll('&gt;','>').replaceAll('&quot;','"');assert.equal(plain,value);
});
