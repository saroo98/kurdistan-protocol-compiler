/** Import the owner's original files; no remote font service or bundled font binary. */
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const inputs=process.argv.slice(2);
if(inputs.length!==2)throw Error('Usage: node scripts/import-fonts.mjs /path/to/k-magroon.woff2 /path/to/shasenem-kiteb.woff2');
const expected=[['k-magroon.woff2','ff8fbd8a47e349dbbcff768acab4d8d66f27961c9288135ea4041efcca873ca4'],['shasenem-kiteb.woff2','1598bddc4f79386c9975342f9a39b2f18ded7994d3e60a992b3107dc3ad9fbd0']];
const files=await Promise.all(inputs.map(p=>readFile(p)));
files.forEach((b,i)=>{if(createHash('sha256').update(b).digest('hex')!==expected[i][1])throw Error('The supplied font does not match the inspected original: '+expected[i][0]);});
await mkdir('.local/fonts',{recursive:true});
for(let i=0;i<files.length;i++)await writeFile('.local/fonts/'+expected[i][0],files[i]);
console.log('Original fonts imported locally. Confirm your deployment rights, then run npm run build. Only Sorani pages request these fonts.');
