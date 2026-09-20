/** Public implementation inventory. Private briefs are not distributable evidence. */
import {readFile,stat,writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const areas={privacy:['src/prototype/app.html','tests/artifacts/refinement.test.mjs'],anchors:['src/components/experiences.mjs','tests/artifacts/refinement.test.mjs'],hero:['src/phase3/refinement.mjs','src/client/phase3.js'],methods:['src/refinement/methods.json','src/client/search.js'],phone:['src/client/prototype-refinement.js','src/client/prototype-adapter.js','src/client/preview.js'],profiles:['src/prototype/app.html','src/client/prototype-refinement.js'],languages:['src/refinement/copy.json','src/i18n/messages.json'],verification:['tests/refinement.browser.mjs','tests/artifacts/production.test.mjs','performance-budgets.json']};
for(const files of Object.values(areas))for(const file of files)assert.ok((await stat(file)).isFile(),file);
const copy=JSON.parse(await readFile('src/refinement/copy.json','utf8'));
for(const locale of ['ckb','kmr'])for(const key of Object.keys(copy.en))assert.ok(copy[locale][key],locale+':'+key);
await writeFile('qa/requirements.json',JSON.stringify({scope:'Implemented public surfaces, not a certification',areas,localeKeys:Object.keys(copy.en).length},null,2));
console.log('Public implementation references and new locale keys are complete.');
