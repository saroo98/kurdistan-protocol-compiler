/** Repeat a clean build and compare every emitted byte through its manifest.
 * This is same-environment determinism, not cross-platform/release provenance.
 */
import {readFile,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const before=await readFile('dist/BUILD_MANIFEST.json');
const result=spawnSync(process.execPath,['scripts/build.mjs'],{encoding:'utf8'});
process.stdout.write(result.stdout||'');process.stderr.write(result.stderr||'');
assert.equal(result.status,0,'Repeated clean build must succeed');
const after=await readFile('dist/BUILD_MANIFEST.json');
assert.ok(before.equals(after),'Clean builds produced different file manifests');
const report={scope:'Two consecutive clean builds in the same recorded environment',passed:true,files:JSON.parse(after).length,manifestSha256:createHash('sha256').update(after).digest('hex'),notProven:['cross-platform build equivalence','signed VPN release provenance']};
await writeFile('qa/reproducibility-report.json',JSON.stringify(report,null,2));
console.log(`Repeated clean build: ${report.files} file hashes and byte lengths are identical.`);
