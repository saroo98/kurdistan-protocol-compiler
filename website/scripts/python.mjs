/** Resolve the active QA Python environment on POSIX and Windows. */
import {spawnSync} from 'node:child_process';
const executable=process.env.QA_PYTHON||(process.platform==='win32'?'python':'python3');
const result=spawnSync(executable,process.argv.slice(2),{stdio:'inherit',env:process.env});
if(result.error){console.error(`Could not start ${executable}: ${result.error.message}. Set QA_PYTHON to your QA interpreter.`);process.exit(1)}
process.exit(result.status??1);
