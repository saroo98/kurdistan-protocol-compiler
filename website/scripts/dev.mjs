import {spawn,spawnSync} from 'node:child_process';
import {watch} from 'node:fs';
const build=()=>{const r=spawnSync(process.execPath,['scripts/build.mjs'],{stdio:'inherit'});return r.status===0};
if(!build())process.exit(1);
let server=spawn(process.execPath,['scripts/serve.mjs'],{stdio:'inherit'}),timer,busy=false;
function changed(){clearTimeout(timer);timer=setTimeout(()=>{if(busy)return;busy=true;if(build()){server.kill('SIGTERM');server.once('exit',()=>{server=spawn(process.execPath,['scripts/serve.mjs'],{stdio:'inherit'})})}busy=false},200)}
for(const dir of ['src','public'])watch(dir,{recursive:true},changed);
watch('site.config.mjs',changed);
console.log('Watching source and assets. Refresh the browser after a build.');
process.on('SIGINT',()=>{server.kill('SIGTERM');process.exit()});
