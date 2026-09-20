/** Check Git publication inputs, not private local files. Never print file contents. */
import {execFileSync} from 'node:child_process';
const staged=process.argv.includes('--staged');
const files=execFileSync('git',staged?['diff','--cached','--name-only','--diff-filter=ACMR','-z']:['ls-files','-z'],{encoding:'utf8',cwd:'..'}).split('\0').filter(p=>p.startsWith('website/'));
const forbidden=/(?:^|\/)(?:qa|dist|node_modules|backups|private-originals|references|plans|planning|specs|\.impeccable|\.superpowers)(?:\/|$)|(?:^|\/)(?:AGENTS|PRODUCT|DESIGN|ROADMAP|HANDOFF|GOAL)(?:\.(?:md|json|txt)|$)|\.(?:zip|rar|7z|bak|pem|key)$/i;
const privateText=/C:[\\/]Users[\\/]|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{30,}|sk-proj-[A-Za-z0-9_-]{30,}/;
const failures=[];
for(const file of files){
 if(forbidden.test(file)||(/\/\.env(?:\.|$)/.test(file)&&!file.endsWith('/.env.example'))){failures.push(file);continue;}
 if(/\.(?:mjs|js|json|html|css|md|txt|yml|yaml|svg|py)$/.test(file)){
  const source=execFileSync('git',['show',':'+file],{encoding:'utf8',cwd:'..',maxBuffer:16*1024*1024});
  if(privateText.test(source))failures.push(file);
 }
}
if(failures.length){console.error('Publication boundary rejected:\n'+failures.join('\n'));process.exit(1);}
console.log(`Publication boundary passed for ${files.length} website files. This is not a comprehensive secret audit.`);
