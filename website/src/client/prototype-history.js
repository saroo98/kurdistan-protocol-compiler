/* The supplied prototype expects URL history. An opaque sandbox must not get
   same-origin privileges merely to satisfy that expectation. Keep its fragment
   navigation in memory instead. This adapter changes no VPN/profile decisions. */
(function(){
 if(window.parent===window)return;
 const entries=[{state:null,fragment:''}];let index=0;
 function check(url){if(url!==undefined&&url!==null&&!/^#[a-z0-9-]{0,120}$/.test(String(url)))throw new TypeError('The embedded prototype permits local screen fragments only.');return String(url||'');}
 function clone(value){return value==null?value:JSON.parse(JSON.stringify(value));}
 Object.defineProperty(history,'state',{configurable:true,get:()=>clone(entries[index].state)});
 history.replaceState=(state,unused,url)=>{entries[index]={state:clone(state),fragment:check(url)}};
 history.pushState=(state,unused,url)=>{const entry={state:clone(state),fragment:check(url)};entries.splice(index+1);entries.push(entry);index++};
 history.go=(delta=0)=>{if(!Number.isInteger(delta))return;const next=Math.min(entries.length-1,Math.max(0,index+delta));if(next===index)return;index=next;dispatchEvent(new PopStateEvent('popstate',{state:clone(entries[index].state)}))};
 history.back=()=>history.go(-1);history.forward=()=>history.go(1);
})();
