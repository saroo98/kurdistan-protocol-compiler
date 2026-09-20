/** Read only the current page's build-checked UI dictionary, lazily after DOM setup. */
let dictionaryElement, dictionaryMessages;
export function msg(key,values={}){
 const el=globalThis.document?.getElementById?.('ui-messages');
 if(!el)throw new Error('Missing built interface dictionary');
 if(el!==dictionaryElement){dictionaryElement=el;dictionaryMessages=JSON.parse(el.textContent||'{}');}
 const value=dictionaryMessages[key];
 if(typeof value!=='string')throw new Error('Missing built interface message: '+key);
 return value.replace(/\{([a-z]+)\}/g,(_,name)=>String(values[name]??''));
}
export function announce(value){const el=document.getElementById('site-announcer');if(el)el.textContent=value;}
