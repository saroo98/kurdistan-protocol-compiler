// Guarded synchronous local preferences. No location detection or network request.
try {
 const p=JSON.parse(localStorage.getItem('kurdistan-site-preferences')||'null');
 if(p){const r=document.documentElement;
  if(['light','dark'].includes(p.theme))r.dataset.theme=p.theme;
  if(p.largeText===true)r.dataset.text='large';
  if(p.contrast===true)r.dataset.contrast='strong';
  if(p.simple===true)r.dataset.mode='simple';
  if(p.reducedMotion===true)r.dataset.motion='reduce';
 }
} catch { /* Readable system appearance is the fallback. */ }
