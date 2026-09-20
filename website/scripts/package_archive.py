"""Portable project archive. Authorized fonts included; private references excluded."""
import hashlib,json,sys,zipfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();output=Path(sys.argv[2]).resolve()
exclude_dirs={'node_modules','.git','.venv','venv','__pycache__','.pytest_cache','.cache','playwright-report','test-results','tmp','.local','references','private-originals'}
exclude_ext={'.pyc','.pyo'}
files=[]
for p in sorted(root.rglob('*')):
 rel=p.relative_to(root)
 if any(part in exclude_dirs for part in rel.parts):continue
 if p.is_symlink():raise RuntimeError('Refusing to package a symlink: '+str(rel))
 if not p.is_file() or p.suffix.lower() in exclude_ext:continue
 if p.name in ('HANDOFF_MANIFEST.json','HANDOFF_INTEGRITY.json'):continue
 if p.name.startswith('.env') and p.name!='.env.example':continue
 files.append((p,rel))
for required in ['README.md','LICENSE','package.json','package-lock.json','site.config.mjs','dist/en/index.html','dist/ckb/index.html','dist/kmr/index.html','src/i18n/messages.json','qa/QA_REPORT.md','qa/verification-receipt.json','docs/LIMITATIONS.md']:
 assert (root/required).is_file(),required
rows=[]
with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p,rel in files:
  data=p.read_bytes();rows.append({'path':str(rel).replace('\\','/'),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()});z.writestr('KurdistanVPN_Website/'+str(rel).replace('\\','/'),data)
 integrity=json.dumps({'scope':'Unsigned portable handoff file integrity, not a VPN release signature','files':{r['path']:{'bytes':r['bytes'],'sha256':r['sha256']} for r in rows}},indent=2)
 z.writestr('KurdistanVPN_Website/HANDOFF_INTEGRITY.json',integrity)
 (root/'HANDOFF_INTEGRITY.json').write_text(integrity,encoding='utf-8')
with zipfile.ZipFile(output) as z:
 assert len(z.namelist())==len(set(z.namelist())),'Duplicate ZIP entries'
 assert z.testzip() is None,'ZIP CRC failed'
 for member in z.namelist():
  path=Path(member);assert '..' not in path.parts and not path.is_absolute();assert path.suffix.lower() not in exclude_ext;assert 'node_modules' not in path.parts
 for r in rows:
  data=z.read('KurdistanVPN_Website/'+r['path']);assert hashlib.sha256(data).hexdigest()==r['sha256']
print(f'ZIP verified: {len(rows)} project files + handoff manifest; {output.stat().st_size:,} bytes')
print('SHA-256: '+hashlib.sha256(output.read_bytes()).hexdigest())
