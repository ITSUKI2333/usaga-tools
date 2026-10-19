"""Translation inheritance for all known MES/TONO5 occurrences, independent of UI prefix.
Direct address translations take priority; ambiguous identical strings are not guessed.
This module never writes game files and does not build an ISO.
"""
import csv,collections,re
from pathlib import Path

TOKEN=re.compile(r'��������[0-9A-Fa-f]{4}��')
def load_inputs(folder):
 direct=collections.defaultdict(list);byraw=collections.defaultdict(list);tables=[];skips=[]
 for p in sorted(Path(folder).glob('*.csv')):
  with p.open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
  if not rows:continue
  field=next((k for k in ('translation_zh','���ķ���') if k in rows[0]),None)
  if not field or not {'iso_offset','raw_hex','byte_length','text'}<=set(rows[0]):continue
  tables.append(dict(file=p.name,rows=len(rows),field=field))
  for n,row in enumerate(rows,2):
   if row.get('unknown_glyphs')=='SCRIPT_ENTRY':skips.append(dict(file=p.name,line=n,reason='script_entry_not_text'));continue
   text=row[field]
   if not text.strip():continue
   q=dict(file=p.name,line=n,off=int(row['iso_offset']),raw=bytes.fromhex(row['raw_hex']),original=row['text'],translation=text,category=row.get('category',''),formal=field=='translation_zh',table_index=row.get('table_index',''))
   assert len(q['raw'])==int(row['byte_length'])
   assert TOKEN.findall(q['original'])==TOKEN.findall(text)
   direct[q['off']].append(q);byraw[q['raw']].append(q)
 return direct,byraw,tables,skips

def resolve_catalog(folder,occurrences,is_supported):
 direct,byraw,tables,skips=load_inputs(folder);resolved={};conflicts=[];ambiguous=[]
 for off,choices in direct.items():
  formal=[q for q in choices if q['formal']];active=formal or choices
  if len({q['translation'] for q in active})!=1:conflicts.append(dict(iso=hex(off),choices=[dict(file=q['file'],translation=q['translation']) for q in active]));continue
  resolved[off]=dict(active[0],resolution='direct_address',inherited=False)
 for row in occurrences:
  off=int(row['iso_offset']);raw=bytes.fromhex(row['raw_hex'])
  if off in resolved or off in direct or raw not in byraw or not is_supported(off,len(raw)):continue
  choices=byraw[raw];translations={q['translation'] for q in choices}
  if len(translations)!=1:
   ambiguous.append(dict(iso=hex(off),original=row['text'],translations=sorted(translations),reason='context_sensitive_same_original; no automatic overwrite'));continue
  resolved[off]=dict(choices[0],off=off,resolution='unique_exact_raw_inheritance_all_prefixes',inherited=True)
 return dict(resolved=resolved,conflicts=conflicts,ambiguous=ambiguous,tables=tables,skips=skips)
