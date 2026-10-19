"""Conservative overflow recovery on BUILD COPIES only; no ISO/file writer.

Native source instruction boundaries and structural dispatch-table proofs are

kept distinct from emulator observations. Never shortens a translation.

"""

import struct

from .usaga_ui_layout import graph,native_lengths



class OverflowRecovery:

 def __init__(self,elf,symbols,allraw,resources):

  self.lengths=native_lengths(elf,symbols);self.resources=resources;self.cache={};self.decisions=[]

  self.texts={}

  for key,r in resources.items():

   self.texts[key]={int(x['iso_offset'])-r['start']:x for x in allraw if r['start']<=int(x['iso_offset'])<r['start']+len(r['original'])}

 def nodes(self,key):

  if key not in self.cache:

   data=self.resources[key]['original'];roots=[];pos=0

   # Native description tables are indexed directly, beyond primary MES entry

   # tables. Admit only aligned arrays of >=4 bank-relative pointers, all to

   # exact 12 10 <attribute> / 16 10 display-function starts after the array.

   # Partial runs within a larger proven table are allowed; random string bytes

   # and raw-name pointer tables never satisfy this script-entry grammar.

   while pos+16<=len(data):

    begin=pos;values=[]

    while pos+4<=len(data):

     target=struct.unpack_from('<I',data,pos)[0]

     if not pos+4<=target<len(data)-5 or data[target:target+2]!=b'\x12\x10' or data[target+3:target+5]!=b'\x16\x10':break

     values.append(target);pos+=4

    if len(values)>=4 and min(values)>=pos:roots.extend(values)

    pos=max(begin+4,pos)

   # The four independently checked MES17 description tables also contain raw

   # FONT default entries. Such defaults split the prefix-only runs above and

   # can isolate legitimate one-off descriptions. Seed the COMPLETE verified

   # arrays, and accept a mirror in MES206 only when all 256/645 entry signatures

   # match MES17, not merely when nearby text looks similar.

   if key in ('17','206') and '17' in self.resources:

    reference=self.resources['17']['original']

    for table,n in ((0x10,645),(0x5b40,256),(0x6780,256),(0x7310,256)):

     refptr=struct.unpack_from('<'+'I'*n,reference,table)

     assert min(refptr)>=table+4*n and all(0<=p<len(reference) for p in refptr)

     signatures=[reference[p:p+12] for p in refptr]

     matches=[table] if key=='17' else []

     if key=='206':

      for field in range(4,len(data)-n*4,4):

       first=struct.unpack_from('<I',data,field)[0]

       if not field+n*4<=first<len(data) or data[first:first+12]!=signatures[0]:continue

       vals=struct.unpack_from('<'+'I'*n,data,field)

       if all(field+n*4<=p<len(data) and data[p:p+12]==sig for p,sig in zip(vals,signatures)):matches.append(field)

     for field in matches:

      vals=struct.unpack_from('<'+'I'*n,data,field);roots.extend(vals)

      gap=field+4*n;first=min(vals)

      # The native unknown-ability fallback lies directly between its array and

      # the first referenced script: one complete display function, ending 01.

      if 5<first-gap<=32 and data[gap:gap+5]==b'\x12\x10\x02\x16\x10' and data[first-1]==1:roots.append(gap)

   self.cache[key]=graph(data,self.lengths,self.texts[key],extra_roots=sorted(set(roots)))

  return self.cache[key][0]

 def recover(self,q,allocate,pointer_edits):

  key=q['bank'];r=self.resources[key];d=r['original'];a=q['off']-r['start'];raw=q['raw'];enc=q['encoded'];end=a+len(raw);ns=self.nodes(key)

  decision=dict(original_iso=hex(q['off']),resource=key,raw_hex=raw.hex(' '),encoded_hex=enc.hex(' '))

  # A scanner may absorb FF padding before an independently addressed string.

  # Redirect only typed descriptor fields or an exact native instruction grammar;

  # do not overwrite the padding or any neighboring compiled instructions.

  pad=len(raw)-len(raw.lstrip(b'\xff'))

  if pad in (1,2) and d[end]==1:

   target=a+pad;fields=[];pos=0

   while (pos:=d.find(struct.pack('<I',target),pos))>=0:

    typed=(pos>=3 and d[pos-3:pos]==b'\x16\x14\x03' and pos-3 in ns and ns[pos-3]['key']==b'\x16\x14')

    call=(pos>=9 and d[pos-9:pos-7]==b'\x12\x40' and d[pos-3:pos]==b'\x11\x33\x03' and d[pos+4:pos+9]==b'\x12\x10\x00\x16\x4d')

    if typed or call:fields.append((pos,'typed_1614' if typed else '1240_1133_03_1210_164d_grammar'))

    pos+=1

   if fields:

    new=allocate(r,enc+b'\x01')

    if new is not None:

     for field,basis in fields:

      assert bytes(r['data'][field:field+4])==d[field:field+4]

      struct.pack_into('<I',r['data'],field,new)

      pointer_edits.append(dict(bank=key,field_iso=hex(r['start']+field),old=hex(target),new=hex(new),basis=basis))

     decision.update(result='recovered',basis='independently_addressed_string_after_FF_padding',padding_bytes=pad,actual_original_start=hex(target),new_text=hex(new),fields=[dict(offset=hex(p),basis=b) for p,b in fields],payload=(enc+b'\x01').hex(' '),translation_preserved_verbatim=True)

     self.decisions.append(decision);return ('relocated_actual_entry_after_padding',new)

  # The six 2780 children and any immediate-field false positives must never be

  # promoted to text entries merely because a byte happens to look printable.

  owners=[(p,n) for p,n in ns.items() if p<a<p+n['size']]

  if owners:

   p,n=owners[0];decision.update(result='not_an_instruction_start',owner_offset=hex(p),owner_opcode=n['key'].hex(),owner_size=n['size']);self.decisions.append(decision);return None

  p=a

  while p<end and p in ns and ns[p]['key']==b'FONT':p+=ns[p]['size']

  proven=(p==end and a in ns)

  prefix=d[a-2:a] if a>=2 else b''

  # Short standalone display functions are also recognized structurally. This

  # is bytecode grammar evidence, not a claim of runtime reachability.

  standalone=(len(raw)==2 and prefix==b'\x16\x1b' and a>=3 and d[a-3]==1 and d[end:end+3]==b'\x01\x16\x1b')

  if not proven and not standalone:

   decision.update(result='no_proven_consumer');self.decisions.append(decision);return None

  anchor=a;pre=b'';finish=end;consume_return=False

  if len(raw)<5:

   if proven and a-2 in ns and ns[a-2]['key'] in (b'\x16\x1b',b'\x16\x10',b'\x16\x04',b'\x15\x0e'):

    anchor=a-2;pre=prefix

   elif standalone:anchor=a-2;pre=prefix

   # A one-character coloured span plus 16 10 is only four bytes. Borrow the

   # PRECEDING complete 12 10 <attribute> instruction, never part of its operand.

   # Replay both controls in the payload; the interior-entry check below still

   # rejects any separate caller that would enter bytes 1..4 of this trampoline.

   if finish-anchor<5 and proven and anchor==a-2 and a-5 in ns and ns[a-5]['key']==b'\x12\x10' and ns[a-5]['size']==3 and ns[a-2]['key']==b'\x16\x10':

    anchor=a-5;pre=d[anchor:a]

   if finish-anchor<5 and d[end]==1:finish+=1;consume_return=True

  if finish-anchor<5:

   decision.update(result='span_still_too_small');self.decisions.append(decision);return None

  # An explicit branch into bytes 1..4 of a trampoline would become invalid.

  # Never silently change such a second entry.

  entries={n['target'] for n in ns.values() if n.get('target') is not None};entries.update(self.nodes_roots(key))

  if any(anchor<t<anchor+5 for t in entries):

   decision.update(result='interior_entry_conflict');self.decisions.append(decision);return None

  if bytes(r['data'][anchor:finish])!=d[anchor:finish]:

   decision.update(result='existing_edit_conflict');self.decisions.append(decision);return None

  payload=pre+enc+(b'\x01' if consume_return else b'\x02'+struct.pack('<I',end))

  new=allocate(r,payload)

  if new is None:

   decision.update(result='resource_limit');self.decisions.append(decision);return None

  r['data'][anchor:anchor+5]=b'\x02'+struct.pack('<I',new)

  assert bytes(r['data'][new:new+len(payload)])==payload

  assert bytes(r['data'][end:end+1])==d[end:end+1] or consume_return

  decision.update(result='recovered',basis='native_graph_FONT' if proven else 'standalone_display_return_grammar',anchor=hex(anchor),continuation=hex(end),consumed_return=consume_return,new_text=hex(new+len(pre)),payload=payload.hex(' '))

  self.decisions.append(decision)

  pointer_edits.append(dict(bank=key,field_iso=hex(r['start']+anchor+1),old='original script span',new=hex(new),basis=decision['basis'],consumed_return=consume_return))

  return (('relocated_verified_font_span_return' if consume_return else 'relocated_verified_font_span') if proven else 'relocated_complete_short_display',new+len(pre))

 def nodes_roots(self,key):

  self.nodes(key);return self.cache[key][1]

