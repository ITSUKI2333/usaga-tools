"""Reused script graph traversal; incomplete opcode coverage is reported."""
import struct,re,collections
PAT=re.compile(rb'(?:[\x30-\xff]|\x28[\x30-\xff]|[\x29-\x2e][\x00-\xff]|\x2f[\x00-\x13])+')
def infer_lengths(x,syms):
 lengths={};evidence=[]
 for s in syms:
  if s['type']!='FUNC' or not re.fullmatch('MESS_code[0-9a-f]{2}(?:[0-9a-f]{2})?',s['name']):continue
  b,_=x.elf_region(int(s['address']),int(s['size']));ws=struct.unpack('<'+'I'*(len(b)//4),b);values=[]
  for i,w in enumerate(ws):
   if w>>26!=3 or (w&0x3ffffff)*4!=0x7325a0:continue
   value=None
   for k in [i+1]+list(range(i-1,max(-1,i-12),-1)):
    if k>=len(ws):continue
    q=ws[k];op=q>>26;rs=q>>21&31;rt=q>>16&31;rd=q>>11&31;im=q&65535
    if op in (9,13) and rt==4:
     if rs==0:value=im if im<32768 else im-65536
     break
    if (op==0 and rd==4) or (op in (32,33,35,36,37,55) and rt==4):break
   values.append(value)
  if values and None not in values and len(set(values))==1 and values[0]>0:
   code=bytes.fromhex(s['name'][9:]);lengths[code]=values[0]
   evidence.append(dict(opcode=code.hex(' '),length=values[0],function=s['name'],function_address=hex(int(s['address'])),basis='constant argument to set_next_seqadr; static inference'))
 # Explicit sizes independently checked in handler disassembly. Branches are explored both ways.
 manual={b'\x00':1,b'\x01':1,b'\x02':5,b'\x03':5,b'\x04':5,b'\x05':5,b'\x06':5,b'\x07':5,b'\x16\x14':7,b'\x16\x06':8,b'\x16\x07':8}
 for sub,n in {0:2,1:14,2:20,3:2,4:2,5:2,6:2,7:2,8:10,9:10,10:10,11:10,12:7,13:7,14:7,15:7,16:16,17:19,255:10}.items():
  manual[bytes([15,sub])]=n
 for sub in (0,16,17,18,32):manual[bytes([14,sub])]=2
 lengths.update(manual)
 byaddr={int(s['address']):s['name'] for s in syms if s['type']=='FUNC'}
 byname={s['name']:s for s in syms}
 # Dispatch tables contain many aliases (e.g. 12 31 uses handler MESS_code1230).
 for table in syms:
  if not re.fullmatch('mess_func_tbl_code[0-9a-f]{2}',table['name']):continue
  prefix=bytes.fromhex(table['name'][-2:]);blob,_=x.elf_region(int(table['address']),int(table['size']))
  for sub,addr in enumerate(struct.unpack('<'+'I'*(len(blob)//4),blob)):
   name=byaddr.get(addr,'')
   if not re.fullmatch('MESS_code[0-9a-f]{4}',name):continue
   canonical=bytes.fromhex(name[9:])
   if canonical in lengths:
    code=prefix+bytes([sub]);lengths[code]=lengths[canonical]
    if code!=canonical:evidence.append(dict(opcode=code.hex(' '),length=lengths[code],function=name,function_address=hex(addr),basis='actual ELF dispatch-table alias'))
 return lengths,evidence

def valid_bank(data):
 if len(data)<8:return None
 n=struct.unpack_from('<I',data)[0]
 if not 0<n<=1024 or 4+n*4>len(data):return None
 entries=struct.unpack_from('<'+'I'*n,data,4)
 if not all(4+n*4<=p<len(data) for p in entries):return None
 return list(entries)

def pointer_pool(data,header):
 # A contiguous, aligned bank-relative pointer table ends at its lowest target.
 p=header;lowest=len(data);targets=[];zeros=0
 while p+4<=lowest and p+4<=len(data):
  v=struct.unpack_from('<I',data,p)[0]
  if v==0:
   zeros+=1
   if zeros>32:break
  elif header<=v<len(data):targets.append(v);lowest=min(lowest,v);zeros=0
  else:break
  p+=4
 if len(targets)>=4 and p==lowest:return sorted(set(targets)),p
 return [],header

def make_record(x,bank,data,p,base,evidence):
 text,end,u,ids=x.decode_run(data,p)
 if not ids or end>=len(data) or len(ids)>=4096 or data[end]>=0x27:return None,end
 return dict(id='',bank=bank,iso_offset=base+p,iso_offset_hex=f'0x{base+p:X}',byte_length=end-p,glyph_count=len(ids),text=text,raw_hex=data[p:end].hex(' '),terminator_hex=f'{data[end]:02X}',evidence=evidence,unknown_glyphs=';'.join(map(str,u))),end

def language_candidate(r,minimum=8):
 if not r or r['unknown_glyphs'] or r['glyph_count']<minimum:return False
 t=r['text'];jp=sum('\u3040'<=c<='\u9fff' for c in t);kana=sum('\u3041'<=c<='\u30fa' for c in t)
 return jp>=minimum*.6 and kana>=3 and jp/len(t)>=.75

def graph_bank(x,bank,data,base,entries,lengths):
 found={};gaps=[];edges=[];controls=[];visited=set();queue=collections.deque()
 pool,pool_end=pointer_pool(data,4+4*len(entries))
 for p in entries+pool:queue.append((p,'bank_entry' if p in entries else 'pointer_table'))
 for m in re.finditer(b'\x16[\x10\x1b]',data):queue.append((m.start(),'display_command_anchor'))
 # Strong, control-terminated natural-language strings can seed otherwise unreferenced text pools.
 unconfirmed=[];cluster=[];cluster_end=-1
 def flush_cluster():
  if len(cluster)>=3 and any(language_candidate(r) for r in cluster):
   for r in cluster:queue.append((r['iso_offset']-base,'contiguous_text_pool'))
 for m in PAT.finditer(data,pool_end):
  r,end=make_record(x,bank,data,m.start(),base,'unreferenced_candidate')
  if m.start()!=cluster_end:flush_cluster();cluster=[]
  if r and r['terminator_hex']=='01':cluster.append(r);cluster_end=end+1
  else:flush_cluster();cluster=[];cluster_end=-1
  if r and language_candidate(r):
   unconfirmed.append(r)
   if r['terminator_hex']=='01' and (data[m.start()-1:m.start()]==b'\x01'):
    queue.append((m.start(),'adjacent_text_pool_candidate'))
 flush_cluster()
 while queue:
  p,origin=queue.popleft()
  steps=0
  while 0<=p<len(data) and p not in visited and steps<20000:
   visited.add(p);steps+=1;c=data[p]
   if c>=0x27:
    r,end=make_record(x,bank,data,p,base,origin)
    if r:
     if origin!='adjacent_text_pool_candidate' or language_candidate(r):
      if not (origin=='display_command_anchor' and r['glyph_count']<4 and r['terminator_hex']=='00'):found[p]=r
     p=end;continue
    gaps.append((p,'font_special_or_invalid_run',data[p:p+12].hex(' ')));break
   if c in (0,1):break
   code=data[p:p+2] if 0x0e<=c<=0x1f else data[p:p+1]
   size=lengths.get(code)
   if code==b'\x16\x05' and p+2<len(data):
    if data[p+2] <= 4:size=3 if data[p+2]==3 else 7
    else:size=None
   if size is None:
    gaps.append((p,'unsupported_opcode',data[p:p+12].hex(' ')));break
   if p+size>len(data):gaps.append((p,'truncated_opcode',code.hex(' ')));break
   controls.append(dict(bank=bank,iso_offset_hex=hex(base+p),opcode=code.hex(' '),byte_length=size,raw_hex=data[p:p+size].hex(' ')))
   if c in (2,3,4,5,6,7):
    target=struct.unpack_from('<I',data,p+1)[0]
    if 0<target<len(data):
     queue.append((target,'direct_script_reference'))
     edges.append(dict(bank=bank,from_iso_hex=hex(base+p),target_iso_hex=hex(base+target),opcode=code.hex(' ')))
   if code==b'\x16\x14' and data[p+2]==3:
    # MESS_code1614 receives a descriptor after the two-byte dispatch.
    # Only mode 3 is a plain local offset; other work/global modes are dynamic.
    target=struct.unpack_from('<I',data,p+3)[0]
    if 0<target<len(data):queue.append((target,'object_label_reference'))
   if c==2:break
   p+=size
   if code in (b'\x16\x10',b'\x16\x1b'):origin='display_command_anchor'
 return found,unconfirmed,gaps,edges,controls,len(pool),len(visited)
