"""Isolate invalid native window addresses without skipping VM instructions.
The nine real 0x1804-byte windows retain their exact original address and code.
"""
import struct
from .usaga_cn_extended_codec import Asm,REG
REG.update(t9=25,s3=19,s4=20,s5=21,s6=22,s7=23)
POOL=0x878bd0
STRIDE=0x1804
COUNT=9

def patch_window_isolation(source,meta):
 b=bytearray(source);off=meta['primary_load_file_offset'];va=meta['primary_load_vaddr']
 read=lambda a,n:bytes(b[off+a-va:off+a-va+n])
 def put(a,data):b[off+a-va:off+a-va+len(data)]=data
 page=int(meta['two_page_font']['page1_ram'],0);dummy=page+meta['two_page_font']['ee_extra_buffer_bytes']
 assert dummy+STRIDE<0xa50000
 cursor=(int(meta['stub_end'],0)+15)&~15;begin=cursor
 def li(a,r,v):a.i(15,r,'zero',v>>16);a.i(13,r,r,v&65535)
 sites=[]
 # All indexed 872800+63D0 materializers in the text/window subsystem.
 for pc in range(0x730000,0x780000,4):
  word=struct.unpack('<I',read(pc,4))[0]
  if word>>26==9 and word&65535==0x63d0:
   assert struct.unpack('<I',read(pc-4,4))[0]&63==33
   sites.append(pc)
 # Explicit pool-base forms: wind_close and both font-effect constructors.
 sites+= [0x735714,0x75beac,0x75bfc0]
 records=[]
 for pc in sorted(sites):
  w,nextword=struct.unpack('<2I',read(pc,8));op=w>>26
  assert op==9 or (op==0 and w&63==33),(hex(pc),hex(w))
  dest=(w>>16&31) if op==9 else (w>>11&31)
  assert dest not in (0,1,25,29)
  assert nextword>>26 not in (1,2,3,4,5,6,7) and not (nextword>>26==0 and nextword&63 in (8,9))
  previous=struct.unpack('<I',read(pc-4,4))[0]
  assert previous>>26 not in (1,2,3,4,5,6,7) and not(previous>>26==0 and previous&63 in (8,9))
  dr=next(n for n,v in REG.items() if v==dest)
  a=Asm(cursor);a.i(9,'sp','sp',-16);a.i(43,'at','sp',0);a.i(43,'t9','sp',4);a.words.append(w)
  li(a,'at',POOL);a.r(43,'t9',dr,'at');a.branch(5,'t9','zero','invalid')
  li(a,'at',POOL+COUNT*STRIDE);a.r(43,'t9',dr,'at');a.branch(5,'t9','zero','done')
  a.label('invalid');li(a,dr,dummy)
  # Keep the isolated sink inside its fixed 18-row/42-column allocation.
  for disp,limit in ((66,433),(72,42),(74,18)):
   a.i(37,'at',dr,disp);a.i(11,'t9','at',limit);a.branch(5,'t9','zero','ok'+str(disp));a.i(41,'zero',dr,disp);a.label('ok'+str(disp))
  a.label('done');a.i(35,'at','sp',0);a.i(35,'t9','sp',4);a.i(9,'sp','sp',16);a.words.append(nextword);a.j(pc+8)
  code=a.finish();assert cursor+len(code)<=page,(hex(pc),hex(cursor+len(code)),hex(page))
  put(cursor,code);put(pc,struct.pack('<2I',(2<<26)|(cursor>>2),0))
  records.append(dict(site=hex(pc),stub=hex(cursor),bytes=len(code),destination_register=dest,original_words=[hex(w),hex(nextword)]))
  cursor=(cursor+len(code)+15)&~15
 heap=(dummy+STRIDE+127)&~127
 assert cursor<=page and heap<0xa50000 and off+cursor-va<=len(b)
 ph=struct.unpack_from('<I',b,28)[0];n=struct.unpack_from('<H',b,44)[0];header=next(ph+i*32 for i in range(n) if struct.unpack_from('<I',b,ph+i*32+8)[0]==va)
 struct.pack_into('<2I',b,header+16,cursor-va,heap-va)
 put(0x700180,struct.pack('<I',0x3c040000|((heap+0x8000)>>16)));put(0x700188,struct.pack('<I',0x24840000|(heap&65535)));put(0x8176d4,struct.pack('<I',heap))
 result=dict(meta,stub_end=hex(cursor),heap_start=hex(heap),new_filesz=cursor-va,new_memsz=heap-va)
 result['window_isolation']=dict(pool=hex(POOL),valid_windows=COUNT,stride=STRIDE,invalid_window_original=hex(POOL+255*STRIDE),sink=hex(dummy),sink_bytes=STRIDE,stub_begin=hex(begin),sites=records,policy='valid pool addresses unchanged; invalid computed window pointers use separately reserved sink; VM instruction/control flow retained',sink_initialized='explicit bzero2 after each second-page font load',native_audio_buffer='0xa50000',all_reservations_below_audio=True)
 return bytes(b),result