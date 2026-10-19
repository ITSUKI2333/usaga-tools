"""Exact-pointer aliases at two TEXT-ONLY gates. No ISO writer or side effects."""

import struct

from .usaga_cn_extended_codec import Asm,CPU

MAGIC=int.from_bytes(b'UTX1','little')

def make_stubs(original_elf,meta):

 base=int(meta['stub_end'],0);context=int(meta['resource_loaders']['asset_relocation_context'],0);blocks={};cursor=base

 blob=bytearray()

 def li(a,r,v):a.i(15,r,'zero',v>>16);a.i(13,r,r,v&65535)

 def emit(name,a):

  nonlocal cursor

  b=a.finish();assert a.base==cursor;blocks[name]=dict(address=hex(cursor),bytes=len(b));blob.extend(b);cursor+=len(b);pad=(-cursor)%16;blob.extend(bytes(pad));cursor+=pad;return a.base

 # Leaf lookup: a0=original text pointer, a1=0 pure raw / 1 script.

 # Loader context is OLD associated start/end and growth delta, NOT a bank id.

 a=Asm(cursor);a.r(33,'v0','a0');a.branch(4,'a1','zero','resource');li(a,'t1',0x8733a0);a.i(35,'t1','t1',0);a.i(36,'t1','t1',129);a.i(12,'t1','t1',0x30);a.branch(5,'t1','zero','done');a.label('resource');li(a,'t0',0x8733b8);a.i(35,'t0','t0',0);li(a,'t1',context);a.i(35,'t2','t1',0);a.r(43,'t3','t0','t2');a.branch(4,'t3','zero','done')

 a.r(35,'t2','t2','t0');a.r(35,'t3','a0','t0');a.r(43,'t4','t3','t2');a.branch(4,'t4','zero','done')

 a.i(35,'t1','t1',8);a.r(33,'t1','t1','t2');a.r(2,'t4','zero','t1',20);a.branch(5,'t4','zero','done');a.i(9,'t4','zero',16);a.r(43,'t4','t1','t4');a.branch(5,'t4','zero','done')

 a.r(33,'t4','t0','t1');a.i(35,'t5','t4',-16);li(a,'at',MAGIC);a.branch(5,'t5','at','done');a.i(35,'t5','t4',-4);a.branch(5,'t5','t2','done')

 a.i(35,'t2','t4',-8);a.i(11,'t5','t2',31);a.branch(4,'t5','zero','done');a.i(35,'t5','t4',-12)

 # Verify table end <= footer start before dereferencing its entries.

 a.r(0,'t4','zero','t2',3);a.r(0,'at','zero','t2',2);a.r(33,'t4','t4','at');a.r(33,'t4','t4','t5');a.i(9,'t1','t1',-16);a.r(43,'t4','t1','t4');a.branch(5,'t4','zero','done');a.r(33,'t5','t5','t0')

 a.label('loop');a.branch(4,'t2','zero','done');a.i(35,'t4','t5',0);a.branch(4,'t4','t3','found');a.i(9,'t5','t5',12);a.i(9,'t2','t2',-1);a.branch(4,'zero','zero','loop')

 a.label('found');a.i(35,'t4','t5',4);a.branch(4,'a1','zero','dest');a.i(35,'t4','t5',8);a.label('dest');a.r(43,'at','t4','t1');a.branch(4,'at','zero','done');a.r(33,'v0','t0','t4')

 a.label('done');a.r(8,'zero','ra');a.nop();lookup=emit('lookup',a)

 # A scoped call gate replaces only MESS_code1614's text resolver JAL, never the

 # generic _get_mess_adr entry or either image resolver site.

 a=Asm(cursor);a.i(9,'sp','sp',-32);a.i(63,'ra','sp',16);a.j(0x7328a0,True);a.r(33,'a0','v0');a.r(33,'a1','zero');a.j(lookup,True);a.i(55,'ra','sp',16);a.i(9,'sp','sp',32);a.r(8,'zero','ra');a.nop();raw_gate=emit('raw_1614_gate',a)

 # Script gate is called only after the VM has classified its cursor as FONT.

 a=Asm(cursor);a.i(9,'sp','sp',-64)

 for i,reg in enumerate(('a0','a1','a2','a3','ra')):a.i(63,reg,'sp',i*8)

 li(a,'t0',0x8733a4);a.i(35,'a0','t0',0);a.i(9,'a1','zero',1);a.j(lookup,True);a.branch(4,'v0','a0','restore');li(a,'t0',0x8733a4);a.i(43,'v0','t0',0);li(a,'t0',0x8733a0);a.i(35,'t0','t0',0);a.i(43,'v0','t0',200)

 a.label('restore')

 for i,reg in enumerate(('a0','a1','a2','a3','ra')):a.i(55,reg,'sp',i*8)

 a.i(9,'sp','sp',64)

 # Replay exact original prologue after restoring the caller's frame/arguments.

 a.words.extend(struct.unpack_from('<II',original_elf,384+0x744750-0x700000));a.j(0x744758);script_gate=emit('script_FONT_gate',a)

 assert cursor<=0x9e0000,('code would overlap font buffer',hex(cursor))

 

 return bytes(blob), dict(blocks=blocks, stub_start=hex(base), stub_end=hex(cursor), context=hex(context))



def patch_gates(elf,meta,original_elf):

 b=bytearray(elf);blob,spec=make_stubs(original_elf,meta);va=meta['primary_load_vaddr'];fileoff=meta['primary_load_file_offset'];start=int(spec['stub_start'],0);end=int(spec['stub_end'],0)

 def put(addr,data):b[fileoff+addr-va:fileoff+addr-va+len(data)]=data

 def read(addr,n):return bytes(b[fileoff+addr-va:fileoff+addr-va+n])

 assert read(0x744750,8)==original_elf[384+0x744750-0x700000:384+0x744758-0x700000]

 assert read(0x75b1e8,4)==struct.pack('<I',(3<<26)|(0x7328a0>>2))

 assert end<=0x9e0000 and fileoff+end-va<=len(b)

 put(start,blob);put(0x744750,struct.pack('<II',(2<<26)|(int(spec['blocks']['script_FONT_gate']['address'],0)>>2),0))

 put(0x75b1e8,struct.pack('<I',(3<<26)|(int(spec['blocks']['raw_1614_gate']['address'],0)>>2)))

 ph=struct.unpack_from('<I',b,28)[0];count=struct.unpack_from('<H',b,44)[0]

 seg=next(ph+i*32 for i in range(count) if struct.unpack_from('<I',b,ph+i*32)[0]==1 and struct.unpack_from('<I',b,ph+i*32+8)[0]==va)

 assert struct.unpack_from('<I',b,seg+16)[0]==start-va

 struct.pack_into('<I',b,seg+16,end-va);meta['new_filesz']=end-va;meta['stub_end']=hex(end);meta['text_address_aliases']=spec

 assert read(0x7328a0,1124)==original_elf[384+0x7328a0-0x700000:384+0x732d04-0x700000]

 assert len(b)==len(elf)

 return bytes(b),meta



def verify_gates(ee,meta,resources,entries):

 spec=meta['text_address_aliases'];base=int(spec['stub_start'],0);context=int(spec['context'],0)

 raw_gate=int(spec['blocks']['raw_1614_gate']['address'],0);lookup=int(spec['blocks']['lookup']['address'],0);script_gate=int(spec['blocks']['script_FONT_gate']['address'],0)

 off=meta['primary_load_file_offset']+base-meta['primary_load_vaddr'];blob=ee[off:off+int(spec['stub_end'],0)-base]

 # Execute real original resolver plus prototype MIPS gates in local EE memory.

 cpu=CPU(ee);assert bytes(cpu.mem[base:base+len(blob)])==blob;mem=cpu.mem;BASE=0xc00000;OBJ=0x2000;DESC=0x3000

 p32=lambda a,v:struct.pack_into('<I',mem,a,v)

 p32(0x8733b8,BASE);p32(0x8733a0,OBJ);mem[OBJ+129]=0

 positive=negative=fontgatecases=0

 if True:

  for BASE in (0xc00000,0x1e00000):

   p32(0x8733b8,BASE)

   for bank,r in resources.items():

    data=r['data'];mem[BASE:BASE+len(data)]=data;p32(context,BASE+r['original_size']);p32(context+4,BASE+r['original_size']+2048);p32(context+8,len(data)-r['original_size'])

    for q in [z for z in entries if z['bank']==bank]:

     for mode in (0,1):

      got=cpu.run(lookup,BASE+q['old'],mode,max_steps=2000)[2];expect=BASE+q['raw_dest' if mode==0 else 'script_dest'];assert got==expect;positive+=1

     # Original _get_mess_adr executes, not mocked.

     p32(DESC,q['old']);got=cpu.run(raw_gate,DESC,1,max_steps=2400)[2];assert got==BASE+q['raw_dest'];positive+=1

     p32(0x8733a4,BASE+q['old']);p32(OBJ+200,BASE+q['old'])

     seen=[]

     def original_font_prologue(c,regs):

      seen.append((struct.unpack_from('<I',mem,0x8733a4)[0],struct.unpack_from('<I',mem,OBJ+200)[0],regs[4:6]))

      regs[31]=int.from_bytes(mem[regs[29]+48:regs[29]+56],'little');regs[29]+=64

     cpu.hooks[0x744758]=original_font_prologue

     regs=cpu.run(0x744750,123,456,max_steps=2400);assert seen==[(BASE+q['script_dest'],BASE+q['script_dest'],[123,456])];assert regs[29]==0x1ff0000;fontgatecases+=1

    # Script continuations use local MES offsets; reject TONO/work namespaces.

    guardptr=BASE+next(z['old'] for z in entries if z['bank']==bank)

    for namespace in (0x10,0x20,0x30):

     mem[OBJ+129]=namespace;assert cpu.run(lookup,guardptr,1,max_steps=2000)[2]==guardptr;negative+=1

    mem[OBJ+129]=0

    for ptr in (BASE-1,BASE+r['original_size'],BASE+len(data)-1,BASE+0x7ffff,0x400000,0):

     for mode in (0,1):assert cpu.run(lookup,ptr,mode,max_steps=2000)[2]==ptr;negative+=1

    # Adjacent addresses must not accidentally match a dictionary entry.

    olds={z['old'] for z in entries if z['bank']==bank}

    for q in [z for z in entries if z['bank']==bank]:

     for delta in (-1,1):

      if q['old']+delta not in olds:

       ptr=BASE+q['old']+delta;assert cpu.run(lookup,ptr,1,max_steps=2000)[2]==ptr;negative+=1

    footer=BASE+len(data)-16;keep=bytes(mem[footer:footer+16]);ptr=BASE+next(z['old'] for z in entries if z['bank']==bank)

    for offset,value in ((0,0),(8,31),(4,len(data)+4),(12,r['original_size']+1)):

     p32(footer+offset,value);assert cpu.run(lookup,ptr,1,max_steps=2000)[2]==ptr;negative+=1;mem[footer:footer+16]=keep

    # Missing/mismatched loader context is rejected before unsafe footer reads.

    old=struct.unpack_from('<I',mem,context)[0];p32(context,0);assert cpu.run(lookup,ptr,0,max_steps=2000)[2]==ptr;negative+=1;p32(context,old)

 return dict(positive=positive,script_entry_cases=fontgatecases,negative=negative,original_font_body_mocked=True,original_resolver_executed=True,elf_loaded_stubs=True,load_bases=["0xC00000","0x1E00000"])

