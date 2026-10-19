"""Two logical 24px font pages; original GS font slot used as a row cache.

Does not allocate a new GS texture region. Only build copies are patched.

"""

import struct

from .usaga_cn_extended_codec import Asm, CPU



def patch_font_pages(source, previous, total, sectors, widths):

 b=bytearray(source); off=previous['primary_load_file_offset']; va=previous['primary_load_vaddr']

 def read(a,n):return bytes(b[off+a-va:off+a-va+n])

 def put(a,data):b[off+a-va:off+a-va+len(data)]=data

 def li(a,r,v):a.i(15,r,'zero',v>>16);a.i(13,r,r,v&65535)

 cursor=(int(previous['stub_end'],0)+127)&~127; start=cursor; blocks={}

 def emit(name,a):

  nonlocal cursor

  data=a.finish();put(a.base,data);blocks[name]=hex(a.base);cursor=(a.base+len(data)+15)&~15;return a.base

 widthbase=cursor;put(widthbase,bytes(widths['A'])+bytes(widths['B']));cursor=(cursor+total*2+15)&~15

 blocks['width_table']=hex(widthbase)

 # A coordinate carrier survives the existing packed 10-bit X field:

 # X=24*column+page. Only the final font renderer removes the 0/1 page marker.

 g=Asm(cursor);g.i(11,'t0','a1',0x100);g.branch(5,'t0','zero','short')

 g.i(11,'t0','a1',0x2830);g.branch(5,'t0','zero','legacy')

 g.i(9,'t2','a1',-0x2830);g.branch(4,'zero','zero','index')

 g.label('short');g.i(9,'t2','a1',-0x30)

 g.label('index');g.i(11,'t0','t2',total);g.branch(5,'t0','zero','valid');g.r(33,'t2','zero')

 g.label('valid');g.i(9,'t0','zero',1764);g.r(27,'zero','t2','t0');g.r(18,'t3','zero');g.r(16,'t1','zero')

 g.i(9,'t0','zero',42);g.r(27,'zero','t1','t0');g.r(18,'t1','zero');g.r(16,'t0','zero')

 # row=t1, column=t0, page=t3. Multiply by 24.

 for r in ('t0','t1'):

  g.r(0,'t4','zero',r,4);g.r(0,r,'zero',r,3);g.r(33,r,r,'t4')

 g.r(33,'t0','t0','t3');li(g,'v0',0x8865b0)

 g.i(43,'t0','v0',0);g.i(43,'t1','v0',4);g.i(9,'t3','zero',24)

 g.i(43,'t3','v0',8);g.i(43,'t3','v0',12);g.i(43,'zero','v0',16);g.i(41,'zero','v0',20)

 li(g,'t0',widthbase);li(g,'t1',0x8526c2);g.i(36,'t1','t1',0);g.branch(4,'t1','zero','width');g.i(9,'t0','t0',total)

 g.label('width');g.r(33,'t0','t0','t2');g.i(36,'t0','t0',0)

 g.branch(5,'a0','zero','fixed');g.i(43,'t0','v0',8);g.branch(4,'t2','zero','flags');g.i(9,'t3','zero',1);g.i(41,'t3','v0',20);g.branch(4,'zero','zero','flags')

 g.label('fixed');g.r(2,'t0','zero','t0',1);g.i(9,'t1','zero',12);g.r(35,'t0','t1','t0');g.i(43,'t0','v0',16)

 g.label('flags');g.i(36,'t0','v0',22);g.i(12,'t0','t0',0xfffe);g.i(40,'t0','v0',22);g.r(8,'zero','ra');g.nop()

 g.label('legacy');g.j(int(previous['old_get'],0));newget=emit('get_font',g)

 # Original entry trampolines retain their actual prologues and absolute calls.

 def trampoline(name,entry):

  a=Asm(cursor);a.words=list(struct.unpack('<2I',read(entry,8)));a.j(entry+8);return emit(name,a)

 olddraw=trampoline('original_draw',0x786e80);oldload=trampoline('original_load_font',0x72e0e0)

 state=cursor;put(state,b'\0'*128);cursor+=128;blocks['row_state']=hex(state)

 # Reserve a 512 KiB NOLOAD EE buffer beyond all code, below the patched heap.

 # Fixed address chosen after checking the resulting code does not reach it.

 page1=0x9e2000;page1_bytes=((total-1764+41)//42)*12288;assert cursor<page1 and page1+page1_bytes<=0xa50000

 l=Asm(cursor);l.i(9,'sp','sp',-32);l.i(63,'ra','sp',16);l.i(43,'a0','sp',0);l.j(oldload,True)

 l.i(35,'t0','sp',0);li(l,'a2',sectors[0]);l.branch(4,'t0','zero','load');li(l,'a2',sectors[1])

 l.label('load');li(l,'a0',page1);li(l,'a1',0x8301b8);l.i(9,'a3','zero',page1_bytes//2048);l.j(0x72cb00,True)

 li(l,'a0',page1+page1_bytes);l.i(9,'a1','zero',0x1804);l.j(0x72c4c0,True)

 l.i(55,'ra','sp',16);l.i(9,'sp','sp',32);l.r(8,'zero','ra');l.nop();newload=emit('load_font',l)

 d=Asm(cursor)

 d.r(33,'t5','zero');d.i(35,'t0','a0',0);d.i(9,'t1','zero',1);d.branch(4,'t0','t1','sprite')

 d.i(9,'t1','zero',3);d.branch(4,'t0','t1','gradient');d.branch(5,'t0','zero','original')

 # Full upload of page 0 invalidates all previous row substitutions.

 d.i(35,'t0','a0',4);li(d,'t1',0x8a6800);d.branch(5,'t0','t1','original')

 d.i(35,'t0','a0',28);d.i(9,'t1','zero',0x2b00);d.branch(5,'t0','t1','original')

 li(d,'t0',state);d.i(9,'t1','zero',42)

 d.label('reset');d.i(40,'zero','t0',0);d.i(9,'t0','t0',1);d.i(9,'t1','t1',-1);d.branch(5,'t1','zero','reset');d.j(olddraw)

 d.label('gradient');d.i(9,'t5','zero',48);d.r(33,'a0','a0','t5')

 d.label('sprite');d.i(35,'t0','a0',72);d.i(9,'t1','zero',0x2b00);d.branch(5,'t0','t1','original')

 d.i(35,'t0','a0',80);d.i(9,'t1','zero',20);d.branch(5,'t0','t1','original')

 d.i(35,'t0','a0',44);d.i(35,'t1','a0',52);d.r(35,'t1','t1','t0');d.branch(4,'t1','zero','original');d.i(11,'t2','t1',25);d.branch(4,'t2','zero','original');d.i(9,'t2','zero',24)

 d.i(35,'t1','a0',48);d.i(35,'t3','a0',56);d.r(35,'t3','t3','t1');d.branch(5,'t3','t2','original')

 for r in ('t0','t1'):

  d.i(11,'t3',r,1008);d.branch(4,'t3','zero','original')

 d.r(27,'zero','t0','t2');d.r(16,'t3','zero');d.i(11,'t4','t3',2);d.branch(4,'t4','zero','original')

 d.r(27,'zero','t1','t2');d.r(16,'t4','zero');d.branch(5,'t4','zero','original');d.r(18,'t4','zero')

 d.i(9,'sp','sp',-160);d.i(63,'ra','sp',144);d.i(43,'a0','sp',128);d.i(43,'t0','sp',132);d.i(43,'t5','sp',112)

 d.i(35,'t2','a0',52);d.i(43,'t2','sp',136)

 d.r(35,'t0','t0','t3');d.r(35,'t2','t2','t3');d.i(43,'t0','a0',44);d.i(43,'t2','a0',52)

 li(d,'t0',state);d.r(33,'t4','t0','t4');d.i(43,'t4','sp',120);d.i(43,'t3','sp',124)

 d.i(36,'t2','t4',0);d.branch(4,'t2','t3','draw')

 # One contiguous 1024x24 PSMT4 row (12 KiB), with original GS stride/base.

 li(d,'t0',0x8a6800);d.branch(4,'t3','zero','source');li(d,'t0',page1)

 d.label('source');d.r(0,'t2','zero','t1',9);d.r(33,'t0','t0','t2')

 for n in range(0,48,4):d.i(43,'zero','sp',n)

 d.i(43,'t0','sp',4);d.i(43,'t1','sp',16)

 for n,v in ((20,1024),(24,24),(28,0x2b00),(36,20),(44,8)):

  d.i(9,'t0','zero',v);d.i(43,'t0','sp',n)

 # Explicitly drain earlier sprites before overwriting their texture rows.

 d.r(33,'a0','zero');d.r(33,'a1','zero');d.j(0x700ea8,True)

 d.r(33,'a0','sp');d.j(0x77e9b0,True)

 d.i(35,'t0','sp',120);d.i(35,'t1','sp',124);d.i(40,'t1','t0',0)

 li(d,'t0',state);d.i(35,'t1','t0',64);d.i(9,'t1','t1',1);d.i(43,'t1','t0',64)

 d.label('draw');d.i(35,'a0','sp',128);d.i(35,'t5','sp',112);d.r(35,'a0','a0','t5');d.j(olddraw,True)

 d.i(35,'t0','sp',128);d.i(35,'t1','sp',132);d.i(43,'t1','t0',44);d.i(35,'t1','sp',136);d.i(43,'t1','t0',52)

 d.i(55,'ra','sp',144);d.i(9,'sp','sp',160);d.r(8,'zero','ra');d.nop()

 d.label('original');d.r(35,'a0','a0','t5');d.j(olddraw);newdraw=emit('draw_hook',d)

 assert cursor<=page1 and off+cursor-va<=len(b)

 for entry,dest in ((0x743880,newget),(int(previous['new_get'],0),newget),(0x72e0e0,newload),(0x786e80,newdraw)):

  put(entry,struct.pack('<2I',(2<<26)|(dest>>2),0))

 heap=page1+page1_bytes;ph=struct.unpack_from('<I',b,28)[0]

 count=struct.unpack_from('<H',b,44)[0]

 header=next(ph+i*32 for i in range(count) if struct.unpack_from('<I',b,ph+i*32+8)[0]==va)

 struct.pack_into('<2I',b,header+16,cursor-va,heap-va)

 put(0x700180,struct.pack('<I',0x3c040000|((heap+0x8000)>>16)));put(0x700188,struct.pack('<I',0x24840000|(heap&65535)));put(0x8176d4,struct.pack('<I',heap))

 meta=dict(previous);meta.update(stub_end=hex(cursor),heap_start=hex(heap),new_filesz=cursor-va,new_memsz=heap-va,cell=24,grid_columns=42,render_size=22)

 meta['two_page_font']=dict(blocks=blocks,added_start=hex(start),page1_ram=hex(page1),page1_sectors=sectors,logical_pages=2,page_capacity=1764,row_bytes=12288,row_count=42,gs_extra_bytes=0,ee_extra_buffer_bytes=page1_bytes,original_sound_buffer_start='0xa50000',coordinate_carrier='x=24*column+page; renderer removes page before drawing',cache_policy='per-row last logical page; reset on normal full font upload')

 from .usaga_ui_spacing_runtime import patch_ui_spacing

 from .usaga_ui_physical_wrap import patch_physical_wrap

 wrapped,wrapmeta=patch_ui_spacing(bytes(b),meta)

 wrapped,wrapmeta=patch_physical_wrap(wrapped,wrapmeta)

 from .usaga_window_isolation import patch_window_isolation

 return patch_window_isolation(wrapped,wrapmeta)



# Existing assembler names only included registers needed by the earlier patch.

from .usaga_cn_extended_codec import REG

REG['t4']=12

REG['t5']=13

