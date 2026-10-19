"""Build-only MIPS font hooks. Never changes the original executable or mappings."""

import struct

REG={'zero':0,'at':1,'v0':2,'v1':3,'a0':4,'a1':5,'a2':6,'a3':7,'t0':8,'t1':9,'t2':10,'t3':11,'t4':12,'t5':13,'s0':16,'s1':17,'s2':18,'sp':29,'ra':31}

class Asm:

 def __init__(self,base):self.base=base;self.words=[];self.labels={};self.fix=[]

 def label(self,n):self.labels[n]=self.base+4*len(self.words)

 def i(self,op,rt,rs,imm):self.words.append((op<<26)|(REG[rs]<<21)|(REG[rt]<<16)|(imm&65535))

 def r(self,fn,rd,rs,rt='zero',sh=0):self.words.append((REG[rs]<<21)|(REG[rt]<<16)|(REG[rd]<<11)|(sh<<6)|fn)

 def nop(self):self.words.append(0)

 def branch(self,op,rs,rt,target):self.fix.append((len(self.words),target));self.i(op,rt,rs,0);self.nop()

 def j(self,target,link=False):self.words.append(((3 if link else 2)<<26)|((target>>2)&0x3ffffff));self.nop()

 def finish(self):

  for i,target in self.fix:

   dest=self.labels[target];offset=(dest-(self.base+i*4+4))//4;assert -32768<=offset<32768;self.words[i]|=offset&65535

  return struct.pack('<'+'I'*len(self.words),*self.words)

def patch_elf(source,total_glyphs,loaders=None,cell=20,columns=51,render_size=18):

 assert cell in (17,20) and columns==1024//cell and total_glyphs<=columns*columns

 b=bytearray(source);phoff=struct.unpack_from('<I',b,28)[0];ents,n=struct.unpack_from('<HH',b,42)

 index,seg=next((i,struct.unpack_from('<8I',b,phoff+i*ents)) for i in range(n) if struct.unpack_from('<I',b,phoff+i*ents)[0]==1 and struct.unpack_from('<I',b,phoff+i*ents+8)[0]==0x700000)

 _,fileoff,va,pa,filesz,memsz,flags,align=seg

 def original(a,size):return source[fileoff+a-va:fileoff+a-va+size]

 old_get=original(0x743880,0x238);old_check=original(0x744400,0xac)

 # Original startup clears a final 16-byte block AT __bss_end, inclusively.

 # Keep that block writable padding and place injected code beyond it.

 base=(va+memsz+16+127)&~127;old_get_addr=base;old_check_addr=(base+len(old_get)+15)&~15;new_get_addr=(old_check_addr+len(old_check)+15)&~15

 a=Asm(new_get_addr)

 a.i(11,'t0','a1',0x100);a.branch(5,'t0','zero','short')

 a.i(11,'t0','a1',0x2830);a.branch(5,'t0','zero','legacy')

 a.i(9,'t2','a1',-0x2830);a.branch(4,'zero','zero','draw')

 a.label('short');a.i(9,'t2','a1',-0x30)

 a.label('draw');a.i(11,'t0','t2',total_glyphs);a.branch(5,'t0','zero','valid');a.r(33,'t2','zero')

 a.label('valid');a.i(9,'t0','zero',columns);a.r(27,'zero','t2','t0');a.r(18,'t1','zero');a.r(16,'t0','zero')

 a.r(0,'t3','zero','t0',4)

 if cell==20:a.r(0,'t0','zero','t0',2)

 a.r(33,'t0','t0','t3');a.r(0,'t3','zero','t1',4)

 if cell==20:a.r(0,'t1','zero','t1',2)

 a.r(33,'t1','t1','t3')

 a.i(15,'v0','zero',0x88);a.i(13,'v0','v0',0x65b0)

 a.i(43,'t0','v0',0);a.i(43,'t1','v0',4);a.i(9,'t3','zero',cell)

 a.i(43,'t3','v0',8);a.i(43,'t3','v0',12);a.i(43,'zero','v0',16);a.i(41,'zero','v0',20)

 a.branch(5,'a0','zero','flags');a.branch(4,'t2','zero','flags');a.i(9,'t3','zero',1);a.i(41,'t3','v0',20)

 a.label('flags');a.i(36,'t0','v0',22);a.i(12,'t0','t0',0xfffe);a.i(40,'t0','v0',22);a.r(8,'zero','ra');a.nop()

 a.label('legacy');a.j(old_get_addr)

 new_get=a.finish();new_check_addr=(new_get_addr+len(new_get)+15)&~15

 c=Asm(new_check_addr)

 c.i(36,'t0','a0',0);c.i(9,'t1','zero',0x27);c.branch(5,'t0','t1','legacy')

 c.i(36,'t0','a0',1);c.i(9,'t1','zero',0xff);c.branch(5,'t0','t1','legacy')

 c.i(9,'sp','sp',-32);c.i(63,'ra','sp',16)

 c.i(36,'t0','a0',2);c.i(36,'t1','a0',3);c.r(0,'t0','zero','t0',8);c.r(37,'t0','t0','t1')

 c.r(33,'a0','a1');c.i(9,'a1','t0',0x2830);c.j(new_get_addr,True)

 c.i(15,'at','zero',0x88);c.i(43,'zero','at',0x65a8);c.i(9,'v0','zero',4)

 c.i(55,'ra','sp',16);c.i(9,'sp','sp',32);c.r(8,'zero','ra');c.nop()

 c.label('legacy');c.j(old_check_addr);new_check=c.finish()

 additions=[];loader_meta={}

 end=new_check_addr+len(new_check)

 if loaders:

  table_addr=(end+15)&~15;table=struct.pack('<512I',*(v for pair in loaders['mes'] for v in pair));additions.append((table_addr,table))

  asset_context=(table_addr+len(table)+15)&~15;additions.append((asset_context,b'\0'*16))

  tone_old=asset_context+16;additions.append((tone_old,original(0x72dc90,0xac)))

  tone_new=(tone_old+0xac+15)&~15;t=Asm(tone_new)

  t.i(9,'t0','zero',5);t.branch(5,'a0','t0','legacy');t.i(9,'sp','sp',-48);t.i(63,'ra','sp',32);t.i(43,'a1','sp',16)

  t.branch(5,'a2','zero','size_ready');t.i(9,'a2','zero',loaders['tono5'][1]);t.label('size_ready');t.i(43,'a2','sp',8)

  t.r(33,'a3','a2');t.r(33,'a0','a1');t.i(15,'a1','zero',0x83);t.i(9,'a1','a1',0x1b8)

  sector=loaders['tono5'][0];t.i(15,'a2','zero',sector>>16);t.i(13,'a2','a2',sector&65535);t.j(0x72cb00,True)

  t.i(35,'v0','sp',8);t.r(0,'v0','zero','v0',11);t.i(55,'ra','sp',32);t.i(9,'sp','sp',48);t.r(8,'zero','ra');t.nop();t.label('legacy');t.j(tone_old)

  tone_code=t.finish();additions.append((tone_new,tone_code));mess_new=(tone_new+len(tone_code)+15)&~15;m=Asm(mess_new)

  m.i(9,'sp','sp',-64);m.i(63,'ra','sp',32);m.i(31,'s1','sp',16);m.i(31,'s0','sp',0);m.i(43,'a0','sp',48);m.j(0x72cc60,True)

  def lookup():

   m.i(35,'t0','sp',48);m.r(0,'t0','zero','t0',3);m.i(15,'t1','zero',table_addr>>16);m.i(13,'t1','t1',table_addr&65535);m.r(33,'t0','t0','t1')

  lookup();m.i(35,'s0','t0',4);m.r(0,'a0','zero','s0',11);m.j(0x72c640,True);m.r(33,'s1','v0')

  lookup();m.i(35,'a2','t0',0);m.r(33,'a0','s1');m.i(15,'a1','zero',0x83);m.i(9,'a1','a1',0x1b8);m.r(33,'a3','s0');m.j(0x72cb00,True)

  # Keep the actual relocation range. Only typed image consumers below use it;

  # ordinary text/sequence resolution must retain its expanded script offsets.

  m.i(35,'t0','sp',48);m.r(0,'t0','zero','t0',3);m.i(15,'t1','zero',0x82);m.i(9,'t1','t1',-0x4be0);m.r(33,'t0','t0','t1')

  m.i(35,'t1','t0',0);m.i(35,'t2','t0',4);m.i(35,'t3','t0',8)

  m.r(35,'t1','t2','t1');m.r(0,'t1','zero','t1',11);m.r(35,'t3','t3','t2');m.r(0,'t3','zero','t3',11)

  m.r(33,'t2','s1','t1');m.r(33,'t3','t2','t3');m.r(0,'t0','zero','s0',11);m.r(35,'t1','t0','t1')

  m.i(15,'t0','zero',asset_context>>16);m.i(13,'t0','t0',asset_context&65535)

  m.i(43,'t2','t0',0);m.i(43,'t3','t0',4);m.i(43,'t1','t0',8)

  m.r(0,'v0','zero','s0',11);m.r(33,'s1','s1','v0');m.i(15,'at','zero',0x87);m.i(43,'s1','at',0x33bc)

  mess_code=m.finish()+original(0x72d940,0xb0);additions.append((mess_new,mess_code));end=mess_new+len(mess_code)

  loader_meta=dict(tone_original_copy=hex(tone_old),tone_hook=hex(tone_new),mess_hook=hex(mess_new),mes_loader_table=hex(table_addr),tono5_sector=loaders['tono5'][0],tono5_sectors=loaders['tono5'][1],associated_mes_data_boundaries='unchanged original mes_sector_table')

  asset_resolver=(end+15)&~15;h=Asm(asset_resolver)

  # Packed image references can address the common TONO6 tail as well as MES.

  # Keep the original operand's namespace/associated flag before resolving it.

  tono=struct.unpack_from('<23I',source,fileoff+0x81b3c0-va)

  original_tono5_bytes=(tono[6]-tono[5])*2048

  original_tono56_bytes=(tono[7]-tono[5])*2048

  def hli(reg,value):h.i(15,reg,'zero',value>>16);h.i(13,reg,reg,value&65535)

  h.i(9,'sp','sp',-32);h.i(63,'ra','sp',16)

  h.i(36,'t0','a0',3);h.i(40,'t0','sp',0);h.j(0x7328a0,True)

  h.i(36,'t4','sp',0);h.i(12,'t0','t4',8);h.branch(5,'t0','zero','mes')

  h.i(12,'t0','t4',0x30);h.i(9,'t1','zero',0x20);h.branch(4,'t0','t1','tono')

  h.branch(5,'t0','zero','mes')

  hli('t0',0x8733a0);h.i(35,'t0','t0',0);h.branch(4,'t0','zero','mes')

  h.i(36,'t0','t0',129);h.i(12,'t0','t0',0x30);h.i(9,'t1','zero',0x10);h.branch(5,'t0','t1','mes')

  h.label('tono');hli('t0',0x8733ac);h.i(35,'t1','t0',0);h.i(35,'t3','t0',4)

  h.branch(4,'t1','zero','mes');h.branch(4,'t3','zero','mes')

  hli('t2',original_tono5_bytes);h.r(33,'t2','t1','t2')

  h.r(43,'t4','v0','t2');h.branch(5,'t4','zero','mes')

  hli('t4',original_tono56_bytes);h.r(33,'t4','t1','t4')

  h.r(43,'t4','v0','t4');h.branch(4,'t4','zero','mes')

  h.r(35,'t3','t3','t2');h.r(33,'v0','v0','t3');h.j(0) # bound to done below

  tono_done_jump=len(h.words)-2

  h.label('mes');h.i(36,'t4','sp',0);h.i(12,'t4','t4',8);h.branch(5,'t4','zero','done') # native associated base is already post-growth

  h.i(15,'t0','zero',asset_context>>16);h.i(13,'t0','t0',asset_context&65535)

  h.i(35,'t1','t0',0);h.r(43,'t2','v0','t1');h.branch(5,'t2','zero','done')

  h.i(35,'t1','t0',4);h.r(43,'t2','v0','t1');h.branch(4,'t2','zero','done')

  h.i(35,'t1','t0',8);h.r(33,'v0','v0','t1')

  h.label('done');h.words[tono_done_jump]=(2<<26)|(h.labels['done']>>2);h.i(55,'ra','sp',16);h.i(9,'sp','sp',32);h.r(8,'zero','ra');h.nop()

  asset_code=h.finish();additions.append((asset_resolver,asset_code));end=asset_resolver+len(asset_code)

  # Typed audio pointers include voice playback, stop/volume/status and SEP.

  # Associated-relative operands already use the actual post-growth base.

  audio_resolver=(end+15)&~15;ar=Asm(audio_resolver)

  ar.i(36,'t0','a0',3);ar.i(12,'t0','t0',8);ar.branch(4,'t0','zero','relocate')

  ar.j(0x7328a0);ar.label('relocate');ar.j(asset_resolver)

  audio_code=ar.finish();additions.append((audio_resolver,audio_code));end=audio_resolver+len(audio_code)

  audio_sites=[0x765918,0x765988,0x765af0,0x765b14,0x765cd8,0x7664a0,0x7664c4,0x767324,0x767a30,0x767a54,0x767f68,0x767fd8,0x768120,0x768144,0x768258,0x768348]

  for site in audio_sites:assert original(site,4)==struct.pack('<I',(3<<26)|(0x7328a0>>2))

  asset_sites=[0x76e750,0x76e8b0,0x756204,0x756370]

  for site in asset_sites:assert original(site,4)==struct.pack('<I',(3<<26)|(0x7328a0>>2))

  loader_meta.update(typed_asset_resolver=hex(asset_resolver),asset_relocation_context=hex(asset_context),typed_asset_call_sites=[hex(x) for x in asset_sites],asset_fix_scope='init_pep image creation and MESS_code1518 image replacement; packed-image and TM2 paths; generic text resolver unchanged',tono6_original_begin=hex(original_tono5_bytes),tono6_original_end=hex(original_tono56_bytes),tono6_actual_base_global='0x8733b0',tono6_namespace_guard=True,tono6_associated_base_excluded=True)

  loader_meta.update(typed_audio_resolver=hex(audio_resolver),typed_audio_call_sites=[hex(x) for x in audio_sites],audio_scope='resource-contained voice, SEP, STR and BGM playback/stop/volume/status; associated-relative operands are not shifted twice')

 # Word-wrap lookahead has its own byte reader; extend it alongside the decoder.

 lookahead=(end+15)&~15;w=Asm(lookahead)

 w.i(9,'sp','sp',-80);w.i(63,'ra','sp',64);w.i(31,'s0','sp',0);w.i(31,'s1','sp',16);w.i(31,'s2','sp',32)

 w.r(33,'s0','a1');w.r(33,'s1','a0');w.r(33,'s2','zero')

 w.label('loop');w.i(36,'t0','s0',0);w.i(11,'t1','t0',0x27);w.branch(5,'t1','zero','done')

 w.i(11,'t1','t0',0x30);w.branch(4,'t1','zero','single')

 w.i(36,'t1','s0',1);w.i(9,'t2','zero',0x27);w.branch(5,'t0','t2','double')

 w.i(9,'t2','zero',0xfd);w.branch(4,'t1','t2','done') # layout escape is a word boundary, never a glyph

 w.i(9,'t2','zero',0xff);w.branch(5,'t1','t2','double')

 w.i(36,'t0','s0',2);w.i(36,'t1','s0',3);w.r(0,'t0','zero','t0',8);w.r(37,'a1','t0','t1');w.i(9,'a1','a1',0x2830);w.i(9,'s0','s0',4);w.branch(4,'zero','zero','check')

 w.label('double');w.r(0,'t0','zero','t0',8);w.r(37,'a1','t0','t1');w.i(9,'s0','s0',2);w.branch(4,'zero','zero','check')

 w.label('single');w.r(33,'a1','t0');w.i(9,'s0','s0',1)

 w.label('check');w.r(33,'a0','s1');w.j(0x743ac0,True);w.branch(4,'v0','zero','done');w.r(33,'s2','s2','v0');w.branch(4,'zero','zero','loop')

 w.label('done');w.r(33,'v0','s2');w.i(55,'ra','sp',64);w.i(30,'s0','sp',0);w.i(30,'s1','sp',16);w.i(30,'s2','sp',32);w.i(9,'sp','sp',80);w.r(8,'zero','ra');w.nop()

 lookahead_code=w.finish();additions.append((lookahead,lookahead_code));end=lookahead+len(lookahead_code)

 newfilesz=end-va;assert fileoff+newfilesz<=len(b),'Not enough existing ELF file extent'

 # Materialize original BSS as zeros, then append executable hooks after its original end.

 b[fileoff+filesz:fileoff+newfilesz]=b'\0'*(newfilesz-filesz)

 for addr,data in [(old_get_addr,old_get),(old_check_addr,old_check),(new_get_addr,new_get),(new_check_addr,new_check)]:b[fileoff+addr-va:fileoff+addr-va+len(data)]=data

 for addr,data in additions:b[fileoff+addr-va:fileoff+addr-va+len(data)]=data

 # PT_LOAD growth does not update the game's hard-coded heap initialization.

 # Reserve all injected code/data before either allocator can use this space.

 heap_start=(end+127)&~127

 assert original(0x700180,4)==struct.pack('<I',0x3c04009e)

 assert original(0x700188,4)==struct.pack('<I',0x2484cb00)

 assert original(0x8176d4,4)==struct.pack('<I',va+memsz)

 struct.pack_into('<I',b,fileoff+0x700180-va,0x3c040000|(((heap_start+0x8000)>>16)&65535))

 struct.pack_into('<I',b,fileoff+0x700188-va,0x24840000|(heap_start&65535))

 struct.pack_into('<I',b,fileoff+0x8176d4-va,heap_start)

 for addr,dest in [(0x743880,new_get_addr),(0x744400,new_check_addr)]:struct.pack_into('<II',b,fileoff+addr-va,(2<<26)|((dest>>2)&0x3ffffff),0)

 assert original(0x743c70,8)==struct.pack('<2I',0x27bdff90,0xffbf0040)

 struct.pack_into('<2I',b,fileoff+0x743c70-va,(2<<26)|(lookahead>>2),0)

 if loaders:

  for addr,dest in [(0x72dc90,tone_new),(0x72d890,mess_new)]:struct.pack_into('<II',b,fileoff+addr-va,(2<<26)|((dest>>2)&0x3ffffff),0)

  for site in asset_sites:struct.pack_into('<I',b,fileoff+site-va,(3<<26)|((asset_resolver>>2)&0x3ffffff))

  for site in audio_sites:struct.pack_into('<I',b,fileoff+site-va,(3<<26)|(audio_resolver>>2))

 struct.pack_into('<II',b,phoff+index*ents+16,newfilesz,newfilesz)

 # Symbols/debug sections occupy bytes now materialized for BSS; remove test-ELF section headers.

 struct.pack_into('<I',b,32,0);struct.pack_into('<HHH',b,46,0,0,0)

 meta=dict(primary_load_file_offset=fileoff,primary_load_vaddr=va,old_filesz=filesz,old_memsz=memsz,new_filesz=newfilesz,new_memsz=newfilesz,stub_start=hex(base),stub_end=hex(end),old_get=hex(old_get_addr),old_check=hex(old_check_addr),new_get=hex(new_get_addr),new_check=hex(new_check_addr),escape='27 FF + big-endian uint16 glyph index',grid_columns=51,cell=20,render_size=18,test_elf_debug_sections_stripped=True,resource_loaders=loader_meta)

 meta.update(original_bss_end=hex(va+memsz),startup_clear_last_exclusive=hex(va+memsz+16),heap_start=hex(heap_start),heap_setup_patched=True,heap_pointer_patched=True)

 meta.update(grid_columns=columns,cell=cell,render_size=render_size)

 meta.update(next_string_lookahead=hex(lookahead),lookahead_encoding='1/2/4 byte; 27FD layout boundary; original prohibit_chk preserved')

 return bytes(b),meta



class CPU:

 """Small independent interpreter for the exact injected instructions and normal decoder path."""

 def __init__(self,elf):

  self.mem=bytearray(0x2000000);self.hooks={};p=struct.unpack_from('<I',elf,28)[0];n=struct.unpack_from('<H',elf,44)[0]

  for i in range(n):

   typ,off,va,pa,fs,ms,fl,al=struct.unpack_from('<8I',elf,p+i*32)

   if typ==1 and fs:self.mem[va:va+fs]=elf[off:off+fs]

 def run(self,start,a0,a1,max_steps=600,fp_initial=None):

  m=self.mem;r=[0]*32;fp=[0]*32;r[4]=a0;r[5]=a1;r[29]=0x1ff0000;r[31]=0x1fffff0;pc=start;pending=None;hi=lo=0

  if fp_initial:

   for register,value in fp_initial.items():fp[register]=value

  fpcc=False

  def signed(x):return x if x<0x80000000 else x-0x100000000

  def asfloat(x):return struct.unpack('<f',struct.pack('<I',x&0xffffffff))[0]

  def floatbits(x):return struct.unpack('<I',struct.pack('<f',x))[0]

  for _ in range(max_steps):

   if pc==0x1fffff0:return r

   if pc in self.hooks:self.hooks[pc](self,r);pc=r[31];r[0]=0;continue

   if pc==0x743710:pc=r[31];r[2]=0;continue # Boundary-prohibition result does not change byte count.

   w=struct.unpack_from('<I',m,pc)[0];op=w>>26;rs=w>>21&31;rt=w>>16&31;rd=w>>11&31;sh=w>>6&31;fn=w&63;im=w&65535;si=im if im<32768 else im-65536;branch=None

   if op==0:

    if fn==0:r[rd]=r[rt]<<sh

    elif fn==2:r[rd]=r[rt]>>sh

    elif fn==3:r[rd]=signed(r[rt])>>sh

    elif fn in (33,45):r[rd]=r[rs]+r[rt]

    elif fn==35:r[rd]=r[rs]-r[rt]

    elif fn==36:r[rd]=r[rs]&r[rt]

    elif fn==37:r[rd]=r[rs]|r[rt]

    elif fn==42:r[rd]=int(signed(r[rs])<signed(r[rt]))

    elif fn==43:r[rd]=int(r[rs]<r[rt])

    elif fn in (24,25):

     product=(signed(r[rs])*signed(r[rt])) if fn==24 else r[rs]*r[rt];lo=product&0xffffffff;hi=(product>>32)&0xffffffff

    elif fn==27:lo=r[rs]//r[rt];hi=r[rs]%r[rt]

    elif fn==16:r[rd]=hi

    elif fn==18:r[rd]=lo

    elif fn==8:branch=r[rs]

    elif fn==60:r[rd]=(r[rt]<<sh)&0xffffffff # dsll32/dsrl32 pairs occur only in copied legacy paths, not tests.

    elif fn==62:r[rd]=r[rt]>>sh

    elif fn==63:r[rd]=signed(r[rt])>>sh

    else:raise ValueError(('fn',hex(pc),fn))

   elif op in (2,3):

    if op==3:r[31]=pc+8

    branch=((pc+4)&0xf0000000)|((w&0x3ffffff)<<2)

   elif op in (4,5):

    if (r[rs]==r[rt])==(op==4):branch=pc+4+si*4

   elif op==9:r[rt]=r[rs]+si

   elif op==10:r[rt]=int(signed(r[rs])<si)

   elif op==11:r[rt]=int(r[rs]<(si&0xffffffff))

   elif op==12:r[rt]=r[rs]&im

   elif op==13:r[rt]=r[rs]|im

   elif op==15:r[rt]=im<<16

   elif op==17:

    if rs==0:r[rt]=fp[rd]

    elif rs==4:fp[rd]=r[rt]

    elif rs==20 and fn==32:fp[sh]=floatbits(float(signed(fp[rd])))

    elif rs==8:

     assert rt in (0,1),(hex(pc),rt)

     if fpcc==bool(rt):branch=pc+4+si*4

    elif rs==16 and fn==0:fp[sh]=floatbits(asfloat(fp[rd])+asfloat(fp[rt]))

    elif rs==16 and fn==1:fp[sh]=floatbits(asfloat(fp[rd])-asfloat(fp[rt]))

    elif rs==16 and fn==2:fp[sh]=floatbits(asfloat(fp[rd])*asfloat(fp[rt]))

    elif rs==16 and fn in (50,52,54,60,62):

     x,y=asfloat(fp[rd]),asfloat(fp[rt]);fpcc=(x==y) if fn==50 else (x<y) if fn in (52,60) else (x<=y)

    elif rs==16 and fn==36:fp[sh]=int(asfloat(fp[rd]))&0xffffffff # EE CVT.W.S; unsupported funct 13 must reach the error below

    else:raise ValueError(('FPU',hex(pc),rs,fn))

   elif op==49:fp[rt]=int.from_bytes(m[(r[rs]+si)&0x1fffffff:((r[rs]+si)&0x1fffffff)+4],'little')

   elif op==57:

    addr=(r[rs]+si)&0x1fffffff;m[addr:addr+4]=struct.pack('<I',fp[rt])

   elif op in (32,33,35,36,37,55,30):

    size={32:1,33:2,35:4,36:1,37:2,55:8,30:16}[op];a=(r[rs]+si)&0x1fffffff;r[rt]=int.from_bytes(m[a:a+size],'little')

    if op in (32,33):

     if r[rt]>>(size*8-1):r[rt]-=1<<(size*8)

   elif op in (40,41,43,63,31):

    size={40:1,41:2,43:4,63:8,31:16}[op];a=(r[rs]+si)&0x1fffffff;m[a:a+size]=(r[rt]&((1<<(size*8))-1)).to_bytes(size,'little')

   else:raise ValueError(('op',hex(pc),op))

   r=[v&0xffffffff for v in r];r[0]=0;nextpc=pending if pending is not None else pc+4;pending=branch;pc=nextpc

  raise RuntimeError('MIPS instruction limit')

def verify_codec(elf,total,cell=20,columns=51):

 cpu=CPU(elf);count=0

 for idx in range(total):

  for mode in (0,1):

   cpu.run(0x743880,mode,idx+0x2830)

   x,y,w,h,offset=struct.unpack_from('<5I',cpu.mem,0x8865b0);spacing=struct.unpack_from('<H',cpu.mem,0x8865c4)[0]

   assert (x,y,w,h,offset)==(idx%columns*cell,idx//columns*cell,cell,cell,0)

   assert spacing==(1 if mode==0 and idx else 0);count+=1

 for idx in [2000,total-1]:

  cpu.mem[0x1000:0x1004]=b'\x27\xff'+idx.to_bytes(2,'big')

  r=cpu.run(0x744400,0x1000,0);assert r[2]==4

  assert struct.unpack_from('<2I',cpu.mem,0x8865b0)==(idx%columns*cell,idx//columns*cell)

 for idx in range(min(total,2000)):

  cpu.mem[0x1000:0x1002]=(idx+0x2830).to_bytes(2,'big');r=cpu.run(0x744400,0x1000,0);assert r[2]==2

 for idx in range(208):

  cpu.mem[0x1000]=idx+0x30;r=cpu.run(0x744400,0x1000,0);assert r[2]==1

 return dict(normal_glyph_mode_cases=count,escape_cases=2,normal_decode_cases=min(total,2000)+208,independent_mips_execution_passed=True,limitation='Boundary prohibition helper mocked to zero; special/icon fallback retained as copied original instructions')



def verify_loaders(elf,loaders,meta=None):

 cpu=CPU(elf);calls=[];heap=[0xc00000]

 def load(c,r):calls.append(tuple(r[4:8]));r[2]=0

 def alloc(c,r):r[2]=heap[0];heap[0]+=r[4]

 cpu.hooks={0x72cb00:load,0x72c640:alloc,0x72cc60:lambda c,r:None}

 for partial in (0,1):

  calls.clear();regs=cpu.run(0x72dc90,5,0x400000) if partial==0 else None

  if partial:

   # Same wrapper entry with a2=1 is exercised through a tiny register setup stub.

   struct.pack_into('<4I',cpu.mem,0x1000,(9<<26)|(6<<16)|1,(2<<26)|(0x72dc90>>2),0,0)

   regs=cpu.run(0x1000,5,0x400000)

  count=partial or loaders['tono5'][1]

  assert calls==[(0x400000,0x8301b8,loaders['tono5'][0],count)],calls

  assert regs[2]==count*2048

 for bank in range(256):

  calls.clear();heap[0]=0xc00000;cpu.run(0x72d890,bank,0)

  s,n=loaders['mes'][bank];old_s,old_e=struct.unpack_from('<2I',cpu.mem,0x81b420+(bank*2+1)*4)

  assert calls[0]==(0xc00000,0x8301b8,s,n)

  assert calls[1]==(0xc00000+n*2048,0x8301b8,old_s,old_e-old_s)

  assert struct.unpack_from('<I',cpu.mem,0x8733bc)[0]==0xc00000+n*2048

  if meta:

   context=int(meta['resource_loaders']['asset_relocation_context'],0)

   script_start,asset_start,asset_end=struct.unpack_from('<3I',cpu.mem,0x81b420+bank*8)

   expected=(0xc00000+(asset_start-script_start)*2048,0xc00000+(asset_end-script_start)*2048,(n-(asset_start-script_start))*2048)

   assert struct.unpack_from('<3I',cpu.mem,context)==expected,(bank,'asset context')

 result=dict(tono_full_and_partial_cases=2,mes_bank_cases=256,loader_argument_and_boundary_checks_passed=True,limitation='File IO and allocator mocked; actual resource reads verified separately at emulator boot')

 if meta:

  resolver=int(meta['resource_loaders']['typed_asset_resolver'],0);context=int(meta['resource_loaders']['asset_relocation_context'],0);count=0

  for bank in range(256):

   start,asset,end=struct.unpack_from('<3I',cpu.mem,0x81b420+bank*8);begin=0xc00000+(asset-start)*2048;stop=0xc00000+(end-start)*2048;delta=(loaders['mes'][bank][1]-(asset-start))*2048

   struct.pack_into('<3I',cpu.mem,context,begin,stop,delta)

   for pointer in [0x400000,0x88d4b0,begin-1,begin,stop-1,stop,0x1ffffff]:

    def resolve(c,r,pointer=pointer):r[2]=pointer

    cpu.hooks[0x7328a0]=resolve

    regs=cpu.run(resolver,0x1000,1)

    expected=pointer+delta if begin<=pointer<stop else pointer

    assert regs[2]==expected and regs[29]==0x1ff0000,(bank,hex(pointer),regs[2],expected)

    count+=1

  result.update(typed_image_pointer_cases=count,typed_image_pointer_and_stack_checks_passed=True,all_bank_asset_contexts_verified=True)

 return result

