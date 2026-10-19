"""Build-only 27 FD u16 spacing: measurable, invisible, no glyph slots consumed."""

import struct

from .usaga_cn_extended_codec import Asm,CPU



def patch_ui_spacing(source,meta):

    if 'ui_spacing' in meta:raise ValueError('Already patched')

    b=bytearray(source);off=meta['primary_load_file_offset'];va=meta['primary_load_vaddr']

    cursor=(int(meta['stub_end'],0)+15)&~15;blocks={}

    def at(a,n):return bytes(b[off+a-va:off+a-va+n])

    def put(a,d):b[off+a-va:off+a-va+len(d)]=d

    def li(a,r,v):a.i(15,r,'zero',v>>16);a.i(13,r,r,v&65535)

    def emit(name,a):

        nonlocal cursor

        raw=a.finish();put(a.base,raw);blocks[name]=hex(a.base);cursor=(a.base+len(raw)+15)&~15;return a.base

    # Existing decoder entry is a J hook; retain it as the fallback target.

    w=struct.unpack('<I',at(0x744400,4))[0];assert w>>26==2

    oldcheck=(w&0x3ffffff)<<2

    a=Asm(cursor)

    a.i(36,'t0','a0',0);a.i(9,'t1','zero',0x27);a.branch(5,'t0','t1','fallback')

    a.i(36,'t0','a0',1);a.i(9,'t1','zero',0xfd);a.branch(5,'t0','t1','fallback')

    a.i(36,'t0','a0',2);a.i(36,'t1','a0',3);a.r(0,'t0','zero','t0',8);a.r(37,'t0','t0','t1');a.i(12,'t0','t0',511)

    li(a,'v0',0x8865b0)

    for n in (0,4,12,16,20):a.i(43,'zero','v0',n)

    a.i(43,'t0','v0',8);li(a,'at',0x8865a8);a.i(43,'zero','at',0)

    a.i(9,'v0','zero',4);a.r(8,'zero','ra');a.nop()

    a.label('fallback');a.j(oldcheck);check=emit('measurement',a)

    # Preserve the original SP decoder (only newline 2780) in a trampoline.

    old=Asm(cursor);original=at(0x7444b0,8);assert original==struct.pack('<2I',0x27bdffb0,0xffbf0020)

    old.words=list(struct.unpack('<2I',original));old.j(0x7444b8);legacy=emit('original_special',old)

    a=Asm(cursor)

    a.i(36,'t0','a0',0);a.i(9,'t1','zero',0x27);a.branch(5,'t0','t1','fallback')

    a.i(36,'t0','a0',1);a.i(9,'t1','zero',0xfd);a.branch(5,'t0','t1','fallback')

    a.i(36,'t0','a0',2);a.i(36,'t1','a0',3);a.r(0,'t0','zero','t0',8);a.r(37,'t0','t0','t1');a.i(12,'t0','t0',511)

    a.r(33,'t5','t0')

    a.i(37,'t1','a1',68);a.r(33,'t0','t0','t1');a.i(11,'t2','t0',512);a.branch(5,'t2','zero','bounded');a.i(9,'t0','zero',511)

    a.label('bounded');a.i(41,'t0','a1',68)

    # Use the native signed RELATIVE offset, not an absolute origin. The renderer

    # adds it after the preceding glyph's scaled advance. Absolute origins mix

    # unscaled interpreter cursor units with actual drawing pixels at scale!=1.

    a.i(37,'t1','a1',72);a.i(11,'t2','t1',42);a.branch(4,'t2','zero','advance')

    a.i(37,'t2','a1',74);a.i(11,'t3','t2',18);a.branch(4,'t3','zero','advance')

    # Multiply row by 42 using shifts; no state or work-register side effects.

    a.i(37,'t2','a1',74);a.r(0,'t3','zero','t2',5);a.r(0,'t4','zero','t2',3);a.r(33,'t3','t3','t4');a.r(0,'t2','zero','t2',1);a.r(33,'t2','t3','t2')

    a.r(33,'t1','t1','t2');a.r(0,'t1','zero','t1',3);a.r(33,'t1','t1','a1')

    # Match native horizontal scale * animation scale and EE CVT.W.S conversion.

    a.words.extend([(17<<26)|(4<<21)|(13<<16),

                    (17<<26)|(20<<21)|32,

                    (49<<26)|(5<<21)|(1<<16)|28,

                    (17<<26)|(16<<21)|(1<<16)|2,

                    (49<<26)|(5<<21)|(1<<16)|36,

                    (17<<26)|(16<<21)|(1<<16)|2,

                    (17<<26)|(16<<21)|36, # EE CVT.W.S; TRUNC.W.S is not supported

                    (17<<26)|(8<<16)])

    a.i(35,'t2','t1',100);a.r(0,'t3','zero','t2',13);a.r(3,'t3','zero','t3',23);a.r(33,'t3','t3','t0')

    a.i(10,'t4','t3',256);a.branch(5,'t4','zero','offset_ok');a.i(9,'t3','zero',255)

    a.label('offset_ok');a.i(12,'t3','t3',511);a.r(0,'t3','zero','t3',10);li(a,'t4',0xfff803ff);a.r(36,'t2','t2','t4');a.r(37,'t2','t2','t3');a.i(43,'t2','t1',100)

    a.label('advance');a.i(9,'sp','sp',-32);a.i(63,'ra','sp',16);a.i(9,'a0','zero',4);a.j(0x7325a0,True)

    a.i(9,'v0','zero',1);a.i(55,'ra','sp',16);a.i(9,'sp','sp',32);a.r(8,'zero','ra');a.nop()

    a.label('fallback');a.j(legacy);special=emit('consume_without_glyph',a)

    assert cursor<=0x9e0000,('UI hooks collide with font buffer',hex(cursor))

    for entry,dest in ((0x744400,check),(0x7444b0,special)):put(entry,struct.pack('<2I',(2<<26)|(dest>>2),0))

    ph=struct.unpack_from('<I',b,28)[0];count=struct.unpack_from('<H',b,44)[0]

    header=next(ph+i*32 for i in range(count) if struct.unpack_from('<I',b,ph+i*32+8)[0]==va)

    struct.pack_into('<I',b,header+16,cursor-va)

    out=dict(meta,stub_end=hex(cursor),new_filesz=cursor-va)

    out['ui_spacing']=dict(blocks=blocks,encoding='27 FD + BE16 font-unit advance (1..511)',glyph_slots=0,work_registers_modified=False,relative_render_offset=True,horizontal_and_animation_scale_applied=True,physical_relative_offset_max=255,original_special_hex=original.hex(),legacy_decoder=hex(oldcheck),float_to_integer='EE CVT.W.S (funct 0x24)')

    return bytes(b),out



def verify_ui_spacing(elf):

    cpu=CPU(elf);calls=[]

    cpu.hooks[0x7325a0]=lambda c,r:calls.append(r[4])

    cases=0

    for delta in (1,8,16,18,24,47,127,255,511):

        cpu.mem[0x1000:0x1004]=b'\x27\xfd'+delta.to_bytes(2,'big')

        for mode in (0,1):

            r=cpu.run(0x744400,0x1000,mode)

            assert r[2]==4 and struct.unpack_from('<6I',cpu.mem,0x8865b0)==(0,0,delta,0,0,0)

            assert r[29]==0x1ff0000

        for line,count in ((0,0),(0,1),(1,40),(17,41),(18,0),(0,42)):

            for x in (0,12,56,510):

              for sx,anim in ((1.,1.),(.9,1.),(1.,.5),(1.25,.8)):

                for previous in (-256,-8,0,8,255):

                    cpu.mem[0x2000:0x4000]=bytes(8192)

                    struct.pack_into('<f',cpu.mem,0x201c,sx);struct.pack_into('<f',cpu.mem,0x2024,anim)

                    struct.pack_into('<3H',cpu.mem,0x2000+68,x,0,count);struct.pack_into('<H',cpu.mem,0x2000+74,line)

                    record=0x2000+100+(line*42+count)*8

                    original=0x80000001|(37<<1)|((previous&511)<<10)

                    struct.pack_into('<I',cpu.mem,record,original)

                    calls.clear();r=cpu.run(0x7444b0,0x1000,0x2000)

                    end=min(511,x+delta)

                    assert struct.unpack_from('<H',cpu.mem,0x2044)[0]==end

                    assert struct.unpack_from('<H',cpu.mem,0x2048)[0]==count

                    assert struct.unpack_from('<H',cpu.mem,0x204a)[0]==line

                    def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]

                    physical=int(f32(f32(delta*f32(sx))*f32(anim)))

                    offset=min(255,previous+physical)

                    expect=(original&0xfff803ff)|((offset&511)<<10) if count<42 and line<18 else original

                    assert struct.unpack_from('<I',cpu.mem,record)[0]==expect

                    assert calls==[4] and r[2]==1 and r[29]==0x1ff0000

                    cases+=1

    return dict(spacing_cursor_record_cases=cases,measurement_cases=18,no_added_glyph_slots=True,native_42_slot_boundary_guard=True,native_9_bit_origin_guard=True,signed_relative_offset_preserved=True,horizontal_and_animation_scale_cases=True,real_mips_executed=True,sequence_advance_mocked=True)

