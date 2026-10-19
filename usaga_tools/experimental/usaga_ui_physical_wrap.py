"""Use rendered row positions for wrapping, retaining native logical cursors.



Installed only in disposable ELF copies. No game assets or translations written.

"""

import struct

from .usaga_cn_extended_codec import Asm,CPU,REG

REG.update(t4=12,t5=13,t6=14,t7=15,t8=24,t9=25)





def patch_physical_wrap(source,meta):

    assert 'physical_wrap' not in meta

    b=bytearray(source);off=meta['primary_load_file_offset'];va=meta['primary_load_vaddr']

    cursor=(int(meta['stub_end'],0)+15)&~15;blocks={}

    def put(a,d):b[off+a-va:off+a-va+len(d)]=d

    def emit(name,a):

        nonlocal cursor

        raw=a.finish();put(a.base,raw);blocks[name]=hex(a.base)

        cursor=(a.base+len(raw)+15)&~15;return a.base

    original=bytes(b[off+0x744090-va:off+0x744098-va])

    assert original==struct.pack('<2I',0x27bdffa0,0xffbf0020)

    a=Asm(cursor);a.words=list(struct.unpack('<2I',original));a.j(0x744098)

    legacy=emit('native_check',a)



    # a0=window, v0=actual position of the next glyph relative to its window.

    # Match draw_all_mess 745E38..746138: origins, signed relative offsets,

    # per-glyph scale conversion, and unscaled inter-glyph spacing.

    a=Asm(cursor)

    a.i(37,'t0','a0',72);a.i(37,'t1','a0',74)

    a.i(11,'t2','t0',42);a.branch(4,'t2','zero','invalid')

    a.i(11,'t2','t1',18);a.branch(4,'t2','zero','invalid')

    a.r(0,'t2','zero','t1',5);a.r(0,'t3','zero','t1',3);a.r(33,'t2','t2','t3')

    a.r(0,'t1','zero','t1',1);a.r(33,'t2','t2','t1')

    a.r(0,'t2','zero','t2',3);a.r(33,'t2','t2','a0');a.i(9,'t2','t2',100)

    a.r(33,'v0','zero');a.r(33,'t8','zero')

    a.label('record')

    a.i(35,'t3','t2',0)

    a.r(2,'t4','zero','t3',1);a.i(12,'t4','t4',511)

    a.branch(4,'t4','zero','no_origin');a.r(33,'v0','t4')

    a.label('no_origin')

    a.r(0,'t4','zero','t3',13);a.r(3,'t4','zero','t4',23)

    # Pending record will become active for the next glyph, so include its

    # relative offset but never stale width/color data.

    a.branch(4,'t8','t0','pending')

    a.i(12,'t5','t3',1);a.branch(4,'t5','zero','next')

    a.r(33,'v0','v0','t4')

    a.i(35,'t5','t2',4);a.r(2,'t5','zero','t5',20);a.i(12,'t5','t5',31)

    a.words.extend([(17<<26)|(4<<21)|(13<<16),

                    (17<<26)|(20<<21)|32,

                    (49<<26)|(4<<21)|(1<<16)|28,

                    (17<<26)|(16<<21)|(1<<16)|2,

                    (49<<26)|(4<<21)|(1<<16)|36,

                    (17<<26)|(16<<21)|(1<<16)|2,

                    # CVT.W.S respects the game's FCR31, exactly like 745F0C.

                    (17<<26)|(16<<21)|36,

                    (17<<26)|(13<<16)])

    a.r(33,'v0','v0','t5');a.r(2,'t4','zero','t3',23);a.i(12,'t4','t4',15)

    a.r(33,'v0','v0','t4')

    a.label('next');a.i(9,'t8','t8',1);a.i(9,'t2','t2',8);a.branch(4,'zero','zero','record')

    a.label('pending');a.r(33,'v0','v0','t4');a.r(8,'zero','ra');a.nop()

    a.label('invalid');a.i(9,'v0','zero',-32768);a.r(8,'zero','ra');a.nop()

    physical=emit('row_position',a)



    # Correct only the temporary input to the original check. Logical cursor,

    # anchor semantics, and numeric alignment retain their native units.

    a=Asm(cursor);a.i(9,'sp','sp',-80);a.i(63,'ra','sp',64)

    a.i(63,'a0','sp',0);a.i(63,'a1','sp',8)

    a.i(37,'t0','a0',68);a.i(43,'t0','sp',16)

    a.i(35,'t0','a0',72);a.i(43,'t0','sp',20)

    a.i(35,'t0','a0',28);a.i(43,'t0','sp',36)

    a.j(physical,True);a.i(43,'v0','sp',24)

    a.i(9,'t0','zero',-32768);a.branch(4,'v0','t0','native')

    a.i(35,'a0','sp',0);a.i(41,'v0','a0',68)

    # Native check scales the current glyph and lookahead by +28 only.

    # Include animation +36 during this synchronous check, then restore +28

    # before any drawing or continuation. Do not change vertical layout.

    a.words.extend([(49<<26)|(4<<21)|28,

                    (49<<26)|(4<<21)|(1<<16)|36,

                    (17<<26)|(16<<21)|(1<<16)|2,

                    (57<<26)|(4<<21)|28])

    a.label('native');a.i(35,'a0','sp',0);a.i(35,'a1','sp',8);a.j(legacy,True)

    a.i(43,'v0','sp',32)

    a.i(35,'a0','sp',0);a.i(35,'t0','sp',36);a.i(43,'t0','a0',28)

    a.i(35,'a0','sp',0);a.i(35,'t0','a0',72);a.i(35,'t1','sp',20)

    a.branch(5,'t0','t1','done')

    a.i(33,'t0','a0',68);a.i(35,'t1','sp',24);a.branch(5,'t0','t1','done')

    a.i(35,'t0','sp',16);a.i(41,'t0','a0',68)

    a.label('done');a.i(35,'v0','sp',32);a.i(35,'a0','sp',0);a.i(35,'a1','sp',8)

    a.i(55,'ra','sp',64);a.i(9,'sp','sp',80);a.r(8,'zero','ra');a.nop()

    wrapper=emit('check_wrapper',a)

    assert cursor<=0x9e0000,('Wrap hook overlaps font RAM',hex(cursor))

    put(0x744090,struct.pack('<2I',(2<<26)|(wrapper>>2),0))

    ph=struct.unpack_from('<I',b,28)[0]

    header=next(ph+i*32 for i in range(struct.unpack_from('<H',b,44)[0]) if struct.unpack_from('<I',b,ph+i*32+8)[0]==va)

    struct.pack_into('<I',b,header+16,cursor-va)

    m=dict(meta,stub_end=hex(cursor),new_filesz=cursor-va)

    m['physical_wrap']=dict(blocks=blocks,native_entry='0x744090',logical_cursor_retained=True,numeric_origins_retained=True,temporary_measurement_only=True,font_scale_temporarily_includes_animation=True)

    return bytes(b),m





def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]





def reference_position(records,pending,scale,animation):

    x=0

    for active,origin,relative,width,spacing in records:

        if origin:x=origin

        if active:x+=relative+int(f32(f32(width*f32(scale))*f32(animation)))+spacing

    origin,relative=pending

    if origin:x=origin

    return x+relative





def verify_physical_wrap(elf,meta):

    import random

    cpu=CPU(elf);physical=int(meta['physical_wrap']['blocks']['row_position'],0)

    native=int(meta['physical_wrap']['blocks']['native_check'],0)

    rng=random.Random(25199);cases=0;wrapper_cases=0

    for count in (0,1,5,20,41):

      for line in (0,3,17):

       for scale,anim in ((1.,1.),(.9,1.),(.85,1.),(.875,1.),(1.,.5),(1.25,.8)):

        for repetition in range(12):

            cpu.mem[0x2000:0x4000]=bytes(8192)

            struct.pack_into('<f',cpu.mem,0x201c,scale);struct.pack_into('<f',cpu.mem,0x2024,anim)

            struct.pack_into('<HH',cpu.mem,0x2048,count,line)

            records=[];base=0x2064+line*42*8

            for i in range(count):

                active=bool(rng.randrange(5));origin=rng.choice((0,0,0,12,56,108,125,240));relative=rng.choice((-96,-8,0,0,8,47));width=rng.randrange(1,25);spacing=rng.randrange(4)

                struct.pack_into('<II',cpu.mem,base+i*8,int(active)|(origin<<1)|((relative&511)<<10)|(spacing<<23),width<<20)

                records.append((active,origin,relative,width,spacing))

            pending=(rng.choice((0,12,56,108,125)),rng.choice((-24,0,0,8,47)))

            struct.pack_into('<II',cpu.mem,base+count*8,(pending[0]<<1)|((pending[1]&511)<<10),31<<20)

            expect=reference_position(records,pending,scale,anim)

            r=cpu.run(physical,0x2000,0,max_steps=4096);actual=r[2] if r[2]<0x80000000 else r[2]-0x100000000

            assert actual==expect,(count,line,scale,anim,actual,expect)

            assert r[29]==0x1ff0000;cases+=1

            for behavior in ('unchanged','newline','blocked','cursor_mutated'):

                struct.pack_into('<HHHH',cpu.mem,0x2044,200,48,count,line)

                calls=[]

                def hook(c,r):

                    assert r[4]==0x2000 and r[5]==0x1000

                    assert struct.unpack_from('<h',c.mem,0x2044)[0]==expect

                    assert struct.unpack_from('<f',c.mem,0x201c)[0]==f32(f32(scale)*f32(anim))

                    calls.append(True)

                    if behavior=='newline':struct.pack_into('<H',c.mem,0x2044,0);struct.pack_into('<H',c.mem,0x204a,(line+1)%18)

                    if behavior=='cursor_mutated':struct.pack_into('<H',c.mem,0x2044,(expect+1)&65535)

                    r[2]=1 if behavior=='blocked' else 0

                cpu.hooks={native:hook};r=cpu.run(0x744090,0x2000,0x1000,max_steps=8192)

                want=0 if behavior=='newline' else (expect+1)&65535 if behavior=='cursor_mutated' else 200

                assert struct.unpack_from('<H',cpu.mem,0x2044)[0]==want,(behavior,count,line,scale,anim,expect,struct.unpack_from('<H',cpu.mem,0x2044)[0],want)

                assert calls==[True] and r[2]==(behavior=='blocked') and r[29]==0x1ff0000

                assert struct.unpack_from('<f',cpu.mem,0x201c)[0]==f32(scale)

                wrapper_cases+=1

            cpu.hooks={}

    result=dict(actual_mips_row_cases=cases,actual_mips_wrapper_cases=wrapper_cases,wrapper_unit_native_body_mocked=True,independent_record_reference=True,logical_cursor_restored=True,newline_state_preserved=True,numeric_offsets_preserved=True,physical_font_and_animation_scale=True)

    result.update(verify_native_wrap_decisions(elf,meta))

    result.update(verify_layout_lookahead(elf))

    return result





def verify_native_wrap_decisions(elf,meta):

    """Execute the original check/FP branches, not a replacement wrap formula.



    Lookahead and newline effects are mocked equally on both sides. The real

    patched wrapper must match the real native body given an independently set

    physical position. Also reproduce spurious wraps with the old logical input.

    """

    cpu=CPU(elf);native=int(meta['physical_wrap']['blocks']['native_check'],0)

    cases=0;false_wraps_removed=0

    for position in (0,50,108,180,220,239,250):

      for scale,animation in ((s,a) for s in (1.,.9,.85) for a in (1.,.5,1.25)):

       for width in (1,12,22):

        for flag in (0,1):

         for word_width in (0,24,80,300):

            def execute(entry,cursor,effective=False):

                cpu.mem[0x2000:0x4000]=bytes(8192)

                struct.pack_into('<2f',cpu.mem,0x201c,f32(f32(scale)*f32(animation)) if effective else scale,1.)

                struct.pack_into('<2f',cpu.mem,0x2024,animation,1.)

                struct.pack_into('<6H',cpu.mem,0x2040,240,168,cursor,0,0,0)

                struct.pack_into('<I',cpu.mem,0x2064,position<<1)

                struct.pack_into('<I',cpu.mem,0x8865a8,flag)

                cpu.mem[0x8865b0:0x8865c8]=bytes(range(24))

                calls=[]

                def lookahead(c,r):r[2]=word_width

                def newline(c,r):

                    calls.append(True);struct.pack_into('<H',c.mem,0x2044,0)

                    struct.pack_into('<H',c.mem,0x204a,1);r[2]=0

                cpu.hooks={0x743c70:lookahead,0x744950:lookahead,0x743d70:newline}

                fbits=struct.unpack('<I',struct.pack('<f',width))[0]

                out=cpu.run(entry,0x2000,0x1000,max_steps=4096,fp_initial={12:fbits})

                assert out[29]==0x1ff0000

                assert cpu.mem[0x8865b0:0x8865c8]==bytes(range(24))

                return bool(calls),out[2],bytes(cpu.mem[0x2000:0x2100])

            direct=execute(native,position,True)

            wrapped=execute(0x744090,position+100)

            assert direct[:2]==wrapped[:2],(position,scale,width,flag,word_width,direct[:2],wrapped[:2])

            # No layout state changes except the intentionally retained raw cursor.

            d,w=bytearray(direct[2]),bytearray(wrapped[2]);d[68:70]=w[68:70];d[28:32]=w[28:32]

            assert struct.unpack_from('<f',w,28)[0]==f32(scale)

            assert d==w

            legacy=execute(native,position+100)

            if legacy[0] and not wrapped[0]:false_wraps_removed+=1

            cases+=1

    assert false_wraps_removed>0

    return dict(native_wrap_body_and_fp_branch_cases=cases,legacy_false_wrap_cases_removed=false_wraps_removed,native_check_body_executed=True,word_lookahead_and_newline_effects_mocked=True,default_fcr31_chop_test_model=True)





def verify_layout_lookahead(elf):

    cpu=CPU(elf);cases=0

    units=[(b'\x91',0x91,9),(b'\x28\x30',0x2830,8),(b'\x27\xff\x08\x01',0x3031,21)]

    for count in (0,1,3,8,20):

      for delta in (1,8,47,127,255,511):

        prefix=b''.join(units[i%3][0] for i in range(count))

        expected_codes=[units[i%3][1] for i in range(count)]

        expected_width=sum(units[i%3][2] for i in range(count))

        data=prefix+b'\x27\xfd'+delta.to_bytes(2,'big')+b'\x91\x01'

        cpu.mem[0x1000:0x1000+len(data)]=data;calls=[]

        def prohibit(c,r):

            calls.append(r[5]);assert r[4]==0x2000

            r[2]={0x91:9,0x2830:8,0x3031:21}.get(r[5],0)

        cpu.hooks={0x743ac0:prohibit}

        r=cpu.run(0x743c70,0x2000,0x1000,max_steps=4096)

        assert calls==expected_codes and r[2]==expected_width,(count,delta,calls,expected_codes,r[2],expected_width)

        assert r[29]==0x1ff0000;cases+=1

    return dict(real_mips_layout_lookahead_cases=cases,layout_parameter_bytes_not_decoded_as_glyphs=True,ordinary_1_2_4_byte_lookahead_retained=True)

