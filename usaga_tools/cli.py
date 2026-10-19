"""Small, explicit CLI. Experimental relocation hooks are not auto-applied."""
import argparse,collections,hashlib,json,re,struct,sys,types
from pathlib import Path
from .runtime import Session,Game,read_csv,digest
from .elf import parse_elf
from .codec import Codec
from . import scripts,images

TABLES=[('��������',0x6260,256),('��ͼ����',0x7820,256),('�������',0x8660,184),('�ز�����',0x9fe0,64),('��������',0xa230,48),('������װ�����',0xa370,256),('��Ҫ��������',0xaecc,33),('��������',0xb040,868),('���ܼ���������',0xc8d0,256),('ս������������',0xd12c,701),('��������',0xee40,256),('������������',0xfa00,256)]
HELP_TABLES=[('���ܼ�����˵��','TONO5',0x1a560,645,0x1af80,0x1bc00),('���ܼ�����˵��','17',0x10,645,0xa30,0x1aa8),('װ������˵��','17',0x5b40,256,0x5f50,0x6780),('��Ч��˵��','17',0x6780,256,0x6b80,0x7310),('��Ŀ�꼰����Ч��','17',0x7310,256,0x7710,0x7930),('��Ҫ����˵��','TONO5',0x1e6a0,32,0x1e720,0x1e980),('����˵��','TONO5',0x1e980,24,0x1e9e0,0x1ed80)]

def text_export(s,args):
    g=Game(s);iso=g.iso(s);codec=Codec(s.input('glyph_map'));out=s.output(args.out)
    info,syms=parse_elf(g.elf_path)
    x=types.SimpleNamespace(elf_region=g.elf_region,decode_run=codec.decode_run)
    lengths,evidence=scripts.infer_lengths(x,syms)
    s.csv(out/'opcode_lengths.csv',evidence)
    found={};candidates=[];gaps=[];names=[];refs=[];bank_summary=[]
    resources=list(g.resources(iso));selected=args.banks.split(',') if args.banks else [r[0] for r in resources]+['ELF_hdd_mess']
    missing=set(selected)-({r[0] for r in resources}|{'ELF_hdd_mess'})
    if missing:raise ValueError('Unknown banks: '+','.join(sorted(missing)))
    with iso.open('rb') as f:
        for k,base,end in resources:
            if k not in selected:continue
            f.seek(base);data=f.read(end-base);entries=scripts.valid_bank(data)
            if entries is None:
                bank_summary.append(dict(bank=k,status='invalid_bank_header',base=hex(base)));continue
            rr,cc,gg,ee,controls,np,nv=scripts.graph_bank(x,k,data,base,entries,lengths)
            found.update({r['iso_offset']:r for r in rr.values() if not (k=='TONO5' and r['evidence']=='bank_entry' and r['glyph_count']<4 and r['terminator_hex']=='00')})
            candidates.extend(cc)
            gaps.extend(dict(bank=k,iso_offset_hex=hex(base+p),reason=reason,raw_hex=raw) for p,reason,raw in gg)
            bank_summary.append(dict(bank=k,status='parsed',base=hex(base),texts=len(rr),unresolved=len(gg)))
            if k=='TONO5':
                for cat,start,n in TABLES:
                    ps=struct.unpack_from('<'+'I'*n,data,start)
                    if min(ps)!=start+4*n or not all(start+4*n<=p<len(data) for p in ps):raise ValueError('Invalid name table '+cat)
                    for i,p in enumerate(ps):
                        row=dict(category=cat,table_index=i,iso_offset=base+p,iso_offset_hex=hex(base+p),pointer_field_iso=hex(base+start+4*i),byte_length=0,text='',raw_hex='',unknown_glyphs='')
                        r,_=scripts.make_record(x,k,data,p,base,'binary_pointer_table') if data[p]>=0x27 else (None,p)
                        if r:found[base+p]=r;row.update(r)
                        else:row['unknown_glyphs']='SCRIPT_ENTRY' if data[p]!=1 else '';row['entry_kind']='script_entry' if data[p]!=1 else 'empty'
                        row['category']=cat;row['table_index']=i;names.append(row)
            for cat,bank,table,n,first,limit in HELP_TABLES:
                if bank!=k:continue
                ps=struct.unpack_from('<'+'I'*n,data,table)
                if min(ps)!=first or not all(first<=p<limit for p in ps):raise ValueError('Invalid description table '+cat)
                targets=sorted(set(ps))
                for i,p in enumerate(ps):
                    stop=next((q for q in targets if q>p),limit)
                    for m in re.finditer(b'\x16\x10',data[p:stop]):
                        q=p+m.end()
                        r,finish=scripts.make_record(x,k,data,q,base,'bounded_description_pointer')
                        if not r or finish>=stop:continue
                        found[base+q]=r
                        refs.append(dict(category=cat,bank=k,table_index=i,pointer_field_iso=hex(base+table+i*4),script_entry_iso=hex(base+p),iso_offset=base+q,iso_offset_hex=hex(base+q),byte_length=r['byte_length'],text=r['text'],raw_hex=r['raw_hex'],evidence='LE32 script pointer and bounded 16 10 display span; table-level semantic interpretation'))
            print(f'[TEXT] bank={k} ISO={end:#x} {len(found)} text spans',flush=True)
    if 'ELF_hdd_mess' in selected:
        data,file_offset=g.elf_region(0x82cee0,2320);p=0;hdd=[]
        while p<len(data):
            end=data.find(b'\0',p)
            if end<0:end=len(data)
            text,stop,unknown,ids=codec.decode_run(data,p)
            if ids and stop==end:
                off=0xfa800+file_offset+p
                r=dict(id='',bank='ELF_hdd_mess',iso_offset=off,iso_offset_hex=hex(off),byte_length=end-p,glyph_count=len(ids),text=text,raw_hex=data[p:end].hex(' '),terminator_hex='00',evidence='bounded ELF hdd_mess object VA 0x82CEE0 size 2320',unknown_glyphs=';'.join(map(str,unknown)))
                found[off]=r;hdd.append(r)
            p=end+1
        s.csv(out/'HDD��װϵͳ��ʾ.csv',hdd)
    candidates=list({r['iso_offset']:r for r in candidates if r['iso_offset'] not in found}.values())
    rows=[dict(r,id=f'T{i:07}') for i,r in enumerate(sorted(found.values(),key=lambda r:r['iso_offset']),1)]
    s.csv(out/'all_text_occurrences.csv',rows);s.csv(out/'description_references.csv',refs)
    s.csv(out/'unconfirmed_candidates.csv',candidates);s.csv(out/'unresolved_script_positions.csv',gaps);s.csv(out/'bank_summary.csv',bank_summary)
    for cat,start,n in TABLES:
        rr=[r for r in names if r['category']==cat]
        if rr:s.csv(out/(cat+'.csv'),rr)
    for cat in sorted({r['category'] for r in refs}):
        rr={r['iso_offset']:dict(r,���ķ���='') for r in refs if r['category']==cat}
        s.csv(out/(cat+'.csv'),rr.values())
    with iso.open('rb') as f:
        for r in rows:
            f.seek(r['iso_offset'])
            if f.read(r['byte_length'])!=bytes.fromhex(r['raw_hex']):raise ValueError('Export readback mismatch')
    s.json(out/'summary.json',dict(text_occurrences=len(rows),description_references=len(refs),unresolved_positions=len(gaps),candidate_count=len(candidates),map_sha256=digest(s.input('glyph_map')),complete_game_text_verified=False,whole_iso_scanned=False,scope='MES banks, TONO5, bounded ELF HDD messages and proven name/help tables; no archive/compression universality claimed'))

def elf_export(s,args):
    info,rows=parse_elf(s.input('elf'));out=s.output(args.out)
    s.json(out/'elf.json',info);s.csv(out/'symbols.csv',rows);s.csv(out/'suspicious_symbols.csv',[r for r in rows if r['keywords']])
    (out/'symbols.txt').write_text('\n'.join(f"{r['address_hex']} {r['type']} {r['name']}" for r in rows)+'\n',encoding='utf-8')
    print('ELF symbols:',len(rows))

def gra_export(s,args):
    g=Game(s);iso=g.iso(s);out=s.output(args.out)
    sectors=struct.unpack('<3401I',g.elf_region(0x81bc30,3401*4)[0]);rows=[];unresolved=[]
    selected={int(v) for v in args.indices.split(',')} if args.indices else set(range(3400))
    if not selected<=set(range(3400)):raise ValueError('Invalid GRA index')
    with iso.open('rb') as f:
        for i in sorted(selected):
            lo,hi=sectors[i]*2048,sectors[i+1]*2048
            if hi==lo:continue
            if not 0<=lo<hi<=iso.stat().st_size or hi-lo>64*1024*1024:raise ValueError('Invalid GRA resource span')
            f.seek(lo);data=f.read(hi-lo);pairs=images.native_pairs(data)
            if not pairs:unresolved.append(dict(resource_index=i,iso_offset_hex=hex(lo),reason='not a verified index/palette texture pair'));continue
            for p in pairs:
                colors=p['colors'];depth=p['depth'];w=p['width'];h=p['height'];pal=data[p['palette_data']:p['palette_data']+p['palette_bytes']]
                palette=[]
                for n in range(colors):
                    j=(n&~24)|((n&8)<<1)|((n&16)>>1) if depth==8 else n
                    palette.append(images.color(pal[j*4:j*4+4],3))
                pixels=data[p['pixel_data']:p['pixel_data']+p['pixel_bytes']]
                indices=pixels if depth==8 else bytes(q for b in pixels for q in (b&15,b>>4))[:w*h]
                rgba=b''.join(palette[v] for v in indices)
                name=f'GRA_{i:04}_{lo:010X}_c{p["chunk_index"]:02}.png';images.png(out/name,w,h,rgba)
                rows.append(dict(resource_index=i,iso_offset_hex=hex(lo),chunk_index=p['chunk_index'],width=w,height=h,depth=depth,png=name,pixel_sha256=hashlib.sha256(rgba).hexdigest(),interpretation='linear upload, CSM1 palette order for 8bpp'))
    s.csv(out/'images.csv',rows);s.csv(out/'unresolved.csv',unresolved);print('GRA images:',len(rows))

def tim2_scan(s,args):
    g=Game(s);iso=g.iso(s);out=s.output(args.out);size=iso.stat().st_size;rows=[];seen=set();pos=0;tail=b''
    with iso.open('rb') as scanner,iso.open('rb') as reader:
        while pos<size:
            block=scanner.read(min(8*1024*1024,size-pos));data=tail+block;base=pos-len(tail)
            for m in re.finditer(b'TIM2',data):
                off=base+m.start()
                if off in seen:continue
                seen.add(off);r,_=images.inspect_tm2(reader,off,size)
                if args.export and r['status']=='validated':
                    n=r['estimated_length']
                    if n<=64*1024*1024:
                        reader.seek(off);dest=out/f'{off:010X}.tm2';dest.write_bytes(reader.read(n));r['export']=dest.name
                    else:r['reason']+='; exceeds 64 MiB export cap'
                rows.append(r)
            pos+=len(block);tail=data[-3:];print(f'[TIM2] {pos:#x} {pos/size:.1%} candidates={len(rows)}',flush=True)
    s.csv(out/'tim2.csv',rows)

def coverage(s,args):
    from .translation import resolve_catalog
    raw=read_csv(s.supplied_input(args.occurrences));folder=s.inside(s.root/args.translations)
    if not folder.is_dir():raise ValueError('Translation directory missing')
    for p in folder.glob('*.csv'):s.inputs.add(p.resolve())
    catalog=resolve_catalog(folder,raw,lambda a,n:True);out=s.output(args.out)
    if catalog['conflicts']:s.json(out/'conflicts.json',catalog['conflicts'])
    missing=[r for r in raw if int(r['iso_offset']) not in catalog['resolved'] and r['text'].strip()]
    grouped=collections.defaultdict(list)
    for r in missing:grouped[r['raw_hex']].append(r)
    clean=[]
    for key,rs in grouped.items():
        q=dict(rs[0],���ķ���='',occurrences=len(rs),all_iso_offsets=';'.join(r['iso_offset_hex'] for r in rs));clean.append(q)
    s.csv(out/'missing_translations.csv',clean);s.json(out/'summary.json',dict(known_occurrences=len(raw),untranslated_nonblank_occurrences=len(missing),unique_missing=len(clean),conflicts=catalog['conflicts'],ambiguous=catalog['ambiguous'],translation_inputs=catalog['tables'],complete_game_text_verified=False))
    print('Missing unique translations:',len(clean))

def validate_edits(edits,size):
    result=[];previous_end=0
    for e in sorted(edits,key=lambda e:e['offset']):
        a=int(e['offset']);before=bytes.fromhex(e['before_hex']);after=bytes.fromhex(e['after_hex'])
        if not before or len(before)!=len(after) or a<previous_end or a+len(before)>size:raise ValueError('Overlapping, empty, resizing or out-of-bounds edit')
        previous_end=a+len(before);result.append((a,before,after))
    return result

def text_plan(s,args):
    g=Game(s);iso=g.iso(s);codec=Codec(s.input('glyph_map'));out=s.output(args.out)
    rows=read_csv(s.supplied_input(args.csv));edits=[];skips=[];seen={}
    # No blanket inline-script rewrite. The stable planner handles only proven
    # direct-string name tables ending in native return 01. Long strings and new
    # glyphs stay explicit skips; experiments contain the relocation work.
    with iso.open('rb') as f:
        f.seek(0x4ad19000);tono=f.read(0x27800)
        known={}
        for cat,table,n in TABLES:
            for i,p in enumerate(struct.unpack_from('<'+'I'*n,tono,table)):known[0x4ad19000+p]=(cat,i)
        for line,r in enumerate(rows,2):
            field=next((k for k in ('���ķ���','translation_zh') if k in r),None)
            if not field:raise ValueError('CSV lacks translation column')
            text=r[field]
            if not text.strip():continue
            a=int(r['iso_offset']);raw=bytes.fromhex(r['raw_hex']);n=int(r['byte_length'])
            if len(raw)!=n or not raw:raise ValueError('Invalid raw span at CSV line '+str(line))
            f.seek(a);actual=f.read(n+1)
            if actual[:n]!=raw:raise ValueError('Original bytes mismatch at '+hex(a))
            decoded,stop,unknown,ids=codec.decode_run(actual,0)
            if stop!=n or decoded!=r['text']:raise ValueError('CSV span is not exactly one original text segment at '+hex(a))
            reason=None;encoded=None
            if text==r['text']:continue
            if a not in known or actual[-1:]!=b'\x01':reason='requires_proven_script_or_relocation'
            try:
                if reason is None:
                    if re.findall(r'��������[0-9A-Fa-f]{4}��',text)!=re.findall(r'��������[0-9A-Fa-f]{4}��',r['text']):raise ValueError('Special-code order changed')
                    encoded=codec.encode_original(text)
                    if len(encoded)>n:reason='too_long_needs_relocation'
            except ValueError as exc:reason=str(exc)
            if reason:skips.append(dict(line=line,iso_offset_hex=hex(a),reason=reason,translation=text));continue
            # Native return terminates the replacement before harmless 01 fill.
            after=encoded+b'\x01'*(n+1-len(encoded));before=actual
            if a in seen and seen[a]!=after:raise ValueError('Conflicting translations for '+hex(a))
            if a not in seen:edits.append(dict(offset=a,before_hex=before.hex(),after_hex=after.hex()))
            seen[a]=after
    validate_edits(edits,iso.stat().st_size)
    source_hash=digest(iso)
    if source_hash!=Game.ISO_HASH:raise ValueError('Original ISO SHA-256 mismatch')
    s.json(out/'patch_plan.json',dict(schema='usaga-fixed-spans-v1',source_sha256=source_hash,source_size=iso.stat().st_size,edits=edits,scope='proven name-table strings only; no extended codec, relocation or ELF change'))
    s.csv(out/'skipped.csv',skips);print('Planned edits:',len(edits),'skipped:',len(skips))

def apply_plan(s,args):
    g=Game(s);iso=g.iso(s);plan=json.loads(s.supplied_input(args.plan).read_text(encoding='utf-8'))
    if plan['schema']!='usaga-fixed-spans-v1' or plan['source_sha256']!=Game.ISO_HASH or plan['source_size']!=iso.stat().st_size:raise ValueError('Wrong plan identity')
    edits=validate_edits(plan['edits'],iso.stat().st_size)
    # Check every preimage and source digest BEFORE creating the output ISO.
    if digest(iso)!=plan['source_sha256']:raise ValueError('Source SHA-256 mismatch')
    with iso.open('rb') as f:
        for off,before,after in edits:
            f.seek(off)
            if f.read(len(before))!=before:raise ValueError('Patch preimage mismatch')
    out=s.output(args.out);partial=out/'translated.iso.partial';final=out/'translated.iso'
    copied_hash=hashlib.sha256()
    with iso.open('rb') as f,partial.open('xb') as dst:
        while b:=f.read(8*1024*1024):copied_hash.update(b);dst.write(b)
    if copied_hash.hexdigest()!=plan['source_sha256']:raise ValueError('Source changed during copy')
    with partial.open('r+b') as f:
        for off,before,after in edits:f.seek(off);f.write(after)
    # Compare the complete output against source plus the approved edits,
    # including unmodified regions and edits crossing a streaming block edge.
    pos=0
    with iso.open('rb') as src,partial.open('rb') as actual:
        while block:=src.read(8*1024*1024):
            expected=bytearray(block);end=pos+len(block)
            for off,before,after in edits:
                a=max(pos,off);b=min(end,off+len(after))
                if a<b:expected[a-pos:b-pos]=after[a-off:b-off]
            if actual.read(len(block))!=expected:raise ValueError('Full output verification failed at '+hex(pos))
            pos=end
        if actual.read(1):raise ValueError('Unexpected extra output bytes')
    partial.rename(final);s.written.add(str(final))
    s.json(out/'build.json',dict(output=final.name,output_sha256=digest(final),edits=len(edits),source_sha256=plan['source_sha256'],source_modified=False,requires_emulator_test=True))

def font_build(s,args):
    vendor=s.config.get('pillow_dir')
    if vendor:
        vendor=s.inside(s.root/vendor)
        if not vendor.is_dir():raise ValueError('pillow_dir does not exist')
        sys.path.insert(0,str(vendor))
    try:from PIL import Image,ImageFont,ImageDraw
    except ImportError as exc:raise ValueError('font-build requires optional Pillow in configured pillow_dir; no automatic install') from exc
    font_path=s.input('font');codec=Codec(s.input('glyph_map'));out=s.output(args.out)
    font=ImageFont.truetype(str(font_path),args.size)
    boxes=[font.getbbox(ch,anchor='ls') for ch in codec.mapping.values()]
    top=min(b[1] for b in boxes);bottom=max(b[3] for b in boxes)
    if bottom-top>24:raise ValueError('Font exceeds 24px common baseline bounds; lower --size (no pixel compression performed)')
    baseline=(24-(bottom-top))//2-top
    pages=[];metrics=[]
    for page in range((max(codec.mapping)//1764)+1):
        mask=Image.new('L',(1024,1024));draw=ImageDraw.Draw(mask)
        for i,ch in codec.mapping.items():
            if i//1764!=page:continue
            local=i%1764;x=(local%42)*24;y=(local//42)*24
            advance=font.getlength(ch);box=font.getbbox(ch,anchor='ls')
            if box[2]-box[0]>24:raise ValueError('Glyph exceeds 24px cell width: '+str(i))
            draw.text((x+(24-advance)/2,y+baseline),ch,font=font,fill=255,anchor='ls')
            metrics.append(dict(glyph_index=i,character=ch,page=page,x=x,y=y,cell=24,baseline=baseline,advance=advance))
        # New antialias alpha is quantized to 4 bits. Original font texture bytes
        # are never copied. A renderer/loader patch is still required to use it.
        rgba=Image.new('RGBA',mask.size,'white');rgba.putalpha(mask);rgba.save(out/f'font_page{page}.png')
        data=bytes((v+8)//17 for v in mask.tobytes())
        packed=bytes(data[i]|(data[i+1]<<4) for i in range(0,len(data),2))
        (out/f'font_page{page}.4bpp.bin').write_bytes(packed);pages.append(dict(page=page,bytes=len(packed),sha256=hashlib.sha256(packed).hexdigest()))
    s.csv(out/'glyph_metrics.csv',metrics)
    s.json(out/'font.json',dict(font_sha256=digest(font_path),glyph_map_sha256=digest(s.input('glyph_map')),size=args.size,cell=24,columns=42,pages=pages,baseline=baseline,no_per_glyph_vertical_centering=True,iso_modified=False,not_a_native_texture_container=True))


def mapc_export(s,args):
    from .mapc import decode_package
    g=Game(s);iso=g.iso(s);offset=args.offset;length=args.length
    if not 0<=offset<offset+length<=iso.stat().st_size or length>64*1024*1024:
        raise ValueError('MAPC package span outside ISO / export limit')
    with iso.open('rb') as handle:
        handle.seek(offset);data=handle.read(length)
    pictures=decode_package(data);out=s.output(args.out);records=[]
    for picture in pictures:
        name=f'mapc_{picture["index"]:03}.png'
        pixel_hash=images.png(out/name,picture['width'],picture['height'],picture['rgba'])
        records.append(dict(index=picture['index'],iso_offset=offset+picture['offset'],
            iso_offset_hex=hex(offset+picture['offset']),bytes=picture['bytes'],png=name,
            pixel_sha256=pixel_hash,**picture['metadata']))
    s.json(out/'manifest.json',dict(package_iso_offset=offset,package_bytes=length,
        source_package_sha256=hashlib.sha256(data).hexdigest(),images=records,
        interpretation='verified MAPC palette-before-pixel layout; read-only export'))
    print('MAPC images:',len(records))


def lay_preview(s,args):
    vendor=s.config.get('pillow_dir')
    if vendor:
        vendor=s.inside(s.root/vendor)
        if not vendor.is_dir():raise ValueError('pillow_dir does not exist')
        sys.path.insert(0,str(vendor))
    from .experimental import lay
    lay.require_pillow()
    g=Game(s);iso=g.iso(s)
    if digest(iso)!=Game.ISO_HASH:raise ValueError('Original ISO SHA-256 mismatch')
    selected=sorted({int(value) for value in args.indices.split(',')})
    if not selected or not set(selected)<=set(range(2900,2907)):
        raise ValueError('LAY preview is currently limited to GRA 2900..2906')
    sectors=struct.unpack('<3401I',g.elf_region(0x81bc30,3401*4)[0])
    out=s.output(args.out);manifest=dict(schema='usaga-lay-preview-v2',
        source_iso_sha256=Game.ISO_HASH,source_elf_sha256=Game.ELF_HASH,
        runtime_pixel_match_verified=False,timing='raw wait values; preview rate only',characters=[])
    with iso.open('rb') as handle:
        for index in selected:
            start,end=sectors[index]*2048,sectors[index+1]*2048
            if not 0<=start<end<=iso.stat().st_size or end-start>64*1024*1024:
                raise ValueError('Invalid GRA resource span')
            handle.seek(start);data=handle.read(end-start)
            if data[:4]!=b'lay\0':raise ValueError('Missing LAY signature')
            atlas,page_heights=lay.decode_atlas(data)
            frames=lay.decode_frames(data,atlas.size)
            sequences=lay.decode_sequences(data,frames,page_heights)
            folder=f'GRA_{index}';dest=out/folder;(dest/'frames').mkdir(parents=True)
            atlas.save(dest/'atlas.png');pages=[];y=0
            for page_id,height in enumerate(page_heights):
                page=atlas.crop((0,y,512,y+height));pages.append(page);y+=height
                page.save(dest/f'page_{page_id}.png')
            variants=collections.defaultdict(set)
            for seq in sequences:
                for entry in seq['entries']:variants[entry['frame']].add(entry['flip'])
            for frame in frames:
                if frame['page'] is None:continue
                for flip in sorted(variants[frame['index']]|{0}):
                    suffix=f'_flip{flip}' if flip else ''
                    lay.compose(pages[frame['page']],frame,flip_mode=flip).save(dest/'frames'/f'{frame["index"]:03}{suffix}.png')
            manifest['characters'].append(dict(index=index,name=f'GRA {index}',folder=folder,
                iso_offset=start,resource_bytes=len(data),resource_sha256=hashlib.sha256(data).hexdigest(),
                page_heights=page_heights,frames=frames,sequences=sequences))
            print('LAY',index,'mapped',sum(f['page'] is not None for f in frames),'of',len(frames))
    s.json(out/'manifest.json',manifest);lay.write_viewer(out,manifest)
    s.json(out/'summary.json',dict(raw_frames=sum(len(c['frames']) for c in manifest['characters']),
        mapped_frames=sum(f['page'] is not None for c in manifest['characters'] for f in c['frames']),
        unreferenced_frames=sum(f['page'] is None for c in manifest['characters'] for f in c['frames']),
        sequences=sum(len(c['sequences']) for c in manifest['characters']),
        limitations=['No 3D mesh, rig or arbitrary camera reconstruction',
            'Scene transforms, depth compositing, GS half-texel rasterization and runtime rate are not fully emulated',
            'Unreferenced raw frames are not assigned guessed texture pages']))

def main(argv=None):
    if sys.flags.optimize:
        raise SystemExit('Run without -O: inherited binary-structure assertions must remain enabled')
    parser=argparse.ArgumentParser(description='Unlimited SaGa JP SLPS-25199 tools (final review)')
    parser.add_argument('--config',required=True,help='Private workspace JSON; never commit real paths')
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('inspect-elf','extract-text','extract-gra','extract-mapc','lay-preview','scan-tim2','coverage','font-build','plan-text','apply-plan'):
        p=sub.add_parser(name);p.add_argument('--out',required=True,help='New relative directory inside work_dir')
        if name=='extract-text':p.add_argument('--banks',help='Comma-separated MES indices and/or TONO5; default all')
        if name=='extract-gra':p.add_argument('--indices',help='Comma-separated GRA indices; default all')
        if name=='scan-tim2':p.add_argument('--export',action='store_true')
        if name=='coverage':p.add_argument('--occurrences',required=True);p.add_argument('--translations',required=True)
        if name=='plan-text':p.add_argument('--csv',required=True)
        if name=='apply-plan':p.add_argument('--plan',required=True)
        if name=='font-build':p.add_argument('--size',type=int,default=22)
        if name=='extract-mapc':
            p.add_argument('--offset',type=lambda value:int(value,0),required=True)
            p.add_argument('--length',type=lambda value:int(value,0),required=True)
        if name=='lay-preview':p.add_argument('--indices',default='2900,2901,2902,2903,2904,2905,2906')
    args=parser.parse_args(argv);s=None
    try:
        s=Session(args.config,args.command)
        handlers={'inspect-elf':elf_export,'extract-text':text_export,'extract-gra':gra_export,'extract-mapc':mapc_export,'lay-preview':lay_preview,'scan-tim2':tim2_scan,'coverage':coverage,'font-build':font_build,'plan-text':text_plan,'apply-plan':apply_plan}
        handlers[args.command](s,args);s.finish();return 0
    except Exception as exc:
        print(type(exc).__name__+': '+str(exc),file=sys.stderr)
        if s:s.finish(type(exc).__name__+': '+str(exc))
        return 1
