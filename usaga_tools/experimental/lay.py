"""Experimental LAY frame/page viewer, limited to the seven verified JP resources.

No native game assets or private workspace defaults are embedded here.
Pillow is loaded only by the caller after the workspace guard is active.
"""
import json, struct, math

def require_pillow():
    global Image, ImageDraw
    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise ValueError('LAY preview requires optional Pillow; configure pillow_dir') from exc

def u32(buf, offset):
    if offset < 0 or offset + 4 > len(buf):
        raise ValueError('Truncated LAY integer')
    return struct.unpack_from('<I', buf, offset)[0]

def decode_atlas(data):
    if len(data)<32 or data[:4]!=b'lay\0':
        raise ValueError('Missing LAY header')
    tex = u32(data, 4)
    if tex<32 or tex+16>len(data):raise ValueError('Invalid LAY texture offset')
    mode, _total, pages, palette_field = struct.unpack_from('<4I', data, tex)
    if (mode != 0x13 or pages<16 or pages>=palette_field or
            palette_field+tex+4>len(data) or (palette_field-pages)%8 or
            (palette_field-pages)//8>16):
        raise ValueError('Unsupported LAY texture layout')
    blocks = [struct.unpack_from('<II', data, tex + p)
              for p in range(pages, palette_field, 8)]
    height = sum(h for _, h in blocks)
    if any(not 0<h<=512 or tex+p<0 or tex+p+512*h>len(data) for p,h in blocks):
        raise ValueError('Invalid LAY texture page bounds')
    pixels = b''.join(data[tex + p:tex + p + 512 * h] for p, h in blocks)
    if len(pixels) != 512 * height:
        raise ValueError('Truncated indexed texture')
    pal_at = tex + u32(data, tex + palette_field)
    palette = data[pal_at:pal_at + 1024]
    if len(palette) != 1024:
        raise ValueError('Truncated palette')
    colors = []
    for k in range(256):
        swizzled = (k & ~24) | ((k & 8) << 1) | ((k & 16) >> 1)
        rgba = palette[swizzled * 4:swizzled * 4 + 4]
        colors.append(bytes((rgba[0], rgba[1], rgba[2], min(255, rgba[3] * 2))))
    image = Image.frombytes('RGBA', (512, height),
                            b''.join(colors[index] for index in pixels))
    return image, [h for _, h in blocks]

def decode_frames(data, atlas_size):
    if len(data)<24:raise ValueError('Truncated LAY header')
    section, end, count = struct.unpack_from('<III', data, 8)
    if not (0 < count < 1000 and section + 4 * count <= end <= len(data)):
        raise ValueError('Invalid LAY frame table')
    offsets = struct.unpack_from(f'<{count}I', data, section)
    frames = []
    for i, relative in enumerate(offsets):
        start = section + relative
        stop = section + offsets[i + 1] if i + 1 < count else end
        if not (section + 4 * count <= start < stop <= end) or stop-start<44:
            raise ValueError(f'Invalid LAY frame {i} offset')
        part_count = u32(data, start + 40)
        if part_count>128 or stop - start != 44 + part_count * 28:
            raise ValueError(f'Unexpected LAY frame {i} length')
        parts = []
        for p in range(part_count):
            off = start + 44 + p * 28
            v = struct.unpack_from('<8h4HI', data, off)
            x0, y0, x1, y1, x2, y2, x3, y3 = v[:8]
            u, vv, w, h, flags = v[8:]
            if any(abs(value)>4096 for value in v[:8]):
                raise ValueError('Unsupported LAY vertex range')
            if not (0 <= u < 512 and 0 <= vv < atlas_size[1] and
                    0 <= w <= 512-u and 0 <= h <= atlas_size[1]-vv):
                raise ValueError(f'Texture coordinates out of bounds at frame {i}')
            parts.append({'xy': list(v[:8]), 'uv': [u, vv, w, h],
                          'flags': flags, 'depth_raw': struct.unpack_from('<h',data,off+24)[0],
                          'texture_flip': data[off+26]})
        frames.append({'index': i, 'offset': start, 'parts': parts,
                       'anchors_raw': list(struct.unpack_from('<20h', data, start))})
    return frames

def affine_coeff(dst, src):
    (x1, y1), (x2, y2), (x3, y3) = dst
    (u1, v1), (u2, v2), (u3, v3) = src
    det = (x2-x1)*(y3-y1) - (x3-x1)*(y2-y1)
    if not det:
        return None
    a = ((u2-u1)*(y3-y1) - (u3-u1)*(y2-y1))/det
    b = ((x2-x1)*(u3-u1) - (x3-x1)*(u2-u1))/det
    d = ((v2-v1)*(y3-y1) - (v3-v1)*(y2-y1))/det
    e = ((x2-x1)*(v3-v1) - (x3-x1)*(v2-v1))/det
    return a, b, u1-a*x1-b*y1, d, e, v1-d*x1-e*y1

def decode_sequences(data, frames, page_heights):
    section = u32(data, 12)
    count = u32(data, 20)
    if not 0<count<=256 or section+count*4>len(data):
        raise ValueError('Invalid LAY sequence table')
    offsets = struct.unpack_from(f'<{count}I', data, section)
    sequences = []
    references = {}
    for seq_id, relative in enumerate(offsets):
        at = section + relative
        entries_count = u32(data, at)
        stop = at + 12 + 36 * entries_count
        if not (section + 4 * count <= at < stop <= len(data)):
            raise ValueError(f'Invalid sequence {seq_id}')
        entries = []
        for j in range(entries_count):
            pos = at + 12 + j * 36
            frame_id = data[pos]
            page_id = data[pos + 32]
            if frame_id >= len(frames) or page_id >= len(page_heights) or data[pos+2]>3:
                raise ValueError(f'Sequence {seq_id} references missing frame/page')
            entry = {'frame': frame_id, 'page': page_id, 'flip': data[pos+2],
                     'duration_raw': struct.unpack_from('<H', data, pos+6)[0],
                     'duration_units': struct.unpack_from('<H', data, pos+6)[0],
                     'position_raw': list(struct.unpack_from('<3i', data, pos+8)),
                     'scale_raw': list(struct.unpack_from('<2f', data, pos+20)),
                     'rotation_raw': struct.unpack_from('<f', data, pos+28)[0],
                     'record_offset': pos}
            entries.append(entry)
            if not all(math.isfinite(value) for value in entry['scale_raw']+[entry['rotation_raw']]):
                raise ValueError('Non-finite LAY transform')
            references.setdefault(frame_id, set()).add(page_id)
        sequences.append({'index': seq_id, 'offset': at, 'entries': entries})
    if any(len(pages) != 1 for pages in references.values()):
        raise ValueError('A frame is associated with multiple texture pages')
    for frame in frames:
        pages = references.get(frame['index'])
        frame['page'] = next(iter(pages)) if pages else None
        if frame['page'] is not None:
            page_height = page_heights[frame['page']]
            frame['uv_overhang'] = max([0] + [part['uv'][1] + part['uv'][3] - page_height
                                            for part in frame['parts']])
    return sequences

def compose(atlas, frame, canvas_size=360, flip_mode=0):
    image = Image.new('RGBA', (canvas_size, canvas_size), (0, 0, 0, 0))
    ox, oy = canvas_size // 2, round(canvas_size * 0.72)
    for part in frame['parts']:
        x0, y0, x1, y1, x2, y2, x3, y3 = part['xy']
        u, v, w, h = part['uv']
        if not w or not h:
            continue
        tile = atlas.crop((u, v, u+w, v+h))
        texture_flip = ((part['flags'] >> 16) ^ flip_mode) & 3
        if texture_flip:
            if texture_flip & 1:
                tile = tile.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
            if texture_flip & 2:
                tile = tile.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
        points = [(x0, y0), (x1, y1), (x2, y2), (x3, y3)]
        if flip_mode & 1:
            points = [(-x, y) for x, y in points]
        if flip_mode & 2:
            points = [(x, -y) for x, y in points]
        left = min(p[0] for p in points); top = min(p[1] for p in points)
        right = max(p[0] for p in points); bottom = max(p[1] for p in points)
        if left == right or top == bottom:
            continue
        width, height = right-left, bottom-top
        local = [(x-left, y-top) for x, y in points]
        layer = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        for vertex_ids, tex_pts in (((0, 1, 2), ((0, 0), (w, 0), (0, h))),
                                    ((1, 3, 2), ((w, 0), (w, h), (0, h)))):
            triangle = [local[k] for k in vertex_ids]
            coeff = affine_coeff(triangle, tex_pts)
            if coeff is None:
                continue
            rendered = tile.transform((width, height), Image.Transform.AFFINE,
                                      coeff, Image.Resampling.NEAREST)
            mask = Image.new('L', (width, height), 0)
            ImageDraw.Draw(mask).polygon(triangle, fill=255)
            # Replace shared-edge pixels once; alpha-compositing triangles twice
            # would darken the diagonal seam on antialiased/transparent pixels.
            layer.paste(rendered, (0, 0), mask)
        image.alpha_composite(layer, (ox+left, oy+top))
    return image

def write_viewer(out, manifest):
    html = r'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>USAGA LAY 原生帧预览器</title><style>
body{font:16px system-ui;background:#202229;color:#eee;margin:24px}a{color:#a9d4ff}
button,input,select{font:inherit}button{margin:3px}.row{display:flex;gap:24px;flex-wrap:wrap}
.view{width:360px;height:360px;background:repeating-conic-gradient(#555 0 25%,#444 0 50%) 0/24px 24px;image-rendering:pixelated}
.atlas{max-width:512px;max-height:600px;object-fit:contain;background:#555}.info{white-space:pre-wrap;font:13px monospace}
</style><h1>USAGA LAY 原生帧预览器</h1>
<p>从原版 ISO 的 .lay 读取四张贴图页、原生部件坐标和动作序列表。按序列读取贴图页、帧号与原始等待值。播放速度为预览参数；场景位置、缩放、旋转与运行时倍率尚未完整复现。未被动作表引用的原始帧不推测贴图页。</p>
<label>角色 <select id="character"></select></label>
<label>帧 <input id="frame" type="range" min="0" max="0" value="0"><span id="number">0</span></label>
<button id="prev">上一帧</button><button id="next">下一帧</button><br>
<label>原生动作序列 <select id="sequence"></select></label>
<label>预览速度（等待单位/秒）<input id="rate" type="number" min="1" max="600" value="60"></label><button id="play">播放/暂停</button><span id="status"></span><div class="row"><section><h2>合成画面</h2><img id="pose" class="view"></section>
<section><h2>当前原始贴图页</h2><img id="atlas" class="atlas"></section></div>
<h2>帧记录</h2><div id="info" class="info"></div>
<p>操作：方向键左右切换帧。所有资源只在本地读取，预览器无需联网。</p>
<script>
let manifest=__MANIFEST__, selected, timer=null, cursor=0;
const el=id=>document.getElementById(id);
function clamp(v,min,max){return Math.max(min,Math.min(max,v));}
function stop(){if(timer){clearTimeout(timer);timer=null}el('status').textContent='';}
function display(variant=0){let n=+el('frame').value;el('number').textContent=n;
 let f=selected.frames[n];
 if(f.page===null){el('pose').removeAttribute('src');el('atlas').removeAttribute('src');el('status').textContent='此原始帧未在动作表中引用，贴图页尚未确定';}
 else {el('pose').src=selected.folder+'/frames/'+String(n).padStart(3,'0')+(variant?'_flip'+variant:'')+'.png';
       el('atlas').src=selected.folder+'/page_'+f.page+'.png';}
 el('info').textContent='GRA '+selected.index+' / 帧 '+n+' / 贴图页 '+f.page+
  ' / ISO偏移 0x'+selected.iso_offset.toString(16)+' / 帧部件 '+f.parts.length+'\n'+
  f.parts.map((p,i)=>i+': XY='+p.xy+' UV='+p.uv+' flag=0x'+p.flags.toString(16)).join('\n');}
function choose(){stop();selected=manifest.characters[el('character').value];el('frame').max=selected.frames.length-1;
 el('frame').value=selected.frames.find(f=>f.page!==null).index;
 el('sequence').replaceChildren();for(let s of selected.sequences){let op=document.createElement('option');op.value=s.index;
 op.textContent='序列 '+s.index+'（'+s.entries.length+' 个指令）';el('sequence').append(op)}display();}
for(let c of manifest.characters){let op=document.createElement('option');op.value=manifest.characters.indexOf(c);op.textContent=c.name+' (GRA '+c.index+')';el('character').append(op)}choose();
el('character').onchange=choose;el('frame').oninput=()=>{stop();display()};
el('prev').onclick=()=>{stop();el('frame').value=clamp(+el('frame').value-1,0,+el('frame').max);display()};
el('next').onclick=()=>{stop();el('frame').value=clamp(+el('frame').value+1,0,+el('frame').max);display()};
function step(){let seq=selected.sequences[+el('sequence').value];if(!seq.entries.length){stop();return}
 let entry=seq.entries[cursor++%seq.entries.length];el('frame').value=entry.frame;display(entry.flip);
 el('status').textContent='序列 '+seq.index+' / 指令 '+((cursor-1)%seq.entries.length)+' / 原始等待值 '+entry.duration_units;
 timer=setTimeout(step,Math.max(16,entry.duration_units*1000/clamp(+el('rate').value||60,1,600)));}
el('sequence').onchange=()=>{stop();cursor=0;let s=selected.sequences[+el('sequence').value];if(s.entries.length){el('frame').value=s.entries[0].frame;display(s.entries[0].flip)}};
el('play').onclick=()=>{if(timer){stop();return}cursor=0;step()};
document.onkeydown=e=>{if(['INPUT','SELECT','TEXTAREA'].includes(e.target.tagName))return;if(e.key==='ArrowLeft')el('prev').click();if(e.key==='ArrowRight')el('next').click()};
</script></html>'''
    safe_json = json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
    (out / 'index.html').write_text(html.replace('__MANIFEST__', safe_json), encoding='utf-8')
