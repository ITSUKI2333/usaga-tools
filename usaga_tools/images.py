"""Structural image parsers; linear-upload interpretations remain explicit."""
import struct,json,zlib,hashlib,collections
def inspect_tm2(f, offset, iso_size):
    f.seek(offset); header = f.read(16)
    result = dict(offset=offset,offset_hex=f'0x{offset:X}',header_hex=header.hex(' '),estimated_length='',status='unverified',reason='',pictures='',export='')
    pics = []
    try:
        if len(header)!=16 or header[:4]!=b'TIM2': raise ValueError('truncated header')
        rev,align,count = struct.unpack_from('<BBH',header,4)
        if rev not in (3,4) or align not in (0,1) or not 1<=count<=4096: raise ValueError('unsupported revision/alignment/count')
        if any(header[8:]): result['reason']='nonzero reserved bytes; structure and bounds checked'
        pos = offset + (16 if align==0 else 128)
        for i in range(count):
            if pos+48>iso_size: raise ValueError('picture header past EOF')
            f.seek(pos); raw=f.read(48)
            total,clut,img,hs,colors,pfmt,mips,ct,it,w,h=struct.unpack_from('<IIIHHBBBBHH',raw)
            if hs<48 or total<hs+img+clut or total-(hs+img+clut)>127 or pos+total>iso_size: raise ValueError('inconsistent picture sizes / EOF')
            if not (1<=w<=4096 and 1<=h<=4096 and it in (1,2,3,4,5) and pfmt==0 and 1<=mips<=7): raise ValueError('unsupported picture dimensions/type/mipmaps')
            bpp={1:16,2:24,3:32,4:4,5:8}[it]
            if img < (w*h*bpp+7)//8: raise ValueError('image data smaller than base level')
            if mips>1 and hs<48+16+4*mips: raise ValueError('mipmap header too short')
            if it in (4,5):
                cbpp={1:2,2:3,3:4}.get(ct&63)
                if not cbpp or not 1<=colors<=(16 if it==4 else 256) or clut<colors*cbpp: raise ValueError('invalid indexed palette')
            pics.append(dict(width=w,height=h,image_type=it,mipmaps=mips))
            pos += total
        result.update(estimated_length=pos-offset,status='validated',pictures=json.dumps(pics))
    except (ValueError,struct.error) as exc:
        result['reason']=str(exc)
    return result,pics

def png(path,w,h,rgba):
 assert len(rgba)==w*h*4
 def ck(t,d):return struct.pack('>I',len(d))+t+d+struct.pack('>I',zlib.crc32(t+d)&0xffffffff)
 raw=b''.join(b'\0'+rgba[y*w*4:(y+1)*w*4] for y in range(h))
 path.write_bytes(b'\x89PNG\r\n\x1a\n'+ck(b'IHDR',struct.pack('>IIBBBBB',w,h,8,6,0,0,0))+ck(b'IDAT',zlib.compress(raw,6))+ck(b'IEND',b''))
 # Independent PNG structure/CRC/decompression check on the actual emitted file.
 b=path.read_bytes();p=8;idat=[]
 while p<len(b):
  n=struct.unpack_from('>I',b,p)[0];t=b[p+4:p+8];d=b[p+8:p+8+n];crc=struct.unpack_from('>I',b,p+8+n)[0]
  assert crc==(zlib.crc32(t+d)&0xffffffff)
  if t==b'IDAT':idat.append(d)
  p+=12+n
 assert p==len(b) and zlib.decompress(b''.join(idat))==raw
 return hashlib.sha256(rgba).hexdigest()

def color(raw,typ):
 if typ==3:r,g,b,a=raw;return bytes((r,g,b,min(255,a*2)))
 if typ==2:return raw+b'\xff'
 if typ==1:
  n=int.from_bytes(raw,'little');return bytes(((n&31)*255//31,((n>>5)&31)*255//31,((n>>10)&31)*255//31,255 if n&32768 else 0))
 raise ValueError('Unsupported palette type')

def decode_picture(blob,p):
 v=struct.unpack_from('<IIIHHBBBBHHQQII',blob,p)
 total,clut,img,hs,colors,pfmt,mips,ct,it,w,h,tex0,tex1,gsregs,gsclut=v
 assert pfmt==0 and mips==1
 raw=blob[p+hs:p+hs+img];palette_raw=blob[p+hs+img:p+hs+img+clut]
 if it in (4,5):
  cbpp={1:2,2:3,3:4}[ct&63];palette=[]
  for i in range(colors):
   j=i
   if it==5 and not ct&128:j=(i&~24)|((i&8)<<1)|((i&16)>>1)
   assert j<colors
   palette.append(color(palette_raw[j*cbpp:(j+1)*cbpp],ct&63))
  if it==5:indices=raw[:w*h]
  else:indices=bytes(q for b in raw for q in (b&15,b>>4))[:w*h]
  assert len(indices)==w*h and max(indices)<colors
  rgba=b''.join(palette[i] for i in indices)
 else:
  cbpp={1:2,2:3,3:4}[it];rgba=b''.join(color(raw[i:i+cbpp],it) for i in range(0,w*h*cbpp,cbpp))
 return w,h,rgba,dict(width=w,height=h,image_type=it,clut_type=ct,clut_colors=colors,image_bytes=img,clut_bytes=clut,header_size=hs,mipmaps=mips,gs_psm=(tex0>>20)&63,tex0_hex=hex(tex0),palette_order='CSM1 swap bits 3 and 4' if it==5 and not ct&128 else 'linear',alpha_conversion='PS2 alpha x2 clamped to 255',storage_assumption='linear image upload; no forced unswizzle'),total

def native_pairs(data):
 if len(data)<16:return []
 n=struct.unpack_from('<I',data)[0]
 if not 2<=n<=64 or 4+4*(n+1)>len(data):return []
 ptrs=struct.unpack_from('<'+'I'*(n+1),data,4)
 if ptrs[0]<4+4*(n+1) or ptrs[-1]>len(data) or not all(a<b for a,b in zip(ptrs,ptrs[1:])):return []
 found=[]
 for i in range(n-1):
  a,b,c=ptrs[i:i+3]
  if b-a<16 or c-b<16:continue
  depth,w,h,flags=struct.unpack_from('<4H',data,a);paltype,colors=struct.unpack_from('<2H',data,b)
  if depth not in (4,8) or not 1<=w<=4096 or not 1<=h<=4096:continue
  pixels=(w*h*depth+7)//8
  if b-a!=16+pixels or paltype!=depth or colors!=(16 if depth==4 else 256) or c-b!=16+4*colors:continue
  if flags!=0 or any(data[a+8:a+16]) or any(data[b+4:b+16]):continue
  found.append(dict(chunk_index=i,pixel_header=a,pixel_data=a+16,pixel_bytes=pixels,palette_header=b,palette_data=b+16,palette_bytes=colors*4,colors=colors,width=w,height=h,depth=depth,package_end=ptrs[-1]))
 return found
