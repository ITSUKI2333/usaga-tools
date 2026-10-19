"""ELF parser extracted without the old process-global startup effects."""
import struct,hashlib
KEYWORDS=("font","text","string","message","msg","print","draw","glyph","kanji","sjis","char")
def parse_elf(path):
    data = path.read_bytes()  # ELF only; ISO is always streamed.
    if data[:4] != b'\x7fELF': raise ValueError('Not an ELF executable')
    if data[4] not in (1,2) or data[5] not in (1,2): raise ValueError('Unsupported ELF identification')
    bits = 32 if data[4] == 1 else 64
    endian = '<' if data[5] == 1 else '>'
    fmt = endian + ('HHIIIIIHHHHHH' if bits == 32 else 'HHIQQQIHHHHHH')
    h = struct.unpack_from(fmt, data, 16)
    etype,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shnames = h
    sfmt = endian + ('IIIIIIIIII' if bits == 32 else 'IIQQQQIIQQ')
    sections = []
    def section(i):
        pos = shoff + i * shsize
        if shsize < struct.calcsize(sfmt) or pos + shsize > len(data): raise ValueError('Invalid section table')
        return struct.unpack_from(sfmt, data, pos)
    if shoff:
        if shnum == 0: shnum = section(0)[5]
        if shnum > 100000: raise ValueError('Unreasonable section count')
        sections = [section(i) for i in range(shnum)]
    def span(offset, size):
        if offset < 0 or offset + size > len(data): raise ValueError('ELF region outside file')
        return data[offset:offset+size]
    def cstr(blob, offset):
        if offset >= len(blob): return '<invalid-name-offset>'
        return blob[offset:blob.find(b'\0', offset) if b'\0' in blob[offset:] else len(blob)].decode('utf-8', 'backslashreplace')
    rows = []
    types = {0:'NOTYPE',1:'OBJECT',2:'FUNC',3:'SECTION',4:'FILE',5:'COMMON',6:'TLS'}
    for si,s in enumerate(sections):
        if s[1] not in (2,11): continue
        if s[6] >= len(sections): raise ValueError('Invalid symbol string table link')
        strings = sections[s[6]]; names = span(strings[4], strings[5])
        size = 16 if bits == 32 else 24
        if s[9] < size or s[5] % s[9]: raise ValueError('Invalid symbol entry size')
        blob = span(s[4], s[5])
        for offset in range(0,len(blob),s[9]):
            if bits == 32: n,v,z,info,other,idx = struct.unpack_from(endian+'IIIBBH',blob,offset)
            else: n,info,other,idx,v,z = struct.unpack_from(endian+'IBBHQQ',blob,offset)
            name = cstr(names,n)
            rows.append(dict(table=si,index=offset//s[9],name=name,address=v,address_hex=f'0x{v:08X}',size=z,type=types.get(info&15,str(info&15)),binding=info>>4,section=idx,keywords=';'.join(k for k in KEYWORDS if k in name.lower())))
    info = dict(path=str(path),size=len(data),sha256=hashlib.sha256(data).hexdigest(),bits=bits,endian='little' if endian=='<' else 'big',machine=machine,machine_name='MIPS' if machine==8 else str(machine),elf_type=etype,entry=f'0x{entry:08X}',section_count=shnum,program_header_count=phnum,symbol_count=len(rows),symbol_tables=sum(s[1] in (2,11) for s in sections))
    return info,rows
