"""Custom glyph IDs are independent of Unicode; no OCR or inferred replacements."""
import re
from .runtime import read_csv
TOKEN=re.compile(r'��������([0-9a-fA-F]{4})��')

class Codec:
    def __init__(self,path):
        self.mapping={};self.reverse={}
        for row in read_csv(path):
            i=int(row['glyph_index']);ch=row['character']
            if not 0<=i<3528 or i in self.mapping or len(ch)!=1:raise ValueError('Invalid or duplicate glyph entry')
            self.mapping[i]=ch;self.reverse.setdefault(ch,i)
        if not self.mapping:raise ValueError('Empty glyph map')

    def decode_run(self,data,start,maximum=4096):
        p=start;chars=[];unknown=[];ids=[]
        while p<len(data) and len(chars)<maximum:
            c=data[p]
            if c<0x27:break
            if c>=0x30:i=c-0x30;step=1
            else:
                if p+1>=len(data):break
                code=c*256+data[p+1];step=2
                if code<0x2830:
                    chars.append(f'��������{code:04X}��');ids.append(100000+code);unknown.append(100000+code);p+=2;continue
                i=code-0x2830
                if i>=1764:break
            chars.append(self.mapping.get(i,f'������{i}��'));ids.append(i)
            if i not in self.mapping:unknown.append(i)
            p+=step
        return ''.join(chars),p,sorted(set(unknown)),ids

    def encode_original(self,text):
        out=bytearray();p=0
        while p<len(text):
            token=TOKEN.match(text,p)
            if token:
                code=int(token[1],16)
                if not 0x2700<=code<0x2830:raise ValueError('Not an original special code')
                out.extend(code.to_bytes(2,'big'));p=token.end();continue
            ch=text[p];p+=1
            if ch not in self.reverse:raise ValueError('Unmapped character: '+ch)
            i=self.reverse[ch]
            if i>=1764:raise ValueError('Extended glyph needs a separately verified ELF/font build')
            if i<208:out.append(i+0x30)
            else:out.extend((i+0x2830).to_bytes(2,'big'))
        return bytes(out)
