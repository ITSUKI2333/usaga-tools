"""Explicit workspace configuration and Python-process filesystem write guard."""
import os,sys,json,hashlib,csv,struct,datetime,tempfile
from pathlib import Path

def read_csv(path):
    with Path(path).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        while b:=f.read(8*1024*1024):h.update(b)
    return h.hexdigest()

def contained(path,root):
    path=Path(path).resolve()
    if not path.is_relative_to(root):raise ValueError('Path outside work_dir: '+str(path))
    return path

class Session:
    def __init__(self,config,command):
        self.config_path=Path(config).resolve()
        self.config=json.loads(self.config_path.read_text(encoding='utf-8'))
        work=Path(self.config['work_dir'])
        self.root=(self.config_path.parent/work).resolve() if not work.is_absolute() else work.resolve()
        if os.name=='nt' and self.root.drive.upper()=='C:':raise ValueError('C: work directories are forbidden')
        if self.config.get('profile','SLPS-25199')!='SLPS-25199':raise ValueError('Only Japanese SLPS-25199 is supported')
        self.inputs=set();self.written=set();self.created_dirs=set();self.events=[]
        self.success=False;self.command=command
        sys.addaudithook(self.audit)
        self.root.mkdir(parents=True,exist_ok=True)
        for name in ('_temp','_cache','_logs'):(self.root/name).mkdir(exist_ok=True)
        for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(self.root/'_temp')
        for key in ('XDG_CACHE_HOME','PYTHONPYCACHEPREFIX','PIP_CACHE_DIR','MPLCONFIGDIR'):os.environ[key]=str(self.root/'_cache')
        os.environ['PYTHONUSERBASE']=str(self.root/'_cache/python_user')
        tempfile.tempdir=str(self.root/'_temp')
        stamp=datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        self.report=self.root/'_logs'/(stamp+'_'+command+'.json')
        self.manifest=self.report.with_suffix('.files.txt')

    def inside(self,p):return contained(p,self.root)

    def audit(self,event,args):
        if event=='open' and isinstance(args[0],(str,bytes,os.PathLike)) and isinstance(args[2],int) and args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            p=self.inside(os.fsdecode(args[0]))
            if p in self.inputs or p==self.config_path:raise PermissionError('Refusing input overwrite: '+str(p))
            self.written.add(str(p))
        elif event=='os.mkdir':self.created_dirs.add(str(self.inside(args[0])))
        elif event in ('os.remove','os.rmdir','os.chmod','os.utime','os.truncate'):
            p=self.inside(args[0])
            if p in self.inputs or p==self.config_path:raise PermissionError('Refusing input mutation')
        elif event in ('os.rename','os.link','os.symlink'):
            a=self.inside(args[0]);b=self.inside(args[1])
            if a in self.inputs or b in self.inputs or self.config_path in (a,b):raise PermissionError('Refusing input move/replacement')
        elif event in ('subprocess.Popen','os.system','os.chdir'):
            raise PermissionError('External processes and directory changes are disabled')

    def input(self,key):
        raw=self.config.get(key)
        if not raw:raise ValueError('Configure '+key+' first')
        p=Path(raw);p=self.inside(p if p.is_absolute() else self.root/p)
        if not p.is_file():raise ValueError('Missing input: '+str(p))
        self.inputs.add(p);return p

    def supplied_input(self,p):
        p=Path(p);p=self.inside(p if p.is_absolute() else self.root/p)
        if not p.is_file():raise ValueError('Missing input: '+str(p))
        self.inputs.add(p);return p

    def output(self,relative):
        p=self.inside(self.root/relative)
        if p.exists():raise FileExistsError('Output already exists; use a new name: '+str(p))
        p.mkdir(parents=True)
        return p

    def json(self,p,obj):
        with self.inside(p).open('w',encoding='utf-8') as f:json.dump(obj,f,ensure_ascii=False,indent=2)

    def csv(self,p,rows,fields=None):
        rows=list(rows)
        fields=fields or list(dict.fromkeys(k for r in rows for k in r)) or ['no_records']
        with self.inside(p).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fields,extrasaction='ignore');w.writeheader();w.writerows(rows)

    def finish(self,error=None):
        self.written.update((str(self.report),str(self.manifest)))
        self.json(self.report,dict(command=self.command,success=error is None,error=error,work_dir=str(self.root),created_directories=sorted(self.created_dirs),written_files=sorted(self.written),events=self.events))
        self.manifest.write_text('\n'.join(sorted(self.written))+'\n',encoding='utf-8')
        print('Written files:',len(self.written),'(including audit manifests)')
        print('File manifest:',self.manifest)

class Game:
    ELF_HASH='3f66b74b090a90fd3cb7573b9c7c4ef9ed1299fe3ee36c1f6d84cccd80ac2760'
    ISO_HASH='62882bb08356dc3457f65e6bbee08e712b5be4a16faf803636226d3dcac87e54'
    ISO_SIZE=3685679104

    def __init__(self,session):
        self.elf_path=session.input('elf');self.elf=self.elf_path.read_bytes()
        if hashlib.sha256(self.elf).hexdigest()!=self.ELF_HASH:raise ValueError('ELF does not match supported Japanese revision')
        ph=struct.unpack_from('<I',self.elf,28)[0]
        size,num=struct.unpack_from('<HH',self.elf,42)
        self.segments=[struct.unpack_from('<8I',self.elf,ph+i*size) for i in range(num)]

    def elf_region(self,address,n):
        s=next(s for s in self.segments if s[0]==1 and s[2]<=address and address+n<=s[2]+s[4])
        p=s[1]+address-s[2];return self.elf[p:p+n],p

    def iso(self,session):
        p=session.input('iso')
        if p.stat().st_size!=self.ISO_SIZE:raise ValueError('Original JP ISO size mismatch')
        with p.open('rb') as f:
            f.seek(0xfa800)
            if f.read(len(self.elf))!=self.elf:raise ValueError('ISO embedded ELF mismatch')
        return p

    def resources(self,iso):
        sectors=struct.unpack('<513I',self.elf_region(0x81b420,2052)[0])
        for i in range(256):
            lo,hi=sectors[2*i:2*i+2];lo*=2048;hi*=2048
            if not 0<=lo<hi<=iso.stat().st_size:raise ValueError('Invalid MES bounds')
            yield str(i),lo,hi
        tono=struct.unpack('<23I',self.elf_region(0x81b3c0,92)[0])
        yield 'TONO5',tono[5]*2048,tono[6]*2048
