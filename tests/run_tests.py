"""Synthetic-only regression checks; every fixture is written under explicit work_dir."""
import os,sys
sys.dont_write_bytecode=True
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
work=os.environ.get('USAGA_TEST_WORK')
if not work:raise SystemExit('Set USAGA_TEST_WORK to an isolated non-C work directory first')
root=Path(work).resolve()
if os.name=='nt' and root.drive.upper()=='C:':raise SystemExit('C: test work directory rejected')
root.mkdir(parents=True,exist_ok=True)
for k in ('TEMP','TMP','TMPDIR'):os.environ[k]=str(root)
import tempfile,unittest,json,csv,struct,hashlib,types
tempfile.tempdir=str(root)
from usaga_tools.runtime import Session
from usaga_tools.codec import Codec
from usaga_tools.cli import validate_edits,apply_plan
from usaga_tools import cli,scripts,images
from usaga_tools.elf import parse_elf
from usaga_tools.experimental.usaga_cn_extended_codec import Asm,CPU

class Regression(unittest.TestCase):
    def setUp(self):
        self.dir=Path(tempfile.mkdtemp(prefix='fixture_',dir=root))
    def codec(self):
        p=self.dir/'mapping.csv'
        with p.open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.writer(f);w.writerow(['glyph_index','character']);w.writerows([(0,'甲'),(207,'乙'),(208,'丙')])
        return Codec(p)
    def test_custom_encoding_boundary(self):
        c=self.codec();raw=b'\x30\xff\x29\x00\x01'
        t,end,u,ids=c.decode_run(raw,0)
        self.assertEqual((t,end,u,ids),('甲乙丙',4,[],[0,207,208]));self.assertEqual(c.encode_original(t),raw[:-1])
        with self.assertRaises(ValueError):c.encode_original('丁')
    def test_special_and_truncated_glyph(self):
        c=self.codec();self.assertEqual(c.decode_run(b'\x27\x80\x01',0)[0],'〈特殊码2780〉')
        self.assertEqual(c.decode_run(b'\x29',0)[1],0)
        self.assertEqual(c.encode_original('〈特殊码2780〉'),b'\x27\x80')
    def test_duplicate_map_rejected(self):
        p=self.dir/'bad.csv';p.write_text('glyph_index,character\n0,甲\n0,乙\n',encoding='utf-8')
        with self.assertRaises(ValueError):Codec(p)
    def test_pointer_table_bounds(self):
        good=struct.pack('<3I',2,12,13)+b'\x01\x01'
        self.assertEqual(scripts.valid_bank(good),[12,13])
        self.assertIsNone(scripts.valid_bank(struct.pack('<3I',2,4,100)))
    def test_overlapping_and_resizing_patches_rejected(self):
        with self.assertRaises(ValueError):validate_edits([dict(offset=0,before_hex='0000',after_hex='00')],8)
        with self.assertRaises(ValueError):validate_edits([dict(offset=0,before_hex='0000',after_hex='1111'),dict(offset=1,before_hex='00',after_hex='22')],8)
        with self.assertRaises(ValueError):validate_edits([dict(offset=8,before_hex='00',after_hex='22')],8)
    def test_gra_structural_pair_and_size_rejection(self):
        # 2x2 4-bit image; palette and pixels are synthetic solid colours.
        b=bytearray(16+18+80);struct.pack_into('<4I',b,0,2,16,34,114)
        struct.pack_into('<4H',b,16,4,2,2,0);struct.pack_into('<2H',b,34,4,16)
        self.assertEqual(len(images.native_pairs(b)),1)
        struct.pack_into('<H',b,18,4);self.assertEqual(images.native_pairs(b),[])
    def test_elf_non_elf_rejected(self):
        p=self.dir/'not.elf';p.write_bytes(b'NOTELF'+b'\0'*64)
        with self.assertRaises(ValueError):parse_elf(p)
    def test_assembler_branch_delay_and_signed_range(self):
        a=Asm(0x1000);a.branch(4,'zero','zero','done');a.i(9,'v0','zero',7);a.label('done');a.r(8,'zero','ra');a.nop()
        data=a.finish();ws=struct.unpack('<5I',data)
        self.assertEqual(ws[0]&65535,2);self.assertEqual(ws[1],0)
        a=Asm(0x1000);a.branch(4,'zero','zero','too_far');a.labels['too_far']=0x1004+32768*4
        with self.assertRaises(AssertionError):a.finish()
    def test_synthetic_iso_copy_preimage_and_guard(self):
        config=self.dir/'config.json';config.write_text(json.dumps(dict(work_dir=str(root),profile='SLPS-25199')),encoding='utf-8')
        source=self.dir/'source.img';source.write_bytes(bytes(range(256))*8);before=source.read_bytes();h=hashlib.sha256(before).hexdigest()
        plan=self.dir/'plan.json';plan.write_text(json.dumps(dict(schema='usaga-fixed-spans-v1',source_sha256=h,source_size=len(before),edits=[dict(offset=255,before_hex=before[255:258].hex(),after_hex='123456')])),encoding='utf-8')
        original=cli.Game
        class FakeGame:
            ISO_HASH=h
            def __init__(self,s):pass
            def iso(self,s):s.inputs.add(source.resolve());return source
        cli.Game=FakeGame;s=Session(config,'synthetic-copy')
        try:
            apply_plan(s,types.SimpleNamespace(plan=str(plan),out=str(self.dir/'build')))
            actual=(self.dir/'build/translated.iso').read_bytes()
            self.assertEqual(actual,before[:255]+bytes.fromhex('123456')+before[258:])
            self.assertEqual(source.read_bytes(),before)
            with self.assertRaises(PermissionError):source.open('wb')
            outside=root.parent/'usaga_test_forbidden_write.tmp'
            with self.assertRaises(ValueError):outside.open('wb')
            s.finish()
        finally:cli.Game=original

sys.path.insert(0,str(Path(__file__).resolve().parent))
from format_cases import FormatRegression
if __name__=='__main__':unittest.main(verbosity=2)
