"""Asset-free binary fixtures for bugs found during final review."""
import os,sys,struct,unittest
from usaga_tools import mapc,scripts
from usaga_tools.experimental import lay


def synthetic_mapc():
    blob=bytearray(128+1024+4);blob[:8]=b'mapc_tm2'
    struct.pack_into('<6I',blob,16,0,0,2,2,1024,19)
    blob[128+16*4:128+16*4+4]=bytes((200,10,20,64))
    blob[128+8*4:128+8*4+4]=bytes((30,40,220,128))
    blob[-4:]=bytes((8,16,8,16))
    return struct.pack('<3I',1,12,12+len(blob))+blob


def synthetic_lay(unreferenced=False):
    tex=32;page_size=512*4;pixel=48;palette=pixel+page_size*2
    frame_count=2 if unreferenced else 1
    frame_section=tex+palette+1024
    sequence_section=frame_section+frame_count*4+frame_count*72
    data=bytearray(sequence_section+4+12+36)
    struct.pack_into('<4s5I',data,0,b'lay\0',tex,frame_section,sequence_section,frame_count,1)
    struct.pack_into('<4I',data,tex,19,2048,16,32)
    struct.pack_into('<4I',data,tex+16,pixel,4,pixel+page_size,4)
    struct.pack_into('<I',data,tex+32,palette)
    data[tex+pixel+page_size:tex+pixel+page_size*2]=bytes([1])*page_size
    data[tex+palette:tex+palette+8]=bytes((255,0,0,64,0,0,255,64))
    for i in range(frame_count):
        at=frame_section+frame_count*4+i*72
        struct.pack_into('<I',data,frame_section+i*4,at-frame_section)
        struct.pack_into('<I',data,at+40,1)
        struct.pack_into('<8h4HI',data,at+44,-2,-2,0,-2,-2,0,0,0,0,0,2,2,0x08000001)
    struct.pack_into('<I',data,sequence_section,4)
    struct.pack_into('<I',data,sequence_section+4,1)
    entry=sequence_section+16
    struct.pack_into('<H',data,entry+6,12)
    struct.pack_into('<2f',data,entry+20,1.0,1.0)
    data[entry+32]=1
    return data


class FormatRegression(unittest.TestCase):
    def test_mapc_palette_precedes_pixels_and_swizzle(self):
        pictures=mapc.decode_package(synthetic_mapc())
        self.assertEqual(len(pictures),1)
        self.assertEqual(pictures[0]['rgba'][:8],bytes((200,10,20,128,30,40,220,255)))

    def test_mapc_truncation_and_pointer_bounds(self):
        data=synthetic_mapc()
        with self.assertRaises(ValueError):mapc.decode_package(data[:-1])
        broken=bytearray(data);struct.pack_into('<I',broken,4,8)
        with self.assertRaises(ValueError):mapc.decode_package(broken)

    def test_script_1614_mode3_target_and_lengths(self):
        data=bytearray(48);struct.pack_into('<2I',data,0,1,8)
        data[8:15]=b'\x16\x14\x03'+struct.pack('<I',40)
        data[15]=1;data[40:43]=b'\x30\x31\x01'
        def decode(raw,p):
            end=p
            while end<len(raw) and raw[end]>=0x30:end+=1
            return 'X'*(end-p),end,[],list(range(end-p))
        import types
        x=types.SimpleNamespace(decode_run=decode)
        lengths,_=scripts.infer_lengths(x,[])
        self.assertEqual([lengths[k] for k in (b'\x16\x14',b'\x16\x06',b'\x16\x07')],[7,8,8])
        found,*_=scripts.graph_bank(x,'synthetic',bytes(data),0,[8],lengths)
        self.assertIn(40,found)
        data[10]=2
        found,*_=scripts.graph_bank(x,'synthetic',bytes(data),0,[8],lengths)
        self.assertNotIn(40,found)

    def test_lay_sequence_selects_second_texture_page(self):
        data=synthetic_lay(unreferenced=True)
        frames=lay.decode_frames(data,(512,8))
        sequences=lay.decode_sequences(data,frames,[4,4])
        self.assertEqual(frames[0]['page'],1)
        self.assertIsNone(frames[1]['page'])
        self.assertEqual(sequences[0]['entries'][0]['duration_units'],12)
        self.assertNotIn('duration_game_frames',sequences[0]['entries'][0])

    def test_lay_missing_page_and_truncated_records(self):
        data=synthetic_lay();frames=lay.decode_frames(data,(512,8))
        data[-4]=7
        with self.assertRaises(ValueError):lay.decode_sequences(data,frames,[4,4])
        data=synthetic_lay()[:-2]
        with self.assertRaises(ValueError):lay.decode_sequences(data,frames,[4,4])
        with self.assertRaises(ValueError):lay.decode_frames(b'lay\0',(512,4))

    def test_lay_compositor_depth_is_not_flip_and_alpha_seam(self):
        vendor=os.environ.get('USAGA_TEST_PILLOW_DIR')
        if not vendor:self.skipTest('Optional Pillow path not configured')
        sys.path.insert(0,vendor);lay.require_pillow()
        tile=lay.Image.new('RGBA',(2,2))
        tile.putdata([(255,0,0,128),(0,0,255,128)]*2)
        frame={'parts':[dict(xy=[-2,-2,0,-2,-2,0,0,0],uv=[0,0,2,2],flags=0x08000001)]}
        image=lay.compose(tile,frame)
        self.assertEqual(image.getpixel((178,257)),(255,0,0,128))
        self.assertEqual(image.getpixel((179,257)),(0,0,255,128))
        self.assertEqual(set(image.getchannel('A').tobytes()),{0,128})
        frame['parts'][0]['flags']=0x08010000
        self.assertEqual(lay.compose(tile,frame).getpixel((178,257)),(0,0,255,128))
