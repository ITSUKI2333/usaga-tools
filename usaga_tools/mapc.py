"""Verified MAPC 8-bit linear uploads: header, then palette, then pixels.

This is a different container from native_pairs()'s pixel/palette chunks.
No game asset bytes or localized labels are included in this module.
"""
import struct
from .images import color


def decode_mapc(blob):
    if len(blob) < 128 or blob[:8] != b'mapc_tm2':
        raise ValueError('Not a complete mapc_tm2 header')
    x, y, width, height, palette_bytes, psm = struct.unpack_from('<6I', blob, 16)
    if not (0 < width <= 4096 and 0 < height <= 4096):
        raise ValueError('Unsupported MAPC dimensions')
    if psm != 0x13 or palette_bytes != 1024:
        raise ValueError('Only verified PSMT8 / 1024-byte palette MAPC is supported')
    expected = 128 + palette_bytes + width * height
    if len(blob) != expected:
        raise ValueError('MAPC payload size mismatch')
    palette_raw = blob[128:128+palette_bytes]
    palette = []
    for index in range(256):
        swizzled = (index & ~24) | ((index & 8) << 1) | ((index & 16) >> 1)
        palette.append(color(palette_raw[swizzled*4:swizzled*4+4], 3))
    indices = blob[128+palette_bytes:]
    rgba = b''.join(palette[index] for index in indices)
    return width, height, rgba, dict(x=x, y=y, width=width, height=height,
        psm=psm, header_bytes=128, palette_bytes=palette_bytes,
        pixel_offset=128+palette_bytes, storage_assumption='linear PSMT8 upload',
        palette_order='CSM1 swap bits 3 and 4')


def decode_package(data):
    if len(data) < 12:
        raise ValueError('Truncated MAPC package')
    count = struct.unpack_from('<I', data)[0]
    header_size = 4 + 4 * (count + 1)
    if not 1 <= count <= 64 or header_size > len(data):
        raise ValueError('Invalid MAPC package count')
    pointers = struct.unpack_from(f'<{count+1}I', data, 4)
    if (pointers[0] < header_size or pointers[-1] > len(data) or
            any(a >= b for a, b in zip(pointers, pointers[1:]))):
        raise ValueError('Invalid MAPC package offsets')
    pictures = []
    for index, (start, end) in enumerate(zip(pointers, pointers[1:])):
        width, height, rgba, metadata = decode_mapc(data[start:end])
        pictures.append(dict(index=index, offset=start, bytes=end-start,
            width=width, height=height, rgba=rgba, metadata=metadata))
    return pictures
