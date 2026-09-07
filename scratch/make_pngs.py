import os
import zlib
import struct

def make_png(width, height, red, green, blue):
    # PNG signature
    png_sig = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk
    ihdr_data = struct.pack('!IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data)
    ihdr_chunk = struct.pack('!I', len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack('!I', ihdr_crc)
    
    # IDAT chunk (raw RGB image data)
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0) # Filter type 0
        for x in range(width):
            # Cyan to Blue shield pattern
            if x in (0, width-1) or y in (0, height-1):
                raw_data.extend([59, 130, 246]) # Border blue
            else:
                raw_data.extend([6, 182, 212]) # Cyan fill
                
    idat_data = zlib.compress(bytes(raw_data))
    idat_crc = zlib.crc32(b'IDAT' + idat_data)
    idat_chunk = struct.pack('!I', len(idat_data)) + b'IDAT' + idat_data + struct.pack('!I', idat_crc)
    
    # IEND chunk
    iend_crc = zlib.crc32(b'IEND')
    iend_chunk = struct.pack('!I', 0) + b'IEND' + struct.pack('!I', iend_crc)
    
    return png_sig + ihdr_chunk + idat_chunk + iend_chunk

icons_dir = r"c:\Users\varun\OneDrive\Desktop\network-anomaly-detection\extension\icons"
os.makedirs(icons_dir, exist_ok=True)

for sz in [16, 48, 128]:
    data = make_png(sz, sz, 6, 182, 212)
    path = os.path.join(icons_dir, f"icon{sz}.png")
    with open(path, 'wb') as f:
        f.write(data)
    print("Wrote", path)
