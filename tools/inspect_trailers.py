import struct

# Let's inspect all blocks of s05, s06, s07
# Is the trailer actually a CRC-16 or something else?
# Let's check s05.dat:
d = open('samples/s05.dat', 'rb').read()
# Let's print each block and what follows each block:
offset = 62
blk_num = 0
while offset < len(d):
    sync = d[offset]
    b_type = d[offset+1]
    b_len = struct.unpack('<H', d[offset+2:offset+4])[0]
    payload = d[offset+4:offset+4+b_len]
    trailer = d[offset+4+b_len:offset+4+b_len+2]
    u16_le = struct.unpack('<H', trailer)[0]
    u16_be = struct.unpack('>H', trailer)[0]
    print(f"s05 blk {blk_num}: type={b_type}, len={b_len}, trailer_bytes={trailer.hex()}, u16_le=0x{u16_le:04x}, u16_be=0x{u16_be:04x}")
    offset += 4 + b_len + 2
    blk_num += 1

print("Total bytes in s05:", len(d), "offset at end:", offset)
