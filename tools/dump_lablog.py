import struct

for fname in ('s05.dat', 's06.dat', 's07.dat'):
    d = open('samples/' + fname, 'rb').read()
    num_channels = d[5]
    ch_offset = 36 + num_channels * 12
    hdr_bytes = d[:ch_offset]
    hdr_crc_le = struct.unpack('<H', d[ch_offset:ch_offset+2])[0]
    hdr_crc_be = struct.unpack('>H', d[ch_offset:ch_offset+2])[0]
    print(f"=== {fname} ===")
    print(f"  Header bytes (0..{ch_offset}) len={len(hdr_bytes)} hex={hdr_bytes.hex()}")
    print(f"  hdr_crc: 0x{hdr_crc_le:04x} (LE) / 0x{hdr_crc_be:04x} (BE)")
    offset = ch_offset + 2
    blk_idx = 0
    while offset < len(d):
        b_sync = d[offset]
        if b_sync != 0xB1:
            print(f"  [NON-SYNC at {offset}]: 0x{b_sync:02x}")
            offset += 1
            continue
        b_type = d[offset+1]
        b_len = struct.unpack('<H', d[offset+2:offset+4])[0]
        body = d[offset+4:offset+4+b_len]
        crc_le = struct.unpack('<H', d[offset+4+b_len:offset+4+b_len+2])[0]
        crc_be = struct.unpack('>H', d[offset+4+b_len:offset+4+b_len+2])[0]
        print(f"  blk {blk_idx}: type={b_type}, len={b_len}, crc_le=0x{crc_le:04x}, crc_be=0x{crc_be:04x}, full_hex={d[offset:offset+4+b_len].hex()}")
        offset = offset + 4 + b_len + 2
        blk_idx += 1
