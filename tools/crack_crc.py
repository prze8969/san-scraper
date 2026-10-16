import struct

# Load s05.dat
d = open('samples/s05.dat', 'rb').read()

# Header:
ch_off = 60
hdr_data = d[:60]
hdr_crc_le = struct.unpack('<H', d[60:62])[0]
hdr_crc_be = struct.unpack('>H', d[60:62])[0]

# Blocks:
# blk 0: b1 01 13 00 ... len=19 (total 4+19 = 23 bytes), crc at d[85:87]
b0_full = d[62:85]
b0_body = d[66:85]
b0_crc_le = struct.unpack('<H', d[85:87])[0]
b0_crc_be = struct.unpack('>H', d[85:87])[0]

# blk 2 (event):
# d[116:136]
b2_full = d[116:136] # b1 02 10 00 ...
b2_body = d[120:136]
b2_crc_le = struct.unpack('<H', d[136:138])[0]
b2_crc_be = struct.unpack('>H', d[136:138])[0]

print(f"Target hdr_crc: LE=0x{hdr_crc_le:04x}, BE=0x{hdr_crc_be:04x}")
print(f"Target b0_crc: LE=0x{b0_crc_le:04x}, BE=0x{b0_crc_be:04x}")
print(f"Target b2_crc: LE=0x{b2_crc_le:04x}, BE=0x{b2_crc_be:04x}")

# Let's test standard algorithms:
# 1. 16-bit additive sum (LE/BE)
for name, data in [("hdr_full", hdr_data), ("hdr_no_magic", hdr_data[4:]), 
                   ("b0_full", b0_full), ("b0_body", b0_body), ("b0_no_sync", b0_full[1:])]:
    s16 = sum(data) & 0xFFFF
    s16_inv = (~sum(data)) & 0xFFFF
    xor16 = 0
    for i in range(0, len(data)-1, 2):
        xor16 ^= struct.unpack('<H', data[i:i+2])[0]
    # Fletcher 16
    c0 = 0
    c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    fl16 = (c1 << 8) | c0
    fl16_sw = (c0 << 8) | c1
    print(f"  {name}: sum=0x{s16:04x}, sum_inv=0x{s16_inv:04x}, fletcher=0x{fl16:04x}, fletcher_sw=0x{fl16_sw:04x}")

# Now CRC-16 brute-force generator
def crc16_generic(data, poly, init, xorout, refin, refout):
    reg = init
    if refin:
        for b in data:
            reg ^= b
            for _ in range(8):
                if reg & 1:
                    reg = (reg >> 1) ^ poly
                else:
                    reg >>= 1
    else:
        for b in data:
            reg ^= (b << 8)
            for _ in range(8):
                if reg & 0x8000:
                    reg = ((reg << 1) ^ poly) & 0xFFFF
                else:
                    reg = (reg << 1) & 0xFFFF
    return (reg ^ xorout) & 0xFFFF

# Standard polynomials:
polys_normal = [0x1021, 0x8005, 0x0589, 0x3D65, 0x8BB7, 0x2F15]
polys_refl = [0x8408, 0xA001, 0x90A0, 0xA6BC, 0xEB21]
inits = [0x0000, 0xFFFF, 0x1D0F, 0x800D]
xorouts = [0x0000, 0xFFFF]

found = []
for p in polys_normal:
    for init in inits:
        for xo in xorouts:
            # test normal
            res_hdr = crc16_generic(hdr_data, p, init, xo, False, False)
            res_b0 = crc16_generic(b0_full, p, init, xo, False, False)
            res_b0_body = crc16_generic(b0_body, p, init, xo, False, False)
            if res_hdr in (hdr_crc_le, hdr_crc_be) or res_b0 in (b0_crc_le, b0_crc_be) or res_b0_body in (b0_crc_le, b0_crc_be):
                found.append(('normal', hex(p), hex(init), hex(xo), hex(res_hdr), hex(res_b0), hex(res_b0_body)))

for p in polys_refl:
    for init in inits:
        for xo in xorouts:
            # test reflected
            res_hdr = crc16_generic(hdr_data, p, init, xo, True, True)
            res_b0 = crc16_generic(b0_full, p, init, xo, True, True)
            res_b0_body = crc16_generic(b0_body, p, init, xo, True, True)
            if res_hdr in (hdr_crc_le, hdr_crc_be) or res_b0 in (b0_crc_le, b0_crc_be) or res_b0_body in (b0_crc_le, b0_crc_be):
                found.append(('reflected', hex(p), hex(init), hex(xo), hex(res_hdr), hex(res_b0), hex(res_b0_body)))

print("CRC Candidates found:", found)
