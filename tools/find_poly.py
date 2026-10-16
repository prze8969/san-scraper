import struct

# Let's brute-force the polynomial for CRC16:
# If CRC is linear, CRC(data ^ zeros) can find the polynomial directly!
# Or we can brute-force all 65536 polynomials with standard inits (0x0000, 0xFFFF)
# against b0_full or b0_body.

d = open('samples/s05.dat', 'rb').read()
b0_full = d[62:85]
b0_body = d[66:85]
b0_crc_le = struct.unpack('<H', d[85:87])[0]
b0_crc_be = struct.unpack('>H', d[85:87])[0]

b1_full = d[87:114]
b1_body = d[91:114]
b1_crc_le = struct.unpack('<H', d[114:116])[0]
b1_crc_be = struct.unpack('>H', d[114:116])[0]

def test_all_polys(data1, targ1_le, targ1_be, data2, targ2_le, targ2_be):
    matches = []
    # Test unreflected
    for poly in range(1, 0x10000):
        for init in (0x0000, 0xFFFF):
            for xorout in (0x0000, 0xFFFF):
                # compute on data1
                reg = init
                for b in data1:
                    reg ^= (b << 8)
                    for _ in range(8):
                        if reg & 0x8000:
                            reg = ((reg << 1) ^ poly) & 0xFFFF
                        else:
                            reg = (reg << 1) & 0xFFFF
                res1 = reg ^ xorout
                if res1 == targ1_le or res1 == targ1_be:
                    # check on data2!
                    reg2 = init
                    for b in data2:
                        reg2 ^= (b << 8)
                        for _ in range(8):
                            if reg2 & 0x8000:
                                reg2 = ((reg2 << 1) ^ poly) & 0xFFFF
                            else:
                                reg2 = (reg2 << 1) & 0xFFFF
                    res2 = reg2 ^ xorout
                    if (res1 == targ1_le and res2 == targ2_le) or (res1 == targ1_be and res2 == targ2_be):
                        matches.append(('unref', hex(poly), hex(init), hex(xorout), 'LE' if res1==targ1_le else 'BE'))

    # Test reflected
    for poly in range(1, 0x10000):
        for init in (0x0000, 0xFFFF):
            for xorout in (0x0000, 0xFFFF):
                reg = init
                for b in data1:
                    reg ^= b
                    for _ in range(8):
                        if reg & 1:
                            reg = (reg >> 1) ^ poly
                        else:
                            reg >>= 1
                res1 = reg ^ xorout
                if res1 == targ1_le or res1 == targ1_be:
                    reg2 = init
                    for b in data2:
                        reg2 ^= b
                        for _ in range(8):
                            if reg2 & 1:
                                reg2 = (reg2 >> 1) ^ poly
                            else:
                                reg2 >>= 1
                    res2 = reg2 ^ xorout
                    if (res1 == targ1_le and res2 == targ2_le) or (res1 == targ1_be and res2 == targ2_be):
                        matches.append(('refl', hex(poly), hex(init), hex(xorout), 'LE' if res1==targ1_le else 'BE'))

    return matches

print("Testing b0_full / b1_full...")
m_full = test_all_polys(b0_full, b0_crc_le, b0_crc_be, b1_full, b1_crc_le, b1_crc_be)
print("Matches full:", m_full)

print("Testing b0_body / b1_body...")
m_body = test_all_polys(b0_body, b0_crc_le, b0_crc_be, b1_body, b1_crc_le, b1_crc_be)
print("Matches body:", m_body)
