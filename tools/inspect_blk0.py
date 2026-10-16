import struct

d = open('samples/s05.dat', 'rb').read()
# Let's inspect the block bodies:
# blk 0: b1 01 13 00 00 00 04 b1 00 88 04 4a 01 7f 04 40 01 7c 04 2d 01 7a 04 53 37
# wait! Look at the payload of blk 0:
# b1: sync
# 01: type (DATA)
# 13 00: len = 19 (0x13)
# payload (19 bytes): 
# 00 00: start sample = 0
# 04: count = 4
# Notice: 4 samples * 2 channels * 2 bytes = 16 bytes!
# 2 + 1 + 16 = 19 bytes!
# bytes:
# sample 0: 88 04, 4a 01 -> wait, what is "b1 00" before 88 04?!
# Look closely at d[62:]:
print("d[62:90]:", d[62:90].hex(' '))
