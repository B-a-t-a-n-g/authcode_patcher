import sys
import struct
from Crypto.Cipher import AES

KEY_VER_OFFSET = 0x36B

HDR_DIGEST_OFFSET = 0x380
DIGEST_SIZE = 0x20

AUTHCODE_OFFSET = 0x7F90
AUTHCODE_SIZE = 0x70

AUTHCODE_MAGIC = b'\x79\x2B\x1A\xC1\xBB\x9B\x9A\x45'
AUTHCODE_FMT = '<8sII16s80s'
AUTHCODE_DATA_FMT = '<32s32sQ8x'

AUTHCODE_KEY = bytes.fromhex('2BCF698E79CFDDFAC24D4C25BF351E62')

with open(sys.argv[1], "r+b") as f:

    f.seek(KEY_VER_OFFSET)
    key_ver = struct.unpack_from('<I', f.read(0x04))[0]
    if  key_ver <= 2:
        print('key version 1!')
        sys.exit()

    f.seek(HDR_DIGEST_OFFSET)
    hdr_digest = f.read(DIGEST_SIZE)

    f.seek(AUTHCODE_OFFSET)
    authcode = bytearray(f.read(struct.calcsize(AUTHCODE_FMT)))
    magic, major, minor, iv, data = struct.unpack_from(AUTHCODE_FMT, authcode)

    if magic != AUTHCODE_MAGIC:
        print('no authcode magic at offset: 0x7F90')
        sys.exit()

    if major != 1 or minor != 1:
        print('invalid version')
        sys.exit()

    cipher = AES.new(AUTHCODE_KEY, AES.MODE_CBC, iv)
    data = bytearray(cipher.decrypt(data))
    hdr_digest_copy_1, hdr_digest_copy_2, copy_counter = struct.unpack_from(AUTHCODE_DATA_FMT, data)

    changed = False

    if hdr_digest_copy_1 != hdr_digest:
        print('hdr digest copy 1 missmatch!')
        struct.pack_into('<32s', data, 0, hdr_digest)
        changed = True

    if hdr_digest_copy_2 != hdr_digest:
        print('hdr digest copy 2 missmatch!')
        struct.pack_into('<32s', data, 32, hdr_digest)
        changed = True

    if copy_counter < 1:
        print('copy counter is below 1!')
        struct.pack_into('<Q', data, 64, 1)
        changed = True

    if changed:
        cipher = AES.new(AUTHCODE_KEY, AES.MODE_CBC, iv)
        data = cipher.encrypt(bytes(data))
        authcode = struct.pack(AUTHCODE_FMT, magic, major, minor, iv, data)

        f.seek(AUTHCODE_OFFSET)
        f.write(authcode)

        print('authocde patched.')
    else:
        print('authcode is valid already.')
