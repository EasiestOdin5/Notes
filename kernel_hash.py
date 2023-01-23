import os
import pefile
import json


INTERESTING_DLLS = [
    "kernel32.dll", "ntdll.dll", "ws2_32.dll"
]


for filename in os.listdir("C:\\Windows\System32"):
    if filename.lower() in INTERESTING_DLLS:
        pe = pefile.PE("C:\\Windows\\System32\\" + filename)

        lib_hash = 0
        # k\x00e\x00r\x00n\x00e\x00l\x003\x002\x00.\x00d\x00l\x00l\x00
        for i in range(0, len(filename*2)):
            ov = 0
            if i%2 == 0:
                ov = ord(filename[int(i/2)])
            if ov >= 0x61:
                ov = ov - 0x20
            lib_hash = (lib_hash >> 0xd) | ((lib_hash << 0x13) & 0xffffffff)
            lib_hash = lib_hash + ov
        # \x00\x00
        lib_hash = (lib_hash >> 0xd) | ((lib_hash << 0x13) & 0xffffffff)
        lib_hash = (lib_hash >> 0xd) | ((lib_hash << 0x13) & 0xffffffff)
        print(hex(lib_hash))

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name is None:
                continue
            api = exp.name.decode('utf-8')
            hash = 0
            for c in api:
                #hash = hash & 0xffffffff
                hash = (hash >> 0xd) | ((hash << 0x13) & 0xffffffff)
                hash = hash + ord(c)
                #print(ord(c), hex(hash))
            hash = (hash >> 0xd) | ((hash << 0x13) & 0xffffffff)
            print(filename, api, hex(lib_hash), hex(hash), hex((lib_hash + hash) & 0xffffffff))

## NTDLL 3e9a174f
## kernel32.dll 0x92af16da
## 0x4ecd6fa8


