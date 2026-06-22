#!/usr/bin/env python3
"""
Layer-1 decryptor for `shader128.map` — reproduces statically what the trojanized
Qt5Core.dll loader (FUN_67001e99) does at runtime.

Loader logic recovered statically (Ghidra + clean-DLL diff):
  - SearchPathW/CreateFileW/ReadFile the file `shader128.map` into a buffer.
  - At buffer offset 0x116e (config local_8[8]) a header: [u32 length][u32 key].
  - Additive cipher: for each dword in [0, length): *dword = (*dword + key) & 0xffffffff,
    starting right after the 8-byte header (config local_8[9] = 8).
  - The loader then maps the decrypted region as code (GlobalAlloc, VirtualProtect 0x40,
    jump entry). This script stops at "decrypted" instead of executing it.

OUTPUT: HijackLoader first-stage x86 shellcode

Usage:  python3 unpack_shader128.py shader128.map  [out.bin]
        (default output: shader128_stage_shellcode.bin)
"""
import sys, struct

HDR_OFF = 0x116e   # config local_8[8]
HDR_LEN = 8        # config local_8[9]  ([u32 length][u32 key])

def unpack(data: bytes):
    if len(data) < HDR_OFF + HDR_LEN:
        raise SystemExit(f"file too small ({len(data)} bytes) — expected header at 0x{HDR_OFF:x}")
    length, key = struct.unpack_from("<II", data, HDR_OFF)
    print(f"[*] header @0x{HDR_OFF:x}: length=0x{length:x} ({length}) key=0x{key:08x}")
    start = HDR_OFF + HDR_LEN
    buf = bytearray(data)
    n = length - (length % 4)
    for i in range(start, start + n, 4):
        v = (struct.unpack_from("<I", buf, i)[0] + key) & 0xffffffff
        struct.pack_into("<I", buf, i, v)
    payload = bytes(buf[start:start + length])
    return payload

def report(p: bytes):
    # Success = the decrypted region is the HijackLoader first-stage x86 shellcode.
    # It is raw shellcode (NOT a PE) and NOT Vidar, so there is intentionally no MZ check.
    print(f"[*] decrypted region: {len(p)} bytes, starts {p[:4]!r}")
    has_tapisrv = b"tapisrv.dll" in p[:0x20]
    has_entry   = p[0x19:0x1c] == b"\x55\x8b\xec"   # entry: push ebp / mov ebp,esp
    checks = {
        "stage marker '\\rtapisrv.dll' @ start": has_tapisrv,
        "x86 entry (55 8B EC) @ 0x19":           has_entry,
        "is NOT a PE (expected)":                p[:2] != b"MZ",
    }
    for k, v in checks.items():
        print(f"      {k:38}: {'OK' if v else 'MISSING'}")
    if has_tapisrv and has_entry:
        print("[+] looks like the HijackLoader first-stage shellcode (decryption OK).")
    else:
        print("[!] does not look like the expected stage shellcode — check the input/offsets.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    data = open(sys.argv[1], "rb").read()
    payload = unpack(data)
    out = sys.argv[2] if len(sys.argv) > 2 else "shader128_stage_shellcode.bin"
    open(out, "wb").write(payload)
    print(f"[+] wrote {out}")
    report(payload)
