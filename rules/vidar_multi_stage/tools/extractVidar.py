from pathlib import Path

blob = Path("blob.bin").read_bytes()

key_dword_count = 0x32
key_size = key_dword_count * 4

key = blob[:key_size]
ciphertext = blob[key_size:]

out = bytearray(ciphertext)
for off in range(0, len(out) - (len(out) % 4), 4):
    key_off = (off // 4) % key_dword_count
    k = int.from_bytes(key[key_off * 4:key_off * 4 + 4], "little")
    c = int.from_bytes(out[off:off + 4], "little")
    out[off:off + 4] = (c ^ k).to_bytes(4, "little")

Path("vidar_decoded.bin").write_bytes(out)
print("Decrypted. Written to vidar_decoded.bin")
