#!/usr/bin/env python3
"""
Static extractor for the Rugmi/HijackLoader fake-XML container used in this
campaign.

The script extracts:
  - concatenated IDAT data from the fake XML/PNG-like stream
  - XOR-decoded LZNT1 stream
  - LZNT1-decompressed resource bundle
  - individual bundle resources
  - the X64L encrypted payload blob
  - the final XOR-decoded Vidar PE payload
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path


IDAT = b"IDAT"
IEND = b"IEND"
RESOURCE_ENTRY_SIZE = 0x8A
RESOURCE_COUNT_DELTA = 0xEE4
RESOURCE_TABLE_DELTA = 0x10DE


class ExtractionError(Exception):
    pass


def u16le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(path: Path, data: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "path": str(path),
        "size": len(data),
        "sha256": sha256(data),
    }


def is_chunk_type(value: bytes) -> bool:
    return len(value) == 4 and all(0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A for b in value)


def find_chunk_stream(data: bytes) -> int:
    """Find the first plausible PNG-like chunk stream containing IDAT chunks."""
    pos = 0
    while True:
        pos = data.find(IDAT, pos)
        if pos < 0:
            raise ExtractionError("could not locate an IDAT chunk marker")
        if pos < 4:
            pos += 1
            continue

        chunk_start = pos - 4
        try:
            chunk_len = u32be(data, chunk_start)
        except struct.error:
            pos += 1
            continue

        chunk_end = chunk_start + 8 + chunk_len + 4
        if chunk_len > 0 and chunk_end <= len(data):
            return chunk_start

        pos += 1


def parse_png_like_chunks(data: bytes, start: int) -> tuple[bytes, list[dict[str, object]]]:
    chunks: list[dict[str, object]] = []
    idat_parts: list[bytes] = []
    offset = start

    while offset + 12 <= len(data):
        length = u32be(data, offset)
        chunk_type = data[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4

        if crc_end > len(data) or not is_chunk_type(chunk_type):
            break

        chunk_data = data[data_start:data_end]
        stored_crc = u32be(data, data_end)
        calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        crc_ok = stored_crc == calc_crc

        chunk_info = {
            "offset": offset,
            "type": chunk_type.decode("ascii", errors="replace"),
            "length": length,
            "stored_crc": f"0x{stored_crc:08x}",
            "calculated_crc": f"0x{calc_crc:08x}",
            "crc_ok": crc_ok,
        }
        chunks.append(chunk_info)

        if chunk_type == IDAT:
            idat_parts.append(chunk_data)

        offset = crc_end
        if chunk_type == IEND:
            break

    if not idat_parts:
        raise ExtractionError("chunk stream did not contain IDAT data")

    return b"".join(idat_parts), chunks


def xor_dwords(data: bytes, key: int) -> bytes:
    out = bytearray(data)
    aligned_len = len(out) - (len(out) % 4)
    for off in range(0, aligned_len, 4):
        value = u32le(out, off) ^ key
        struct.pack_into("<I", out, off, value)
    return bytes(out)


def lznt1_decompress(data: bytes, expected_size: int | None = None) -> bytes:
    """
    Pure-Python LZNT1 decompressor.

    This implements the chunk format used by COMPRESSION_FORMAT_LZNT1:
    each chunk has a 2-byte little-endian header, followed by either raw bytes
    or tag-controlled LZ-style phrase/literal tokens.
    """
    out = bytearray()
    pos = 0

    while pos < len(data):
        if pos + 2 > len(data):
            break

        header = u16le(data, pos)
        pos += 2

        if header == 0:
            break

        chunk_size = (header & 0x0FFF) + 1
        compressed = bool(header & 0x8000)
        chunk = data[pos : pos + chunk_size]
        pos += chunk_size

        if len(chunk) != chunk_size:
            raise ExtractionError("truncated LZNT1 chunk")

        if not compressed:
            out.extend(chunk)
            continue

        chunk_out = bytearray()
        chunk_pos = 0

        while chunk_pos < len(chunk):
            tag = chunk[chunk_pos]
            chunk_pos += 1

            for bit in range(8):
                if chunk_pos >= len(chunk):
                    break

                if not (tag & (1 << bit)):
                    chunk_out.append(chunk[chunk_pos])
                    chunk_pos += 1
                    continue

                if chunk_pos + 2 > len(chunk):
                    raise ExtractionError("truncated LZNT1 phrase token")

                token = u16le(chunk, chunk_pos)
                chunk_pos += 2

                displacement_bits = 0
                while (1 << displacement_bits) < len(chunk_out):
                    displacement_bits += 1
                displacement_bits = max(displacement_bits, 4)

                length_bits = 16 - displacement_bits
                length_mask = (1 << length_bits) - 1
                length = (token & length_mask) + 3
                displacement = (token >> length_bits) + 1

                if displacement > len(chunk_out):
                    raise ExtractionError("invalid LZNT1 back-reference")

                for _ in range(length):
                    chunk_out.append(chunk_out[-displacement])

        out.extend(chunk_out)

    result = bytes(out)
    if expected_size is not None and len(result) != expected_size:
        raise ExtractionError(
            f"LZNT1 output size mismatch: got 0x{len(result):x}, expected 0x{expected_size:x}"
        )
    return result


def decode_idat_stream(idat_data: bytes) -> tuple[bytes, bytes, dict[str, object]]:
    if len(idat_data) < 0x10:
        raise ExtractionError("IDAT stream is too small to contain the loader header")

    marker = u32le(idat_data, 0x00)
    xor_key = u32le(idat_data, 0x04)
    compressed_size = u32le(idat_data, 0x08)
    decompressed_size = u32le(idat_data, 0x0C)

    body_start = 0x10
    body_end = body_start + compressed_size
    if body_end > len(idat_data):
        raise ExtractionError("declared compressed body extends past concatenated IDAT data")

    decoded_body = xor_dwords(idat_data[body_start:body_end], xor_key)
    decoded_stream = idat_data[:body_start] + decoded_body
    decompressed = lznt1_decompress(decoded_body, decompressed_size)

    return decoded_stream, decompressed, {
        "marker": f"0x{marker:08x}",
        "xor_key": f"0x{xor_key:08x}",
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
    }


def read_resource_name(entry: bytes) -> str:
    raw = entry[:0x82].split(b"\x00", 1)[0]
    return raw.decode("latin-1", errors="replace")


def validate_resource_table(data: bytes, base: int) -> tuple[bool, int]:
    count_off = base + RESOURCE_COUNT_DELTA
    table_off = base + RESOURCE_TABLE_DELTA

    if count_off + 4 > len(data) or table_off >= len(data):
        return False, 0

    count = u32le(data, count_off)
    if count == 0 or count > 256:
        return False, count

    if table_off + count * RESOURCE_ENTRY_SIZE > len(data):
        return False, count

    names: list[str] = []
    for idx in range(count):
        entry_off = table_off + idx * RESOURCE_ENTRY_SIZE
        entry = data[entry_off : entry_off + RESOURCE_ENTRY_SIZE]
        name = read_resource_name(entry)
        rel = u32le(entry, 0x82)
        size = u32le(entry, 0x86)
        abs_off = base + RESOURCE_COUNT_DELTA + rel

        if not name or abs_off + size > len(data):
            return False, count
        names.append(name)

    required = {"X64L", "CUSTOMINJECT", "BDATA"}
    return required.issubset(set(names)), count


def find_bundle_base(data: bytes) -> int:
    """
    Locate the bundle base by anchoring on the X64L resource entry.

    The resource lookup code uses:
      count       = *(base + 0xee4)
      entry_table = base + 0x10de
      entry_size  = 0x8a

    The script searches for X64L entries and tests candidate base addresses
    against those invariants.
    """
    search_from = 0
    while True:
        hit = data.find(b"X64L\x00", search_from)
        if hit < 0:
            raise ExtractionError("could not locate X64L resource entry")

        for index in range(256):
            base = hit - RESOURCE_TABLE_DELTA - index * RESOURCE_ENTRY_SIZE
            if base < 0:
                continue
            valid, _count = validate_resource_table(data, base)
            if valid:
                return base

        search_from = hit + 1


def parse_resources(data: bytes, base: int) -> list[dict[str, object]]:
    valid, count = validate_resource_table(data, base)
    if not valid:
        raise ExtractionError(f"invalid resource table at base 0x{base:x}")

    resource_base = base + RESOURCE_COUNT_DELTA
    table = base + RESOURCE_TABLE_DELTA
    resources: list[dict[str, object]] = []

    for idx in range(count):
        entry_off = table + idx * RESOURCE_ENTRY_SIZE
        entry = data[entry_off : entry_off + RESOURCE_ENTRY_SIZE]
        name = read_resource_name(entry)
        rel = u32le(entry, 0x82)
        size = u32le(entry, 0x86)
        abs_off = resource_base + rel
        blob = data[abs_off : abs_off + size]

        resources.append(
            {
                "index": idx,
                "name": name,
                "entry_offset": entry_off,
                "relative_offset": rel,
                "absolute_offset": abs_off,
                "size": size,
                "sha256": sha256(blob),
                "data": blob,
            }
        )

    return resources


def decrypt_x64l_payload_blob(bundle: bytes, base: int) -> tuple[bytes, bytes, dict[str, object]]:
    key_dword_count = u32le(bundle, base + 0xCA4)
    blob_size = u32le(bundle, base + 0xCA8)
    blob_rel_offset = u32le(bundle, base + 0xEEC)
    blob_offset = base + RESOURCE_COUNT_DELTA + blob_rel_offset

    if key_dword_count == 0 or key_dword_count > 0x1000:
        raise ExtractionError(f"invalid X64L key DWORD count: 0x{key_dword_count:x}")
    if blob_size <= key_dword_count * 4:
        raise ExtractionError("invalid X64L blob size")
    if blob_offset + blob_size > len(bundle):
        raise ExtractionError("X64L encrypted blob extends past bundle end")

    blob = bundle[blob_offset : blob_offset + blob_size]
    key_size = key_dword_count * 4
    key = blob[:key_size]
    ciphertext = blob[key_size:]
    plaintext = bytearray(ciphertext)

    aligned_len = len(plaintext) - (len(plaintext) % 4)
    for off in range(0, aligned_len, 4):
        key_index = (off // 4) % key_dword_count
        key_dword = u32le(key, key_index * 4)
        value = u32le(plaintext, off) ^ key_dword
        struct.pack_into("<I", plaintext, off, value)

    payload = bytes(plaintext)
    if not is_pe(payload):
        raise ExtractionError("decoded X64L payload is not a valid PE")

    return blob, payload, {
        "key_dword_count": key_dword_count,
        "key_size": key_size,
        "blob_relative_offset": blob_rel_offset,
        "blob_absolute_offset": blob_offset,
        "blob_size": blob_size,
        "payload_size": len(payload),
    }


def is_pe(data: bytes) -> bool:
    if len(data) < 0x100 or data[:2] != b"MZ":
        return False
    e_lfanew = u32le(data, 0x3C)
    return e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def pe_summary(data: bytes) -> dict[str, object]:
    if not is_pe(data):
        return {"valid_pe": False}

    e_lfanew = u32le(data, 0x3C)
    machine = u16le(data, e_lfanew + 4)
    sections = u16le(data, e_lfanew + 6)
    optional_header_size = u16le(data, e_lfanew + 20)
    optional = e_lfanew + 24
    magic = u16le(data, optional)
    is_pe32_plus = magic == 0x20B

    entry_rva = u32le(data, optional + 0x10)
    image_base = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, optional + 0x18)[0]
    size_of_image = u32le(data, optional + 0x38)
    size_of_headers = u32le(data, optional + 0x3C)
    section_table = optional + optional_header_size

    section_rows = []
    for idx in range(sections):
        off = section_table + idx * 40
        name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = u32le(data, off + 8)
        virtual_address = u32le(data, off + 12)
        raw_size = u32le(data, off + 16)
        raw_pointer = u32le(data, off + 20)
        section_rows.append(
            {
                "name": name,
                "virtual_address": f"0x{virtual_address:x}",
                "virtual_size": f"0x{virtual_size:x}",
                "raw_pointer": f"0x{raw_pointer:x}",
                "raw_size": f"0x{raw_size:x}",
            }
        )

    return {
        "valid_pe": True,
        "machine": f"0x{machine:04x}",
        "format": "PE32+" if is_pe32_plus else "PE32",
        "entry_rva": f"0x{entry_rva:x}",
        "image_base": f"0x{image_base:x}",
        "size_of_image": f"0x{size_of_image:x}",
        "size_of_headers": f"0x{size_of_headers:x}",
        "sections": section_rows,
    }


def extract(xml_path: Path, out_dir: Path, chunk_offset: int | None, bundle_base: int | None) -> dict[str, object]:
    source = xml_path.read_bytes()
    out_dir.mkdir(parents=True, exist_ok=True)

    start = chunk_offset if chunk_offset is not None else find_chunk_stream(source)
    idat_data, chunks = parse_png_like_chunks(source, start)
    decoded_stream, bundle, idat_header = decode_idat_stream(idat_data)

    summary: dict[str, object] = {
        "source": {
            "path": str(xml_path),
            "size": len(source),
            "sha256": sha256(source),
        },
        "chunk_stream": {
            "start_offset": f"0x{start:x}",
            "chunks": len(chunks),
            "idat_chunks": sum(1 for c in chunks if c["type"] == "IDAT"),
            "all_crc_ok": all(bool(c["crc_ok"]) for c in chunks),
        },
        "idat_header": idat_header,
        "outputs": {},
    }

    outputs: dict[str, object] = {}
    outputs["idat_concat"] = write_bytes(out_dir / "scenesync45_idat_concat.bin", idat_data)
    outputs["stage_xor_decoded"] = write_bytes(out_dir / "scenesync45_stage_xor_decoded.bin", decoded_stream)
    outputs["lznt1_decompressed_bundle"] = write_bytes(out_dir / "scenesync45_lznt1_decompressed.bin", bundle)

    base = bundle_base if bundle_base is not None else find_bundle_base(bundle)
    resources = parse_resources(bundle, base)

    resource_dir = out_dir / "resource_records"
    resource_summaries = []
    for resource in resources:
        name = resource["name"] or f"resource_{resource['index']:02d}"
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(name))
        path = resource_dir / f"{safe_name}.bin"
        write_bytes(path, resource["data"])  # type: ignore[arg-type]
        resource_summaries.append(
            {
                key: value
                for key, value in resource.items()
                if key != "data"
            }
            | {"path": str(path)}
        )

    encrypted_blob, payload, payload_meta = decrypt_x64l_payload_blob(bundle, base)
    outputs["x64l_encrypted_payload_blob"] = write_bytes(
        out_dir / "x64l_config_blob_candidate.bin", encrypted_blob
    )
    outputs["vidar_payload"] = write_bytes(out_dir / "vidar_payload.bin", payload)

    summary["bundle"] = {
        "base": f"0x{base:x}",
        "resource_base": f"0x{base + RESOURCE_COUNT_DELTA:x}",
        "entry_table": f"0x{base + RESOURCE_TABLE_DELTA:x}",
        "entry_size": f"0x{RESOURCE_ENTRY_SIZE:x}",
        "resource_count": len(resources),
        "resources": resource_summaries,
    }
    summary["x64l_payload"] = {
        **payload_meta,
        "blob_absolute_offset": f"0x{payload_meta['blob_absolute_offset']:x}",
        "blob_relative_offset": f"0x{payload_meta['blob_relative_offset']:x}",
        "blob_size": f"0x{payload_meta['blob_size']:x}",
        "key_size": f"0x{payload_meta['key_size']:x}",
        "payload_size": f"0x{payload_meta['payload_size']:x}",
        "payload_sha256": sha256(payload),
        "pe": pe_summary(payload),
    }
    summary["outputs"] = outputs

    summary_path = out_dir / "extraction_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary["summary_path"] = str(summary_path)

    return summary


def parse_int(value: str) -> int:
    return int(value, 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract bundled Rugmi/HijackLoader resources and the Vidar PE from scenesync45.xml"
    )
    parser.add_argument("xml", type=Path, help="Path to the fake XML container")
    parser.add_argument(
        "-o",
        "--out-dir",
        type=Path,
        default=Path("extracted_scenesync45"),
        help="Output directory (default: extracted_scenesync45)",
    )
    parser.add_argument(
        "--chunk-offset",
        type=parse_int,
        help="Override fake PNG chunk-stream offset, e.g. 0x404e",
    )
    parser.add_argument(
        "--bundle-base",
        type=parse_int,
        help="Override decompressed bundle base, e.g. 0x639c4",
    )
    args = parser.parse_args(argv)

    try:
        summary = extract(args.xml, args.out_dir, args.chunk_offset, args.bundle_base)
    except ExtractionError as exc:
        print(f"[!] extraction failed: {exc}", file=sys.stderr)
        return 1

    payload = summary["outputs"]["vidar_payload"]  # type: ignore[index]
    print("[+] extraction complete")
    print(f"[+] summary: {summary['summary_path']}")
    print(f"[+] Vidar payload: {payload['path']}")  # type: ignore[index]
    print(f"[+] Vidar SHA256:  {payload['sha256']}")  # type: ignore[index]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

