#!/usr/bin/env python3
"""Assemble the source-only Debug Channel package deterministically."""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import stat
import struct
from pathlib import Path

REPOSITORY_ID = "1306065111"
LUA_PATH = re.compile(r"^lua/(?:[a-z][a-z0-9_]*/)*[a-z][a-z0-9_]*\.lua$")
MODULE_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_manifest(path: Path) -> bytes:
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    manifest = json.loads(text, object_pairs_hook=strict_object)
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    if manifest.get("manifestVersion") != 1:
        raise ValueError("manifestVersion must be 1")
    if manifest.get("repositoryId") != REPOSITORY_ID:
        raise ValueError("repositoryId does not match the durable repository ID")
    if manifest.get("packageVersion") != "1.0.0":
        raise ValueError("packageVersion must be 1.0.0")
    if manifest.get("entryModule") != "plugin":
        raise ValueError("entryModule must be plugin")
    runtime = manifest.get("runtime")
    if runtime != {"luaVersion": "Lua 5.4", "apiVersion": "subspace-lua-v1"}:
        raise ValueError("runtime does not declare the exact v1 contract")
    # The archived bytes use one canonical JSON representation, independent of
    # whitespace in the checked-in source manifest.
    return json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def read_sources(root: Path) -> list[tuple[str, bytes]]:
    lua_root = root / "lua"
    if not lua_root.is_dir():
        raise ValueError("lua directory is missing")
    entries: list[tuple[str, bytes]] = []
    for path in sorted(lua_root.rglob("*.lua")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Lua source is not a regular file: {path}")
        name = path.relative_to(root).as_posix()
        if not LUA_PATH.fullmatch(name):
            raise ValueError(f"non-canonical Lua module path: {name}")
        module = name[4:-4].replace("/", ".")
        if not MODULE_NAME.fullmatch(module):
            raise ValueError(f"non-canonical Lua module name: {module}")
        data = path.read_bytes()
        text = data.decode("utf-8")
        if data.startswith(b"\x1bLua") or data.startswith(b"\xef\xbb\xbf"):
            raise ValueError(f"bytecode or BOM is forbidden: {name}")
        if "\r" in text or text != text.encode("utf-8").decode("utf-8"):
            raise ValueError(f"source is not canonical UTF-8/LF: {name}")
        import unicodedata
        if not unicodedata.is_normalized("NFC", text):
            raise ValueError(f"source is not NFC-normalized: {name}")
        entries.append((name, data))
    if not entries:
        raise ValueError("no Lua modules found")
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    return entries


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def make_zip(entries: list[tuple[str, bytes]]) -> bytes:
    # ZIP local/central records are emitted directly: no data descriptors,
    # extra fields, comments, compression, timestamps, or implementation drift.
    output = bytearray()
    central: list[tuple[bytes, int, int, int]] = []
    for name, data in entries:
        name_bytes = name.encode("utf-8")
        offset = len(output)
        checksum = crc32(data)
        size = len(data)
        output += struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, 0, 0, checksum, size, size, len(name_bytes), 0)
        output += name_bytes + data
        central.append((name_bytes, checksum, size, offset))
    central_offset = len(output)
    for name_bytes, checksum, size, offset in central:
        output += struct.pack(
            "<4s6H3I5H2I",
            b"PK\x01\x02", 0x0314, 20, 0, 0, 0, 0,
            checksum, size, size, len(name_bytes), 0, 0, 0, 0,
            0x81A40000, offset,
        )
        output += name_bytes
    central_size = len(output) - central_offset
    count = len(central)
    output += struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, count, count, central_size, central_offset, 0)
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="subspace-channel.zip")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = read_manifest(root / "manifest.json")
    source_entries = read_sources(root)
    entries = [("manifest.json", manifest), *source_entries]
    archive = make_zip(entries)
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(archive)
    os.chmod(output, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    digest = hashlib.sha256(archive).hexdigest()
    print(f"Archive: {output}")
    print("Entries:")
    for name, _ in entries:
        print(f"  {name}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
