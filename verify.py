#!/usr/bin/env python3
"""Verify the exact source-only Debug Channel package format."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import unicodedata
import zlib
from pathlib import Path

REPOSITORY_ID = "1306065111"
LUA_PATH = re.compile(r"^lua/(?:[a-z][a-z0-9_]*/)*[a-z][a-z0-9_]*\.lua$")
MODULE_NAME = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
CAPABILITIES = ["audio.transcription", "audio.synthesis", "audio.playback"]
MODES = ["ECHO", "DELAYED_ECHO", "STT", "TTS", "STT_TTS"]
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ENTRY_COUNT = 100
MAX_PATH_BYTES = 256
MAX_MANIFEST_BYTES = 64 * 1024
MAX_MODULE_BYTES = 256 * 1024
MAX_TOTAL_SOURCE_BYTES = 1024 * 1024
NATIVE_SIGNATURES = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\x00asm")


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def expect_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} has unexpected or missing keys")
    return value


def validate_manifest(data: bytes, modules: dict[str, bytes]) -> None:
    try:
        text = data.decode("utf-8")
        manifest = json.loads(text, object_pairs_hook=strict_object, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except Exception as exc:
        raise ValueError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    root = expect_keys(manifest, {"manifestVersion", "repositoryId", "packageVersion", "entryModule", "presentation", "runtime", "configuration", "resources", "capabilities"}, "manifest")
    if root["manifestVersion"] != 1 or root["repositoryId"] != REPOSITORY_ID or root["packageVersion"] != "1.2.0":
        raise ValueError("manifest identity/version is not exact")
    if root["entryModule"] != "plugin" or not isinstance(root["entryModule"], str) or not MODULE_NAME.fullmatch(root["entryModule"]):
        raise ValueError("entryModule is invalid")
    presentation = expect_keys(root["presentation"], {"label", "summary"}, "presentation")
    if not all(isinstance(presentation[key], str) and presentation[key].strip() for key in ("label", "summary")):
        raise ValueError("presentation values must be nonblank strings")
    runtime = expect_keys(root["runtime"], {"luaVersion", "apiVersion"}, "runtime")
    if runtime != {"luaVersion": "Lua 5.4", "apiVersion": "subspace-lua-v1"}:
        raise ValueError("runtime contract is not exact")
    configuration = expect_keys(root["configuration"], {"schemaVersion", "data", "ui"}, "configuration")
    if configuration["schemaVersion"] != 1:
        raise ValueError("configuration schemaVersion must be 1")
    data_schema = expect_keys(configuration["data"], {"additionalProperties", "fields"}, "configuration.data")
    if data_schema["additionalProperties"] is not False or not isinstance(data_schema["fields"], list) or len(data_schema["fields"]) != 1:
        raise ValueError("Debug data schema is not exact")
    field = expect_keys(data_schema["fields"][0], {"id", "type", "default", "allowedValues"}, "mode field")
    if field != {"id": "mode", "type": "string", "default": "ECHO", "allowedValues": MODES}:
        raise ValueError("mode declaration is not exact")
    ui = expect_keys(configuration["ui"], {"fields"}, "configuration.ui")
    if not isinstance(ui["fields"], list) or len(ui["fields"]) != 1:
        raise ValueError("Debug UI declaration is not exact")
    control = expect_keys(ui["fields"][0], {"field", "control", "label", "choices"}, "mode UI field")
    expected_choices = [{"value": value, "label": value} for value in MODES]
    if control != {"field": "mode", "control": "choice", "label": "Mode", "choices": expected_choices}:
        raise ValueError("mode UI choice declaration is not exact")
    resources = expect_keys(root["resources"], {"mounts"}, "resources")
    if not isinstance(resources["mounts"], list) or resources["mounts"] != []:
        raise ValueError("Debug resources must declare an empty mounts array")
    if root["capabilities"] != CAPABILITIES:
        raise ValueError("capability declaration is not exact")
    if "plugin" not in modules:
        raise ValueError("entry module is missing")
    canonical = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if canonical != data:
        raise ValueError("manifest bytes are not canonical JSON")


def parse_archive(raw: bytes) -> tuple[list[tuple[str, bytes]], int]:
    if len(raw) > MAX_ARTIFACT_BYTES or len(raw) < 22:
        raise ValueError("archive size is outside bounds")
    if raw[-22:-18] != b"PK\x05\x06" or raw[-2:] != b"\x00\x00":
        raise ValueError("archive must have a zero-comment EOCD")
    _, disk, central_disk, count_disk, count, central_size, central_offset, comment = struct.unpack("<4s4H2IH", raw[-22:])
    if disk or central_disk or count_disk != count or comment or count == 0 or count > MAX_ENTRY_COUNT:
        raise ValueError("invalid EOCD fields")
    if central_offset + central_size != len(raw) - 22:
        raise ValueError("central directory bounds are invalid")
    cursor = central_offset
    central: list[dict[str, object]] = []
    seen: set[str] = set()
    for _ in range(count):
        if cursor + 46 > central_offset + central_size or raw[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("invalid central directory record")
        fields = struct.unpack("<4s6H3I5H2I", raw[cursor:cursor + 46])
        (_, made, needed, flags, method, mtime, mdate, crc, comp_size, size, name_len, extra_len, comment_len, disk_start, internal, external, local_offset) = fields
        if (made, needed, flags, method, mtime, mdate, extra_len, comment_len, disk_start, internal, external) != (0x0314, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0x81A40000):
            raise ValueError("central record is not canonical stored 0644")
        end = cursor + 46 + name_len + extra_len + comment_len
        if end > central_offset + central_size:
            raise ValueError("central record exceeds directory")
        try:
            name = raw[cursor + 46:cursor + 46 + name_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("entry name is not UTF-8") from exc
        if len(name.encode("utf-8")) > MAX_PATH_BYTES or name in seen or not unicodedata.is_normalized("NFC", name) or "\\" in name or "//" in name or ".." in name or name.startswith("/") or extra_len or comment_len:
            raise ValueError(f"invalid or duplicate entry name: {name!r}")
        if name != "manifest.json" and not LUA_PATH.fullmatch(name):
            raise ValueError(f"unexpected archive entry: {name}")
        seen.add(name)
        central.append({"name": name, "crc": crc, "comp": comp_size, "size": size, "offset": local_offset})
        cursor = end
    if cursor != central_offset + central_size:
        raise ValueError("central directory size mismatch")
    names = [entry["name"] for entry in central]
    if not names or names[0] != "manifest.json" or names[1:] != sorted(names[1:], key=lambda name: name.encode("utf-8")):
        raise ValueError("entries are not in canonical order")
    ranges: list[tuple[int, int]] = []
    result: list[tuple[str, bytes]] = []
    for entry in central:
        offset = int(entry["offset"])
        if offset + 30 > central_offset or raw[offset:offset + 4] != b"PK\x03\x04":
            raise ValueError("invalid local header")
        _, needed, flags, method, mtime, mdate, crc, comp_size, size, name_len, extra_len = struct.unpack("<4s5H3I2H", raw[offset:offset + 30])
        name = str(entry["name"])
        name_bytes = name.encode("utf-8")
        if (needed, flags, method, mtime, mdate, crc, comp_size, size, name_len, extra_len) != (20, 0, 0, 0, 0, int(entry["crc"]), int(entry["comp"]), int(entry["size"]), len(name_bytes), 0):
            raise ValueError("local and central records differ")
        if raw[offset + 30:offset + 30 + name_len] != name_bytes:
            raise ValueError("local entry name differs")
        end = offset + 30 + name_len + extra_len + comp_size
        if end > central_offset:
            raise ValueError("local entry exceeds archive")
        ranges.append((offset, end))
        content = raw[offset + 30 + name_len + extra_len:end]
        if len(content) != size or (zlib.crc32(content) & 0xFFFFFFFF) != crc:
            raise ValueError("entry checksum or size mismatch")
        result.append((name, content))
    ranges.sort()
    if ranges[0][0] != 0 or any(ranges[index][1] != ranges[index + 1][0] for index in range(len(ranges) - 1)) or ranges[-1][1] != central_offset:
        raise ValueError("archive contains gaps, overlap, or payload bytes")
    return result, central_offset


def main() -> None:
    archive = Path(sys.argv[1] if len(sys.argv) > 1 else "subspace-channel.zip")
    raw = archive.read_bytes()
    entries, _ = parse_archive(raw)
    manifest = next((data for name, data in entries if name == "manifest.json"), None)
    if manifest is None:
        raise ValueError("manifest.json is missing")
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds size bound")
    total_source_bytes = 0
    modules: dict[str, bytes] = {}
    for name, data in entries:
        if name == "manifest.json":
            continue
        if data.startswith(b"\x1bLua") or data.startswith(b"\xef\xbb\xbf") or data.startswith(NATIVE_SIGNATURES):
            raise ValueError(f"bytecode, native, or signature payload is forbidden: {name}")
        if len(data) > MAX_MODULE_BYTES:
            raise ValueError(f"module exceeds size bound: {name}")
        total_source_bytes += len(data)
        text = data.decode("utf-8")
        if "\r" in text or not unicodedata.is_normalized("NFC", text):
            raise ValueError(f"non-canonical Lua source: {name}")
        modules[name[4:-4].replace("/", ".")] = data
    validate_manifest(manifest, modules)
    digest = hashlib.sha256(raw).hexdigest()
    if total_source_bytes > MAX_TOTAL_SOURCE_BYTES:
        raise ValueError("total source exceeds size bound")
    print(f"Verified: {archive}")
    print("Entries:")
    for name, _ in entries:
        print(f"  {name}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Verification FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
