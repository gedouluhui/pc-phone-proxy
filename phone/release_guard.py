"""Shared fail-closed node checks. Never include node contents in diagnostics."""
import json
import struct
import zipfile
import zlib
from pathlib import Path

NODE_ASSET = "assets/nodes.json"
MAX_NODES_BYTES = 1024 * 1024


class ReleaseCheckError(ValueError):
    """An input or artifact could not be proven safe for publication."""


def parse_nodes(data, require_empty=True):
    if len(data) > MAX_NODES_BYTES:
        raise ReleaseCheckError("node resource too large (limit 1 MiB)")
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise ReleaseCheckError("node resource is not valid UTF-8") from None
    try:
        nodes = json.loads(text)
    except (ValueError, RecursionError):
        raise ReleaseCheckError("invalid JSON in node resource") from None
    if not isinstance(nodes, list):
        raise ReleaseCheckError("node resource must be a JSON array")
    if require_empty and nodes:
        raise ReleaseCheckError("non-empty node array; public input must be []")
    return nodes


def read_nodes(path, require_empty=True):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_NODES_BYTES + 1)
    except OSError:
        raise ReleaseCheckError("node input missing or unreadable") from None
    return parse_nodes(data, require_empty=require_empty)


def _read_node_entry(archive, entry):
    """Validate the raw member, not ZipExtFile's declared-size-truncated view.

    The build writes ordinary STORED/DEFLATED members with sizes in the local
    header. Encryption, data descriptors and ZIP64 node members fail closed.
    """
    if entry.file_size > MAX_NODES_BYTES:
        raise ReleaseCheckError("node resource too large (limit 1 MiB)")
    if (entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            or entry.flag_bits & ~0x0806):  # Only UTF-8 and DEFLATE option bits.
        raise zipfile.BadZipFile("unsupported node ZIP encoding")

    # Reuse ZipFile's handle so the local header and CEN come from the same file.
    stream = archive.fp
    stream.seek(entry.header_offset)
    header = stream.read(30)
    if len(header) != 30:
        raise zipfile.BadZipFile("truncated local header")
    (signature, version, flags, method, _, _, crc, compressed_size, size,
     name_length, extra_length) = struct.unpack("<4s5H3I2H", header)
    if (signature != b"PK\x03\x04" or version != entry.extract_version
            or flags != entry.flag_bits or method != entry.compress_type
            or (crc, compressed_size, size) != (entry.CRC, entry.compress_size, entry.file_size)
            or size == 0xffffffff or compressed_size == 0xffffffff
            or entry.orig_filename != NODE_ASSET
            or stream.read(name_length) != NODE_ASSET.encode("ascii")):
        raise zipfile.BadZipFile("inconsistent node ZIP headers")
    data_start = stream.tell() + extra_length
    boundary = min([archive.start_dir] + [item.header_offset for item in archive.infolist()
                                         if item.header_offset > entry.header_offset])
    if entry.header_offset < 0 or data_start + compressed_size > boundary:
        raise zipfile.BadZipFile("node ZIP data overlaps another entry or directory")
    stream.seek(data_start)

    if method == zipfile.ZIP_STORED:
        if compressed_size != size:
            raise zipfile.BadZipFile("inconsistent STORED size")
        data = stream.read(size)  # Already bounded by MAX_NODES_BYTES.
    else:
        inflater = zlib.decompressobj(-zlib.MAX_WBITS)
        data = bytearray()
        remaining = compressed_size
        while remaining:
            chunk = stream.read(min(remaining, 64 * 1024))
            if not chunk:
                raise zipfile.BadZipFile("truncated node ZIP data")
            remaining -= len(chunk)
            # A positive cumulative budget on EVERY call; never use flush(),
            # whose length argument is not a hard cap on decompressed output.
            data.extend(inflater.decompress(chunk, MAX_NODES_BYTES + 1 - len(data)))
            if len(data) > MAX_NODES_BYTES:
                raise ReleaseCheckError("node resource too large (limit 1 MiB)")
            if inflater.unconsumed_tail or inflater.unused_data or (inflater.eof and remaining):
                raise zipfile.BadZipFile("trailing node compressed data")
        if not inflater.eof:
            raise zipfile.BadZipFile("incomplete node DEFLATE stream")
    if len(data) != size or zlib.crc32(data) != crc:
        raise zipfile.BadZipFile("node ZIP size or CRC mismatch")
    return data


def nodes_in_apk(apk, require_empty=True):
    """Return a validated array (exactly [] for public APKs), or raise."""
    apk = Path(apk)
    if not apk.is_file():
        raise ReleaseCheckError("APK missing or not a regular file")
    try:
        with zipfile.ZipFile(apk) as archive:
            entries = [item for item in archive.infolist() if item.filename == NODE_ASSET]
            if not entries:
                raise ReleaseCheckError("missing assets/nodes.json")
            if len(entries) != 1:
                raise ReleaseCheckError("duplicate assets/nodes.json")
            data = _read_node_entry(archive, entries[0])
    except ReleaseCheckError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError,
            EOFError, ValueError, zlib.error):
        raise ReleaseCheckError("invalid APK ZIP or unreadable node resource") from None
    return parse_nodes(data, require_empty=require_empty)
