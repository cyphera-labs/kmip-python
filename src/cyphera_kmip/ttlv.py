"""
TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
Implements the OASIS KMIP 1.4 binary encoding.

Each TTLV item:
  Tag:    3 bytes (identifies the field)
  Type:   1 byte  (data type)
  Length: 4 bytes  (value length in bytes)
  Value:  variable (padded to 8-byte alignment)
"""

import math
import struct


# KMIP data types
class Type:
    Structure = 0x01
    Integer = 0x02
    LongInteger = 0x03
    BigInteger = 0x04
    Enumeration = 0x05
    Boolean = 0x06
    TextString = 0x07
    ByteString = 0x08
    DateTime = 0x09
    Interval = 0x0A


def encode_ttlv(tag: int, type_: int, value: bytes) -> bytes:
    """
    Encode a TTLV item to bytes.

    Args:
        tag: 3-byte tag value (e.g., 0x420069)
        type_: 1-byte type value
        value: raw value bytes

    Returns:
        Encoded TTLV bytes.
    """
    value_len = len(value)
    padded = math.ceil(value_len / 8) * 8
    buf = bytearray(8 + padded)

    # Tag: 3 bytes big-endian
    buf[0] = (tag >> 16) & 0xFF
    buf[1] = (tag >> 8) & 0xFF
    buf[2] = tag & 0xFF

    # Type: 1 byte
    buf[3] = type_

    # Length: 4 bytes big-endian
    struct.pack_into(">I", buf, 4, value_len)

    # Value + padding (padding bytes remain zero)
    buf[8:8 + value_len] = value

    return bytes(buf)


def encode_structure(tag: int, children: list) -> bytes:
    """Encode a Structure (type 0x01) containing child TTLV items."""
    inner = b"".join(children)
    return encode_ttlv(tag, Type.Structure, inner)


def encode_integer(tag: int, value: int) -> bytes:
    """Encode a 32-bit integer."""
    return encode_ttlv(tag, Type.Integer, struct.pack(">i", value))


def encode_long_integer(tag: int, value: int) -> bytes:
    """Encode a 64-bit long integer."""
    return encode_ttlv(tag, Type.LongInteger, struct.pack(">q", value))


def encode_enum(tag: int, value: int) -> bytes:
    """Encode an enumeration (32-bit)."""
    return encode_ttlv(tag, Type.Enumeration, struct.pack(">I", value))


def encode_boolean(tag: int, value: bool) -> bytes:
    """Encode a boolean."""
    return encode_ttlv(tag, Type.Boolean, struct.pack(">q", 1 if value else 0))


def encode_text_string(tag: int, value: str) -> bytes:
    """Encode a text string (UTF-8)."""
    return encode_ttlv(tag, Type.TextString, value.encode("utf-8"))


def encode_byte_string(tag: int, value: bytes) -> bytes:
    """Encode a byte string (raw bytes)."""
    return encode_ttlv(tag, Type.ByteString, value)


def encode_date_time(tag: int, value: int) -> bytes:
    """Encode a DateTime (64-bit POSIX timestamp)."""
    return encode_ttlv(tag, Type.DateTime, struct.pack(">q", value))


def decode_ttlv(buf: bytes, offset: int = 0) -> dict:
    """
    Decode a TTLV buffer into a parsed tree.

    Args:
        buf: Raw TTLV bytes.
        offset: Starting offset in the buffer.

    Returns:
        Dict with keys: tag, type, value, length, total_length.
    """
    if len(buf) - offset < 8:
        raise ValueError("TTLV buffer too short for header")

    tag = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    type_ = buf[offset + 3]
    length = struct.unpack_from(">I", buf, offset + 4)[0]
    padded = math.ceil(length / 8) * 8
    total_length = 8 + padded

    value_start = offset + 8

    if type_ == Type.Structure:
        children = []
        pos = value_start
        end = value_start + length
        while pos < end:
            child = decode_ttlv(buf, pos)
            children.append(child)
            pos += child["total_length"]
        value = children
    elif type_ == Type.Integer:
        value = struct.unpack_from(">i", buf, value_start)[0]
    elif type_ == Type.LongInteger:
        value = struct.unpack_from(">q", buf, value_start)[0]
    elif type_ == Type.Enumeration:
        value = struct.unpack_from(">I", buf, value_start)[0]
    elif type_ == Type.Boolean:
        value = struct.unpack_from(">q", buf, value_start)[0] != 0
    elif type_ == Type.TextString:
        value = buf[value_start:value_start + length].decode("utf-8")
    elif type_ == Type.ByteString:
        value = bytes(buf[value_start:value_start + length])
    elif type_ == Type.DateTime:
        value = struct.unpack_from(">q", buf, value_start)[0]
    elif type_ == Type.BigInteger:
        value = bytes(buf[value_start:value_start + length])
    elif type_ == Type.Interval:
        value = struct.unpack_from(">I", buf, value_start)[0]
    else:
        value = bytes(buf[value_start:value_start + length])

    return {
        "tag": tag,
        "type": type_,
        "value": value,
        "length": length,
        "total_length": total_length,
    }


def find_child(decoded: dict, tag: int):
    """Find a child item by tag within a decoded structure."""
    if not isinstance(decoded.get("value"), list):
        return None
    for child in decoded["value"]:
        if child["tag"] == tag:
            return child
    return None


def find_children(decoded: dict, tag: int) -> list:
    """Find all children by tag within a decoded structure."""
    if not isinstance(decoded.get("value"), list):
        return []
    return [c for c in decoded["value"] if c["tag"] == tag]
