"""TTLV codec tests — comprehensive suite ported from kmip-node."""

import struct

import pytest
from cyphera_kmip.ttlv import (
    Type,
    encode_ttlv,
    encode_integer,
    encode_long_integer,
    encode_enum,
    encode_text_string,
    encode_byte_string,
    encode_boolean,
    encode_date_time,
    encode_structure,
    decode_ttlv,
    find_child,
    find_children,
)


# ---------------------------------------------------------------------------
# Primitive encode / decode round-trips
# ---------------------------------------------------------------------------


class TestPrimitives:
    def test_encode_decode_integer(self):
        encoded = encode_integer(0x42006A, 1)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x42006A
        assert decoded["type"] == Type.Integer
        assert decoded["value"] == 1

    def test_negative_integer(self):
        encoded = encode_integer(0x42006A, -42)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == -42

    def test_max_32bit_integer(self):
        encoded = encode_integer(0x42006A, 0x7FFFFFFF)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == 0x7FFFFFFF

    def test_min_32bit_integer(self):
        encoded = encode_integer(0x42006A, -0x80000000)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == -0x80000000

    def test_zero_integer(self):
        encoded = encode_integer(0x42006A, 0)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == 0

    def test_encode_decode_enumeration(self):
        encoded = encode_enum(0x42005C, 0x0000000A)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x42005C
        assert decoded["type"] == Type.Enumeration
        assert decoded["value"] == 0x0000000A

    def test_encode_decode_long_integer(self):
        encoded = encode_long_integer(0x42006A, 1234567890123)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x42006A
        assert decoded["type"] == Type.LongInteger
        assert decoded["value"] == 1234567890123

    def test_negative_long_integer(self):
        encoded = encode_long_integer(0x42006A, -9999999999)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == -9999999999

    def test_encode_decode_text_string(self):
        encoded = encode_text_string(0x420055, "my-key")
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x420055
        assert decoded["type"] == Type.TextString
        assert decoded["value"] == "my-key"

    def test_encode_decode_byte_string(self):
        key = bytes.fromhex("aabbccdd")
        encoded = encode_byte_string(0x420043, key)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x420043
        assert decoded["type"] == Type.ByteString
        assert decoded["value"] == key

    def test_encode_decode_boolean_true(self):
        encoded = encode_boolean(0x420008, True)
        decoded = decode_ttlv(encoded)
        assert decoded["type"] == Type.Boolean
        assert decoded["value"] is True

    def test_encode_decode_boolean_false(self):
        encoded = encode_boolean(0x420008, False)
        decoded = decode_ttlv(encoded)
        assert decoded["type"] == Type.Boolean
        assert decoded["value"] is False

    def test_encode_decode_datetime(self):
        # 2026-04-18T12:00:00Z as POSIX timestamp
        ts = 1776600000
        encoded = encode_date_time(0x420008, ts)
        decoded = decode_ttlv(encoded)
        assert decoded["type"] == Type.DateTime
        assert decoded["value"] == ts

    def test_epoch_zero_datetime(self):
        encoded = encode_date_time(0x420008, 0)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == 0


# ---------------------------------------------------------------------------
# Padding and alignment
# ---------------------------------------------------------------------------


class TestPadding:
    def test_integer_occupies_16_bytes(self):
        encoded = encode_integer(0x42006A, 1)
        # 8 header + 8 padded value (4 value + 4 padding) = 16
        assert len(encoded) == 16
        assert struct.unpack_from(">I", encoded, 4)[0] == 4

    def test_enum_occupies_16_bytes(self):
        encoded = encode_enum(0x42005C, 1)
        assert len(encoded) == 16
        assert struct.unpack_from(">I", encoded, 4)[0] == 4

    def test_boolean_occupies_16_bytes(self):
        encoded = encode_boolean(0x420008, True)
        assert len(encoded) == 16
        assert struct.unpack_from(">I", encoded, 4)[0] == 8

    def test_long_integer_occupies_16_bytes(self):
        encoded = encode_long_integer(0x42006A, 42)
        assert len(encoded) == 16
        assert struct.unpack_from(">I", encoded, 4)[0] == 8

    def test_text_string_pads_to_8_byte_alignment(self):
        # "hello" = 5 bytes -> padded to 8
        encoded = encode_text_string(0x420055, "hello")
        assert len(encoded) == 16  # 8 header + 8 padded

    def test_text_string_exactly_8_bytes_no_padding(self):
        encoded = encode_text_string(0x420055, "12345678")
        assert len(encoded) == 16  # 8 header + 8 value

    def test_text_string_9_bytes_pads_to_16(self):
        encoded = encode_text_string(0x420055, "123456789")
        assert len(encoded) == 24  # 8 header + 16 padded

    def test_empty_text_string(self):
        encoded = encode_text_string(0x420055, "")
        assert len(encoded) == 8  # header only
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == ""

    def test_byte_string_exact_8_byte_alignment(self):
        data = bytes(16)
        encoded = encode_byte_string(0x420043, data)
        assert len(encoded) == 24  # 8 header + 16 value

    def test_byte_string_1_extra_byte_pads(self):
        data = bytes(17)
        encoded = encode_byte_string(0x420043, data)
        assert len(encoded) == 32  # 8 header + 24 padded

    def test_empty_byte_string(self):
        encoded = encode_byte_string(0x420043, b"")
        assert len(encoded) == 8
        decoded = decode_ttlv(encoded)
        assert len(decoded["value"]) == 0

    def test_32_byte_key_material_roundtrip(self):
        key = bytes.fromhex(
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )
        encoded = encode_byte_string(0x420043, key)
        assert len(encoded) == 40  # 8 header + 32 value (exact alignment)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == key


# ---------------------------------------------------------------------------
# Structures and tree navigation
# ---------------------------------------------------------------------------


class TestStructures:
    def test_structure_with_children(self):
        encoded = encode_structure(0x420069, [
            encode_integer(0x42006A, 1),
            encode_integer(0x42006B, 4),
        ])
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x420069
        assert decoded["type"] == Type.Structure
        assert len(decoded["value"]) == 2
        assert decoded["value"][0]["value"] == 1
        assert decoded["value"][1]["value"] == 4

    def test_empty_structure(self):
        encoded = encode_structure(0x420069, [])
        decoded = decode_ttlv(encoded)
        assert decoded["type"] == Type.Structure
        assert len(decoded["value"]) == 0

    def test_structure_with_mixed_types(self):
        encoded = encode_structure(0x420069, [
            encode_integer(0x42006A, 42),
            encode_text_string(0x420055, "hello"),
            encode_boolean(0x420008, True),
            encode_byte_string(0x420043, bytes.fromhex("cafe")),
            encode_enum(0x42005C, 0x0A),
        ])
        decoded = decode_ttlv(encoded)
        assert len(decoded["value"]) == 5
        assert decoded["value"][0]["value"] == 42
        assert decoded["value"][1]["value"] == "hello"
        assert decoded["value"][2]["value"] is True
        assert decoded["value"][3]["value"] == bytes.fromhex("cafe")
        assert decoded["value"][4]["value"] == 0x0A

    def test_find_child_locates_by_tag(self):
        encoded = encode_structure(0x420069, [
            encode_integer(0x42006A, 1),
            encode_integer(0x42006B, 4),
        ])
        decoded = decode_ttlv(encoded)
        child = find_child(decoded, 0x42006B)
        assert child is not None
        assert child["value"] == 4

    def test_find_child_returns_none_for_missing(self):
        encoded = encode_structure(0x420069, [
            encode_integer(0x42006A, 1),
        ])
        decoded = decode_ttlv(encoded)
        assert find_child(decoded, 0x42FFFF) is None

    def test_find_child_returns_none_for_non_structure(self):
        encoded = encode_integer(0x42006A, 1)
        decoded = decode_ttlv(encoded)
        assert find_child(decoded, 0x42006A) is None

    def test_find_children_returns_all_matches(self):
        encoded = encode_structure(0x420069, [
            encode_text_string(0x420094, "id-1"),
            encode_text_string(0x420094, "id-2"),
            encode_text_string(0x420094, "id-3"),
            encode_integer(0x42006A, 99),
        ])
        decoded = decode_ttlv(encoded)
        ids = find_children(decoded, 0x420094)
        assert len(ids) == 3
        assert ids[0]["value"] == "id-1"
        assert ids[1]["value"] == "id-2"
        assert ids[2]["value"] == "id-3"

    def test_find_children_returns_empty_for_non_structure(self):
        encoded = encode_integer(0x42006A, 1)
        decoded = decode_ttlv(encoded)
        assert find_children(decoded, 0x42006A) == []

    def test_deeply_nested_structures(self):
        encoded = encode_structure(0x420078, [
            encode_structure(0x420077, [
                encode_structure(0x420069, [
                    encode_integer(0x42006A, 1),
                    encode_integer(0x42006B, 4),
                ]),
                encode_integer(0x42000D, 1),
            ]),
        ])
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x420078
        header = find_child(decoded, 0x420077)
        assert header is not None
        version = find_child(header, 0x420069)
        assert version is not None
        major = find_child(version, 0x42006A)
        assert major["value"] == 1
        minor = find_child(version, 0x42006B)
        assert minor["value"] == 4

    def test_three_levels_deep(self):
        encoded = encode_structure(0x420001, [
            encode_structure(0x420002, [
                encode_structure(0x420003, [
                    encode_text_string(0x420055, "deep"),
                ]),
            ]),
        ])
        decoded = decode_ttlv(encoded)
        lvl1 = find_child(decoded, 0x420002)
        lvl2 = find_child(lvl1, 0x420003)
        leaf = find_child(lvl2, 0x420055)
        assert leaf["value"] == "deep"


# ---------------------------------------------------------------------------
# Wire format verification
# ---------------------------------------------------------------------------


class TestWireFormat:
    def test_tag_encoded_as_3_bytes_big_endian(self):
        encoded = encode_integer(0x420069, 0)
        assert encoded[0] == 0x42
        assert encoded[1] == 0x00
        assert encoded[2] == 0x69

    def test_type_byte_correct_for_each_type(self):
        assert encode_integer(0x420001, 0)[3] == Type.Integer
        assert encode_long_integer(0x420001, 0)[3] == Type.LongInteger
        assert encode_enum(0x420001, 0)[3] == Type.Enumeration
        assert encode_boolean(0x420001, True)[3] == Type.Boolean
        assert encode_text_string(0x420001, "x")[3] == Type.TextString
        assert encode_byte_string(0x420001, b"\x01")[3] == Type.ByteString
        assert encode_structure(0x420001, [])[3] == Type.Structure
        assert encode_date_time(0x420001, 0)[3] == Type.DateTime

    def test_length_field_4_bytes_big_endian(self):
        encoded = encode_text_string(0x420055, "AB")  # 2 bytes
        assert struct.unpack_from(">I", encoded, 4)[0] == 2

    def test_padding_bytes_are_zero(self):
        encoded = encode_text_string(0x420055, "AB")  # 2 bytes -> padded to 8
        # Bytes 10-15 should be zero padding
        for i in range(10, 16):
            assert encoded[i] == 0, f"padding byte at {i} should be 0"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_buffer_too_short_for_header(self):
        with pytest.raises(ValueError, match="too short"):
            decode_ttlv(bytes(4))

    def test_empty_buffer(self):
        with pytest.raises(ValueError, match="too short"):
            decode_ttlv(b"")


# ---------------------------------------------------------------------------
# Unicode and special strings
# ---------------------------------------------------------------------------


class TestUnicode:
    def test_utf8_multi_byte_characters(self):
        encoded = encode_text_string(0x420055, "caf\u00e9")
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == "caf\u00e9"

    def test_emoji(self):
        encoded = encode_text_string(0x420055, "key-\U0001f511")
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == "key-\U0001f511"

    def test_long_text_crossing_multiple_boundaries(self):
        long_str = "a]" * 100  # 200 bytes
        encoded = encode_text_string(0x420055, long_str)
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == long_str
