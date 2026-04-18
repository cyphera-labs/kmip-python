"""TTLV codec round-trip tests."""

import pytest
from cyphera_kmip.ttlv import (
    Type,
    encode_integer,
    encode_enum,
    encode_text_string,
    encode_byte_string,
    encode_boolean,
    encode_structure,
    decode_ttlv,
    find_child,
)


class TestTtlvCodec:
    def test_encode_decode_integer(self):
        encoded = encode_integer(0x42006A, 1)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x42006A
        assert decoded["type"] == Type.Integer
        assert decoded["value"] == 1

    def test_encode_decode_enumeration(self):
        encoded = encode_enum(0x42005C, 0x0000000A)
        decoded = decode_ttlv(encoded)
        assert decoded["tag"] == 0x42005C
        assert decoded["type"] == Type.Enumeration
        assert decoded["value"] == 0x0000000A

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

    def test_encode_decode_boolean(self):
        encoded = encode_boolean(0x420008, True)
        decoded = decode_ttlv(encoded)
        assert decoded["type"] == Type.Boolean
        assert decoded["value"] is True

    def test_encode_decode_structure(self):
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

    def test_find_child(self):
        encoded = encode_structure(0x420069, [
            encode_integer(0x42006A, 1),
            encode_integer(0x42006B, 4),
        ])
        decoded = decode_ttlv(encoded)
        child = find_child(decoded, 0x42006B)
        assert child is not None
        assert child["value"] == 4

    def test_text_string_padding(self):
        # "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
        encoded = encode_text_string(0x420055, "hello")
        assert len(encoded) == 16  # 8 header + 8 padded value

    def test_empty_text_string(self):
        encoded = encode_text_string(0x420055, "")
        decoded = decode_ttlv(encoded)
        assert decoded["value"] == ""

    def test_nested_structures(self):
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
