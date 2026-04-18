"""Operations request/response tests — ported from kmip-node."""

import pytest
from cyphera_kmip.operations import (
    build_locate_request,
    build_get_request,
    build_create_request,
    parse_response,
    parse_locate_payload,
    parse_get_payload,
    parse_create_payload,
    PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
)
from cyphera_kmip.ttlv import (
    Type,
    decode_ttlv,
    find_child,
    find_children,
    encode_structure,
    encode_enum,
    encode_integer,
    encode_text_string,
    encode_byte_string,
)
from cyphera_kmip.tags import (
    Tag,
    Operation,
    ObjectType,
    ResultStatus,
    Algorithm,
    KeyFormatType,
    UsageMask,
)


# ---------------------------------------------------------------------------
# Helper: build a mock KMIP response
# ---------------------------------------------------------------------------


def _build_mock_response(operation, status, payload_children=None, extra_batch_children=None):
    """Construct a synthetic ResponseMessage for testing parse_response."""
    batch_children = [
        encode_enum(Tag.Operation, operation),
        encode_enum(Tag.ResultStatus, status),
    ]
    if extra_batch_children:
        batch_children.extend(extra_batch_children)
    if payload_children:
        batch_children.append(
            encode_structure(Tag.ResponsePayload, payload_children)
        )
    return encode_structure(Tag.ResponseMessage, [
        encode_structure(Tag.ResponseHeader, [
            encode_structure(Tag.ProtocolVersion, [
                encode_integer(Tag.ProtocolVersionMajor, 1),
                encode_integer(Tag.ProtocolVersionMinor, 4),
            ]),
            encode_integer(Tag.BatchCount, 1),
        ]),
        encode_structure(Tag.BatchItem, batch_children),
    ])


# ---------------------------------------------------------------------------
# Request building
# ---------------------------------------------------------------------------


class TestRequestBuilding:
    def test_locate_produces_valid_ttlv(self):
        request = build_locate_request("test-key")
        decoded = decode_ttlv(request)
        assert decoded["tag"] == Tag.RequestMessage
        assert decoded["type"] == Type.Structure

    def test_locate_contains_protocol_version(self):
        decoded = decode_ttlv(build_locate_request("k"))
        header = find_child(decoded, Tag.RequestHeader)
        assert header is not None
        version = find_child(header, Tag.ProtocolVersion)
        assert version is not None
        major = find_child(version, Tag.ProtocolVersionMajor)
        minor = find_child(version, Tag.ProtocolVersionMinor)
        assert major["value"] == PROTOCOL_MAJOR
        assert minor["value"] == PROTOCOL_MINOR

    def test_locate_has_batch_count_1(self):
        decoded = decode_ttlv(build_locate_request("k"))
        header = find_child(decoded, Tag.RequestHeader)
        count = find_child(header, Tag.BatchCount)
        assert count["value"] == 1

    def test_locate_has_locate_operation(self):
        decoded = decode_ttlv(build_locate_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        op = find_child(batch, Tag.Operation)
        assert op["value"] == Operation.Locate

    def test_locate_contains_name_attribute(self):
        decoded = decode_ttlv(build_locate_request("my-key"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        attr = find_child(payload, Tag.Attribute)
        attr_name = find_child(attr, Tag.AttributeName)
        assert attr_name["value"] == "Name"
        attr_value = find_child(attr, Tag.AttributeValue)
        name_value = find_child(attr_value, Tag.NameValue)
        assert name_value["value"] == "my-key"

    def test_get_produces_valid_ttlv(self):
        request = build_get_request("unique-id-123")
        decoded = decode_ttlv(request)
        assert decoded["tag"] == Tag.RequestMessage

    def test_get_has_get_operation(self):
        decoded = decode_ttlv(build_get_request("uid"))
        batch = find_child(decoded, Tag.BatchItem)
        op = find_child(batch, Tag.Operation)
        assert op["value"] == Operation.Get

    def test_get_contains_unique_identifier(self):
        decoded = decode_ttlv(build_get_request("uid-456"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-456"

    def test_create_produces_valid_ttlv(self):
        request = build_create_request("new-key")
        decoded = decode_ttlv(request)
        assert decoded["tag"] == Tag.RequestMessage

    def test_create_has_create_operation(self):
        decoded = decode_ttlv(build_create_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        op = find_child(batch, Tag.Operation)
        assert op["value"] == Operation.Create

    def test_create_uses_symmetric_key_object_type(self):
        decoded = decode_ttlv(build_create_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        obj_type = find_child(payload, Tag.ObjectType)
        assert obj_type["value"] == ObjectType.SymmetricKey

    def test_create_defaults_to_aes(self):
        decoded = decode_ttlv(build_create_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        algo_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Algorithm"
        )
        algo_value = find_child(algo_attr, Tag.AttributeValue)
        assert algo_value["value"] == Algorithm.AES

    def test_create_defaults_to_256_bit_length(self):
        decoded = decode_ttlv(build_create_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        len_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Length"
        )
        len_value = find_child(len_attr, Tag.AttributeValue)
        assert len_value["value"] == 256

    def test_create_includes_encrypt_decrypt_usage_mask(self):
        decoded = decode_ttlv(build_create_request("k"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        usage_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Usage Mask"
        )
        usage_value = find_child(usage_attr, Tag.AttributeValue)
        assert usage_value["value"] == UsageMask.Encrypt | UsageMask.Decrypt

    def test_create_includes_key_name(self):
        decoded = decode_ttlv(build_create_request("prod-key"))
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        name_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Name"
        )
        name_struct = find_child(name_attr, Tag.AttributeValue)
        name_value = find_child(name_struct, Tag.NameValue)
        assert name_value["value"] == "prod-key"

    def test_create_accepts_custom_algorithm_and_length(self):
        decoded = decode_ttlv(
            build_create_request("k", algorithm=Algorithm.TripleDES, length=192)
        )
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)

        algo_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Algorithm"
        )
        assert find_child(algo_attr, Tag.AttributeValue)["value"] == Algorithm.TripleDES

        len_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Length"
        )
        assert find_child(len_attr, Tag.AttributeValue)["value"] == 192


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


class TestResponseParsing:
    def test_parse_response_extracts_operation_and_status(self):
        response = _build_mock_response(
            Operation.Locate, ResultStatus.Success,
            payload_children=[encode_text_string(Tag.UniqueIdentifier, "id-1")],
        )
        result = parse_response(response)
        assert result["operation"] == Operation.Locate
        assert result["result_status"] == ResultStatus.Success

    def test_parse_response_throws_on_failure(self):
        batch_extra = [encode_text_string(Tag.ResultMessage, "Item Not Found")]
        response = _build_mock_response(
            Operation.Get, ResultStatus.OperationFailed,
            extra_batch_children=batch_extra,
        )
        with pytest.raises(RuntimeError, match="Item Not Found"):
            parse_response(response)

    def test_parse_response_throws_on_wrong_tag(self):
        bad_msg = encode_structure(Tag.RequestMessage, [])
        with pytest.raises(ValueError, match="Expected ResponseMessage"):
            parse_response(bad_msg)

    def test_parse_locate_payload_extracts_ids(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-1"),
            encode_text_string(Tag.UniqueIdentifier, "uid-2"),
            encode_text_string(Tag.UniqueIdentifier, "uid-3"),
        ]))
        result = parse_locate_payload(payload)
        assert result["unique_identifiers"] == ["uid-1", "uid-2", "uid-3"]

    def test_parse_locate_payload_empty_result(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, []))
        result = parse_locate_payload(payload)
        assert result["unique_identifiers"] == []

    def test_parse_locate_payload_single_result(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "only-one"),
        ]))
        result = parse_locate_payload(payload)
        assert result["unique_identifiers"] == ["only-one"]

    def test_parse_get_payload_extracts_key_material(self):
        key_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef")
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-99"),
            encode_enum(Tag.ObjectType, ObjectType.SymmetricKey),
            encode_structure(Tag.SymmetricKey, [
                encode_structure(Tag.KeyBlock, [
                    encode_enum(Tag.KeyFormatType, KeyFormatType.Raw),
                    encode_structure(Tag.KeyValue, [
                        encode_byte_string(Tag.KeyMaterial, key_bytes),
                    ]),
                ]),
            ]),
        ]))
        result = parse_get_payload(payload)
        assert result["unique_identifier"] == "uid-99"
        assert result["object_type"] == ObjectType.SymmetricKey
        assert result["key_material"] == key_bytes

    def test_parse_get_payload_no_symmetric_key(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-50"),
            encode_enum(Tag.ObjectType, ObjectType.Certificate),
        ]))
        result = parse_get_payload(payload)
        assert result["unique_identifier"] == "uid-50"
        assert result["key_material"] is None

    def test_parse_create_payload_extracts_type_and_id(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_enum(Tag.ObjectType, ObjectType.SymmetricKey),
            encode_text_string(Tag.UniqueIdentifier, "new-uid-7"),
        ]))
        result = parse_create_payload(payload)
        assert result["object_type"] == ObjectType.SymmetricKey
        assert result["unique_identifier"] == "new-uid-7"


# ---------------------------------------------------------------------------
# Round-trip: build -> encode -> decode -> verify
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_locate_request_deterministic(self):
        req1 = build_locate_request("round-trip-key")
        req2 = build_locate_request("round-trip-key")
        assert req1 == req2

    def test_get_request_round_trip(self):
        request = build_get_request("uid-abc")
        decoded = decode_ttlv(request)
        assert decoded["tag"] == Tag.RequestMessage
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-abc"

    def test_create_request_round_trip(self):
        request = build_create_request("rt-key", algorithm=Algorithm.AES, length=128)
        decoded = decode_ttlv(request)
        assert decoded["tag"] == Tag.RequestMessage
        batch = find_child(decoded, Tag.BatchItem)
        op = find_child(batch, Tag.Operation)
        assert op["value"] == Operation.Create
