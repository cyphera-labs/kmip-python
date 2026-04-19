"""Operations request/response tests -- full 27-operation set."""

import pytest
from cyphera_kmip.operations import (
    build_locate_request,
    build_get_request,
    build_create_request,
    build_activate_request,
    build_destroy_request,
    build_create_key_pair_request,
    build_register_request,
    build_re_key_request,
    build_derive_key_request,
    build_check_request,
    build_get_attributes_request,
    build_get_attribute_list_request,
    build_add_attribute_request,
    build_modify_attribute_request,
    build_delete_attribute_request,
    build_obtain_lease_request,
    build_revoke_request,
    build_archive_request,
    build_recover_request,
    build_query_request,
    build_poll_request,
    build_discover_versions_request,
    build_encrypt_request,
    build_decrypt_request,
    build_sign_request,
    build_signature_verify_request,
    build_mac_request,
    parse_response,
    parse_locate_payload,
    parse_get_payload,
    parse_create_payload,
    parse_check_payload,
    parse_re_key_payload,
    parse_encrypt_payload,
    parse_decrypt_payload,
    parse_sign_payload,
    parse_signature_verify_payload,
    parse_mac_payload,
    parse_query_payload,
    parse_discover_versions_payload,
    parse_derive_key_payload,
    parse_create_key_pair_payload,
    parse_obtain_lease_payload,
    KmipError,
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
# Original request building tests
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
# New operation request builders
# ---------------------------------------------------------------------------


def _decode_request(request_bytes):
    """Decode a request and return (operation_value, payload_decoded)."""
    decoded = decode_ttlv(request_bytes)
    batch = find_child(decoded, Tag.BatchItem)
    op = find_child(batch, Tag.Operation)
    payload = find_child(batch, Tag.RequestPayload)
    return op["value"], payload


class TestActivateDestroyBuilders:
    def test_activate_has_correct_operation(self):
        op, payload = _decode_request(build_activate_request("uid-1"))
        assert op == Operation.Activate

    def test_activate_contains_uid(self):
        op, payload = _decode_request(build_activate_request("uid-1"))
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-1"

    def test_destroy_has_correct_operation(self):
        op, payload = _decode_request(build_destroy_request("uid-2"))
        assert op == Operation.Destroy

    def test_destroy_contains_uid(self):
        op, payload = _decode_request(build_destroy_request("uid-2"))
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-2"


class TestCreateKeyPairBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(
            build_create_key_pair_request("kp-1", Algorithm.RSA, 2048)
        )
        assert op == Operation.CreateKeyPair

    def test_contains_algorithm(self):
        op, payload = _decode_request(
            build_create_key_pair_request("kp-1", Algorithm.RSA, 2048)
        )
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        algo_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Algorithm"
        )
        assert find_child(algo_attr, Tag.AttributeValue)["value"] == Algorithm.RSA

    def test_contains_sign_verify_usage_mask(self):
        op, payload = _decode_request(
            build_create_key_pair_request("kp-1", Algorithm.RSA, 2048)
        )
        tmpl = find_child(payload, Tag.TemplateAttribute)
        attrs = find_children(tmpl, Tag.Attribute)
        usage_attr = next(
            a for a in attrs
            if find_child(a, Tag.AttributeName)["value"] == "Cryptographic Usage Mask"
        )
        assert find_child(usage_attr, Tag.AttributeValue)["value"] == (
            UsageMask.Sign | UsageMask.Verify
        )


class TestRegisterBuilder:
    def test_has_correct_operation(self):
        material = bytes(32)
        op, payload = _decode_request(
            build_register_request(ObjectType.SymmetricKey, material, "reg-key", Algorithm.AES, 256)
        )
        assert op == Operation.Register

    def test_contains_object_type(self):
        material = bytes(32)
        op, payload = _decode_request(
            build_register_request(ObjectType.SymmetricKey, material, "reg-key", Algorithm.AES, 256)
        )
        obj_type = find_child(payload, Tag.ObjectType)
        assert obj_type["value"] == ObjectType.SymmetricKey

    def test_contains_key_material(self):
        material = bytes.fromhex("aabbccdd" * 8)
        op, payload = _decode_request(
            build_register_request(ObjectType.SymmetricKey, material, "reg-key", Algorithm.AES, 256)
        )
        sym_key = find_child(payload, Tag.SymmetricKey)
        key_block = find_child(sym_key, Tag.KeyBlock)
        key_value = find_child(key_block, Tag.KeyValue)
        km = find_child(key_value, Tag.KeyMaterial)
        assert km["value"] == material

    def test_contains_name_when_provided(self):
        material = bytes(32)
        op, payload = _decode_request(
            build_register_request(ObjectType.SymmetricKey, material, "my-reg", Algorithm.AES, 256)
        )
        tmpl = find_child(payload, Tag.TemplateAttribute)
        assert tmpl is not None

    def test_no_template_when_name_empty(self):
        material = bytes(32)
        op, payload = _decode_request(
            build_register_request(ObjectType.SymmetricKey, material, "", Algorithm.AES, 256)
        )
        tmpl = find_child(payload, Tag.TemplateAttribute)
        assert tmpl is None


class TestReKeyBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(build_re_key_request("uid-rk"))
        assert op == Operation.ReKey

    def test_contains_uid(self):
        op, payload = _decode_request(build_re_key_request("uid-rk"))
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-rk"


class TestDeriveKeyBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(
            build_derive_key_request("uid-dk", b"\x01\x02", "derived", 128)
        )
        assert op == Operation.DeriveKey

    def test_contains_uid(self):
        op, payload = _decode_request(
            build_derive_key_request("uid-dk", b"\x01\x02", "derived", 128)
        )
        uid = find_child(payload, Tag.UniqueIdentifier)
        assert uid["value"] == "uid-dk"

    def test_contains_derivation_parameters(self):
        op, payload = _decode_request(
            build_derive_key_request("uid-dk", b"\x01\x02", "derived", 128)
        )
        params = find_child(payload, Tag.DerivationParameters)
        assert params is not None
        dd = find_child(params, Tag.DerivationData)
        assert dd["value"] == b"\x01\x02"


class TestCheckBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(build_check_request("uid-chk"))
        assert op == Operation.Check


class TestAttributeBuilders:
    def test_get_attributes_operation(self):
        op, payload = _decode_request(build_get_attributes_request("uid-ga"))
        assert op == Operation.GetAttributes

    def test_get_attribute_list_operation(self):
        op, payload = _decode_request(build_get_attribute_list_request("uid-gal"))
        assert op == Operation.GetAttributeList

    def test_add_attribute_operation(self):
        op, payload = _decode_request(
            build_add_attribute_request("uid-aa", "Contact", "admin@example.com")
        )
        assert op == Operation.AddAttribute

    def test_add_attribute_contains_attr(self):
        op, payload = _decode_request(
            build_add_attribute_request("uid-aa", "Contact", "admin@example.com")
        )
        attr = find_child(payload, Tag.Attribute)
        attr_name = find_child(attr, Tag.AttributeName)
        attr_value = find_child(attr, Tag.AttributeValue)
        assert attr_name["value"] == "Contact"
        assert attr_value["value"] == "admin@example.com"

    def test_modify_attribute_operation(self):
        op, payload = _decode_request(
            build_modify_attribute_request("uid-ma", "Contact", "new@example.com")
        )
        assert op == Operation.ModifyAttribute

    def test_delete_attribute_operation(self):
        op, payload = _decode_request(
            build_delete_attribute_request("uid-da", "Contact")
        )
        assert op == Operation.DeleteAttribute

    def test_delete_attribute_contains_attr_name(self):
        op, payload = _decode_request(
            build_delete_attribute_request("uid-da", "Contact")
        )
        attr = find_child(payload, Tag.Attribute)
        attr_name = find_child(attr, Tag.AttributeName)
        assert attr_name["value"] == "Contact"


class TestObtainLeaseBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(build_obtain_lease_request("uid-ol"))
        assert op == Operation.ObtainLease


class TestRevokeBuilder:
    def test_has_correct_operation(self):
        op, payload = _decode_request(build_revoke_request("uid-rv", 1))
        assert op == Operation.Revoke

    def test_contains_revocation_reason(self):
        op, payload = _decode_request(build_revoke_request("uid-rv", 5))
        rr = find_child(payload, Tag.RevocationReason)
        assert rr is not None
        rrc = find_child(rr, Tag.RevocationReasonCode)
        assert rrc["value"] == 5


class TestArchiveRecoverBuilders:
    def test_archive_operation(self):
        op, payload = _decode_request(build_archive_request("uid-ar"))
        assert op == Operation.Archive

    def test_recover_operation(self):
        op, payload = _decode_request(build_recover_request("uid-rc"))
        assert op == Operation.Recover


class TestEmptyPayloadBuilders:
    def test_query_operation(self):
        op, payload = _decode_request(build_query_request())
        assert op == Operation.Query

    def test_poll_operation(self):
        op, payload = _decode_request(build_poll_request())
        assert op == Operation.Poll

    def test_discover_versions_operation(self):
        op, payload = _decode_request(build_discover_versions_request())
        assert op == Operation.DiscoverVersions


class TestCryptoBuilders:
    def test_encrypt_operation(self):
        op, payload = _decode_request(build_encrypt_request("uid-enc", b"plaintext"))
        assert op == Operation.Encrypt

    def test_encrypt_contains_data(self):
        op, payload = _decode_request(build_encrypt_request("uid-enc", b"plaintext"))
        data = find_child(payload, Tag.Data)
        assert data["value"] == b"plaintext"

    def test_decrypt_operation(self):
        op, payload = _decode_request(build_decrypt_request("uid-dec", b"ciphertext"))
        assert op == Operation.Decrypt

    def test_decrypt_without_nonce(self):
        op, payload = _decode_request(build_decrypt_request("uid-dec", b"ciphertext"))
        nonce = find_child(payload, Tag.IVCounterNonce)
        assert nonce is None

    def test_decrypt_with_nonce(self):
        op, payload = _decode_request(
            build_decrypt_request("uid-dec", b"ciphertext", nonce=b"\x01\x02\x03")
        )
        nonce = find_child(payload, Tag.IVCounterNonce)
        assert nonce["value"] == b"\x01\x02\x03"

    def test_sign_operation(self):
        op, payload = _decode_request(build_sign_request("uid-sign", b"data"))
        assert op == Operation.Sign

    def test_signature_verify_operation(self):
        op, payload = _decode_request(
            build_signature_verify_request("uid-sv", b"data", b"sig")
        )
        assert op == Operation.SignatureVerify

    def test_signature_verify_contains_signature_data(self):
        op, payload = _decode_request(
            build_signature_verify_request("uid-sv", b"data", b"sig-bytes")
        )
        sig = find_child(payload, Tag.SignatureData)
        assert sig["value"] == b"sig-bytes"

    def test_mac_operation(self):
        op, payload = _decode_request(build_mac_request("uid-mac", b"data"))
        assert op == Operation.MAC


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

    def test_parse_response_throws_kmip_error_on_failure(self):
        batch_extra = [encode_text_string(Tag.ResultMessage, "Item Not Found")]
        response = _build_mock_response(
            Operation.Get, ResultStatus.OperationFailed,
            extra_batch_children=batch_extra,
        )
        with pytest.raises(KmipError, match="Item Not Found"):
            parse_response(response)

    def test_kmip_error_has_status_and_reason(self):
        batch_extra = [
            encode_text_string(Tag.ResultMessage, "Denied"),
            encode_enum(Tag.ResultReason, 42),
        ]
        response = _build_mock_response(
            Operation.Get, ResultStatus.OperationFailed,
            extra_batch_children=batch_extra,
        )
        with pytest.raises(KmipError) as exc_info:
            parse_response(response)
        assert exc_info.value.result_status == ResultStatus.OperationFailed
        assert exc_info.value.result_reason == 42

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
# New payload parsers
# ---------------------------------------------------------------------------


class TestNewPayloadParsers:
    def test_parse_check_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-chk"),
        ]))
        result = parse_check_payload(payload)
        assert result["unique_identifier"] == "uid-chk"

    def test_parse_check_payload_none(self):
        result = parse_check_payload(None)
        assert result["unique_identifier"] is None

    def test_parse_re_key_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-rk-new"),
        ]))
        result = parse_re_key_payload(payload)
        assert result["unique_identifier"] == "uid-rk-new"

    def test_parse_re_key_payload_none(self):
        result = parse_re_key_payload(None)
        assert result["unique_identifier"] is None

    def test_parse_encrypt_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_byte_string(Tag.Data, b"ciphertext"),
            encode_byte_string(Tag.IVCounterNonce, b"\xaa\xbb"),
        ]))
        result = parse_encrypt_payload(payload)
        assert result["data"] == b"ciphertext"
        assert result["nonce"] == b"\xaa\xbb"

    def test_parse_encrypt_payload_no_nonce(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_byte_string(Tag.Data, b"ciphertext"),
        ]))
        result = parse_encrypt_payload(payload)
        assert result["data"] == b"ciphertext"
        assert result["nonce"] is None

    def test_parse_encrypt_payload_none(self):
        result = parse_encrypt_payload(None)
        assert result["data"] is None
        assert result["nonce"] is None

    def test_parse_decrypt_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_byte_string(Tag.Data, b"plaintext"),
        ]))
        result = parse_decrypt_payload(payload)
        assert result["data"] == b"plaintext"

    def test_parse_decrypt_payload_none(self):
        result = parse_decrypt_payload(None)
        assert result["data"] is None

    def test_parse_sign_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_byte_string(Tag.SignatureData, b"sig-bytes"),
        ]))
        result = parse_sign_payload(payload)
        assert result["signature_data"] == b"sig-bytes"

    def test_parse_sign_payload_none(self):
        result = parse_sign_payload(None)
        assert result["signature_data"] is None

    def test_parse_signature_verify_payload_valid(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_enum(Tag.ValidityIndicator, 0),  # 0 = valid
        ]))
        result = parse_signature_verify_payload(payload)
        assert result["valid"] is True

    def test_parse_signature_verify_payload_invalid(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_enum(Tag.ValidityIndicator, 1),  # 1 = invalid
        ]))
        result = parse_signature_verify_payload(payload)
        assert result["valid"] is False

    def test_parse_signature_verify_payload_none(self):
        result = parse_signature_verify_payload(None)
        assert result["valid"] is False

    def test_parse_mac_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_byte_string(Tag.MACData, b"mac-bytes"),
        ]))
        result = parse_mac_payload(payload)
        assert result["mac_data"] == b"mac-bytes"

    def test_parse_mac_payload_none(self):
        result = parse_mac_payload(None)
        assert result["mac_data"] is None

    def test_parse_query_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_enum(Tag.Operation, Operation.Create),
            encode_enum(Tag.Operation, Operation.Get),
            encode_enum(Tag.ObjectType, ObjectType.SymmetricKey),
        ]))
        result = parse_query_payload(payload)
        assert result["operations"] == [Operation.Create, Operation.Get]
        assert result["object_types"] == [ObjectType.SymmetricKey]

    def test_parse_query_payload_empty(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, []))
        result = parse_query_payload(payload)
        assert result["operations"] == []
        assert result["object_types"] == []

    def test_parse_query_payload_none(self):
        result = parse_query_payload(None)
        assert result["operations"] == []
        assert result["object_types"] == []

    def test_parse_discover_versions_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_structure(Tag.ProtocolVersion, [
                encode_integer(Tag.ProtocolVersionMajor, 1),
                encode_integer(Tag.ProtocolVersionMinor, 4),
            ]),
            encode_structure(Tag.ProtocolVersion, [
                encode_integer(Tag.ProtocolVersionMajor, 1),
                encode_integer(Tag.ProtocolVersionMinor, 3),
            ]),
        ]))
        result = parse_discover_versions_payload(payload)
        assert len(result["versions"]) == 2
        assert result["versions"][0] == {"major": 1, "minor": 4}
        assert result["versions"][1] == {"major": 1, "minor": 3}

    def test_parse_discover_versions_payload_none(self):
        result = parse_discover_versions_payload(None)
        assert result["versions"] == []

    def test_parse_derive_key_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.UniqueIdentifier, "uid-derived"),
        ]))
        result = parse_derive_key_payload(payload)
        assert result["unique_identifier"] == "uid-derived"

    def test_parse_derive_key_payload_none(self):
        result = parse_derive_key_payload(None)
        assert result["unique_identifier"] is None

    def test_parse_create_key_pair_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_text_string(Tag.PrivateKeyUniqueIdentifier, "priv-uid-1"),
            encode_text_string(Tag.PublicKeyUniqueIdentifier, "pub-uid-1"),
        ]))
        result = parse_create_key_pair_payload(payload)
        assert result["private_key_uid"] == "priv-uid-1"
        assert result["public_key_uid"] == "pub-uid-1"

    def test_parse_create_key_pair_payload_none(self):
        result = parse_create_key_pair_payload(None)
        assert result["private_key_uid"] is None
        assert result["public_key_uid"] is None

    def test_parse_obtain_lease_payload(self):
        payload = decode_ttlv(encode_structure(Tag.ResponsePayload, [
            encode_integer(Tag.LeaseTime, 3600),
        ]))
        result = parse_obtain_lease_payload(payload)
        assert result["lease_time"] == 3600

    def test_parse_obtain_lease_payload_none(self):
        result = parse_obtain_lease_payload(None)
        assert result["lease_time"] == 0


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

    def test_encrypt_request_round_trip(self):
        request = build_encrypt_request("uid-rt", b"round-trip-data")
        decoded = decode_ttlv(request)
        batch = find_child(decoded, Tag.BatchItem)
        payload = find_child(batch, Tag.RequestPayload)
        uid = find_child(payload, Tag.UniqueIdentifier)
        data = find_child(payload, Tag.Data)
        assert uid["value"] == "uid-rt"
        assert data["value"] == b"round-trip-data"

    def test_revoke_request_round_trip(self):
        request = build_revoke_request("uid-rv-rt", 3)
        decoded = decode_ttlv(request)
        batch = find_child(decoded, Tag.BatchItem)
        op = find_child(batch, Tag.Operation)
        assert op["value"] == Operation.Revoke
        payload = find_child(batch, Tag.RequestPayload)
        rr = find_child(payload, Tag.RevocationReason)
        rrc = find_child(rr, Tag.RevocationReasonCode)
        assert rrc["value"] == 3

    def test_all_uid_only_builders_produce_valid_ttlv(self):
        """All UID-only builders should produce decodable TTLV."""
        builders = [
            (build_activate_request, "uid"),
            (build_destroy_request, "uid"),
            (build_re_key_request, "uid"),
            (build_check_request, "uid"),
            (build_get_attributes_request, "uid"),
            (build_get_attribute_list_request, "uid"),
            (build_obtain_lease_request, "uid"),
            (build_archive_request, "uid"),
            (build_recover_request, "uid"),
        ]
        for builder, arg in builders:
            request = builder(arg)
            decoded = decode_ttlv(request)
            assert decoded["tag"] == Tag.RequestMessage

    def test_all_empty_payload_builders_produce_valid_ttlv(self):
        """All empty-payload builders should produce decodable TTLV."""
        builders = [
            build_query_request,
            build_poll_request,
            build_discover_versions_request,
        ]
        for builder in builders:
            request = builder()
            decoded = decode_ttlv(request)
            assert decoded["tag"] == Tag.RequestMessage
