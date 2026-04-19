"""
KMIP request/response builders for all 27 operations.
Matches the kmip-go reference exactly.
"""

from .ttlv import (
    encode_structure,
    encode_integer,
    encode_enum,
    encode_text_string,
    encode_byte_string,
    decode_ttlv,
    find_child,
    find_children,
)
from .tags import Tag, Operation, ObjectType, ResultStatus, Algorithm, NameType, UsageMask, KeyFormatType

# Protocol version: KMIP 1.4
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 4


# ---------------------------------------------------------------------------
# KmipError
# ---------------------------------------------------------------------------


class KmipError(RuntimeError):
    """Raised when a KMIP operation fails."""

    def __init__(self, message: str, result_status: int = 0, result_reason: int = 0):
        super().__init__(message)
        self.result_status = result_status
        self.result_reason = result_reason


# ---------------------------------------------------------------------------
# Request header (shared by all requests)
# ---------------------------------------------------------------------------


def _build_request_header(batch_count: int = 1) -> bytes:
    """Build the request header (included in every request)."""
    return encode_structure(Tag.RequestHeader, [
        encode_structure(Tag.ProtocolVersion, [
            encode_integer(Tag.ProtocolVersionMajor, PROTOCOL_MAJOR),
            encode_integer(Tag.ProtocolVersionMinor, PROTOCOL_MINOR),
        ]),
        encode_integer(Tag.BatchCount, batch_count),
    ])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_uid_only_request(operation: int, unique_id: str) -> bytes:
    """Build a request with just a UID in the payload."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, operation),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def _build_empty_payload_request(operation: int) -> bytes:
    """Build a request with an empty payload."""
    payload = encode_structure(Tag.RequestPayload, [])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, operation),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


# ---------------------------------------------------------------------------
# Request builders (27 operations)
# ---------------------------------------------------------------------------


def build_locate_request(name: str) -> bytes:
    """Build a Locate request -- find keys by name."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_structure(Tag.Attribute, [
            encode_text_string(Tag.AttributeName, "Name"),
            encode_structure(Tag.AttributeValue, [
                encode_text_string(Tag.NameValue, name),
                encode_enum(Tag.NameType, NameType.UninterpretedTextString),
            ]),
        ]),
    ])

    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Locate),
        payload,
    ])

    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_get_request(unique_id: str) -> bytes:
    """Build a Get request -- fetch key material by unique ID."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
    ])

    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Get),
        payload,
    ])

    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_create_request(
    name: str,
    algorithm: int = Algorithm.AES,
    length: int = 256,
) -> bytes:
    """Build a Create request -- create a new symmetric key."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_enum(Tag.ObjectType, ObjectType.SymmetricKey),
        encode_structure(Tag.TemplateAttribute, [
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Algorithm"),
                encode_enum(Tag.AttributeValue, algorithm),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Length"),
                encode_integer(Tag.AttributeValue, length),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Usage Mask"),
                encode_integer(Tag.AttributeValue, UsageMask.Encrypt | UsageMask.Decrypt),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Name"),
                encode_structure(Tag.AttributeValue, [
                    encode_text_string(Tag.NameValue, name),
                    encode_enum(Tag.NameType, NameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])

    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Create),
        payload,
    ])

    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_activate_request(unique_id: str) -> bytes:
    """Build an Activate request for a key by unique ID."""
    return _build_uid_only_request(Operation.Activate, unique_id)


def build_destroy_request(unique_id: str) -> bytes:
    """Build a Destroy request for a key by unique ID."""
    return _build_uid_only_request(Operation.Destroy, unique_id)


def build_create_key_pair_request(
    name: str,
    algorithm: int,
    length: int,
) -> bytes:
    """Build a CreateKeyPair request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_structure(Tag.TemplateAttribute, [
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Algorithm"),
                encode_enum(Tag.AttributeValue, algorithm),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Length"),
                encode_integer(Tag.AttributeValue, length),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Usage Mask"),
                encode_integer(Tag.AttributeValue, UsageMask.Sign | UsageMask.Verify),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Name"),
                encode_structure(Tag.AttributeValue, [
                    encode_text_string(Tag.NameValue, name),
                    encode_enum(Tag.NameType, NameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.CreateKeyPair),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_register_request(
    object_type: int,
    material: bytes,
    name: str,
    algorithm: int,
    length: int,
) -> bytes:
    """Build a Register request for a symmetric key."""
    payload_children = [
        encode_enum(Tag.ObjectType, object_type),
        encode_structure(Tag.SymmetricKey, [
            encode_structure(Tag.KeyBlock, [
                encode_enum(Tag.KeyFormatType, KeyFormatType.Raw),
                encode_structure(Tag.KeyValue, [
                    encode_byte_string(Tag.KeyMaterial, material),
                ]),
                encode_enum(Tag.CryptographicAlgorithm, algorithm),
                encode_integer(Tag.CryptographicLength, length),
            ]),
        ]),
    ]
    if name:
        payload_children.append(
            encode_structure(Tag.TemplateAttribute, [
                encode_structure(Tag.Attribute, [
                    encode_text_string(Tag.AttributeName, "Name"),
                    encode_structure(Tag.AttributeValue, [
                        encode_text_string(Tag.NameValue, name),
                        encode_enum(Tag.NameType, NameType.UninterpretedTextString),
                    ]),
                ]),
            ]),
        )
    payload = encode_structure(Tag.RequestPayload, payload_children)
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Register),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_re_key_request(unique_id: str) -> bytes:
    """Build a ReKey request."""
    return _build_uid_only_request(Operation.ReKey, unique_id)


def build_derive_key_request(
    unique_id: str,
    derivation_data: bytes,
    name: str,
    length: int,
) -> bytes:
    """Build a DeriveKey request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_structure(Tag.DerivationParameters, [
            encode_byte_string(Tag.DerivationData, derivation_data),
        ]),
        encode_structure(Tag.TemplateAttribute, [
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Cryptographic Length"),
                encode_integer(Tag.AttributeValue, length),
            ]),
            encode_structure(Tag.Attribute, [
                encode_text_string(Tag.AttributeName, "Name"),
                encode_structure(Tag.AttributeValue, [
                    encode_text_string(Tag.NameValue, name),
                    encode_enum(Tag.NameType, NameType.UninterpretedTextString),
                ]),
            ]),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.DeriveKey),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_check_request(unique_id: str) -> bytes:
    """Build a Check request."""
    return _build_uid_only_request(Operation.Check, unique_id)


def build_get_attributes_request(unique_id: str) -> bytes:
    """Build a GetAttributes request."""
    return _build_uid_only_request(Operation.GetAttributes, unique_id)


def build_get_attribute_list_request(unique_id: str) -> bytes:
    """Build a GetAttributeList request."""
    return _build_uid_only_request(Operation.GetAttributeList, unique_id)


def build_add_attribute_request(unique_id: str, attr_name: str, attr_value: str) -> bytes:
    """Build an AddAttribute request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_structure(Tag.Attribute, [
            encode_text_string(Tag.AttributeName, attr_name),
            encode_text_string(Tag.AttributeValue, attr_value),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.AddAttribute),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_modify_attribute_request(unique_id: str, attr_name: str, attr_value: str) -> bytes:
    """Build a ModifyAttribute request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_structure(Tag.Attribute, [
            encode_text_string(Tag.AttributeName, attr_name),
            encode_text_string(Tag.AttributeValue, attr_value),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.ModifyAttribute),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_delete_attribute_request(unique_id: str, attr_name: str) -> bytes:
    """Build a DeleteAttribute request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_structure(Tag.Attribute, [
            encode_text_string(Tag.AttributeName, attr_name),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.DeleteAttribute),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_obtain_lease_request(unique_id: str) -> bytes:
    """Build an ObtainLease request."""
    return _build_uid_only_request(Operation.ObtainLease, unique_id)


def build_revoke_request(unique_id: str, reason: int) -> bytes:
    """Build a Revoke request with a revocation reason."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_structure(Tag.RevocationReason, [
            encode_enum(Tag.RevocationReasonCode, reason),
        ]),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Revoke),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_archive_request(unique_id: str) -> bytes:
    """Build an Archive request."""
    return _build_uid_only_request(Operation.Archive, unique_id)


def build_recover_request(unique_id: str) -> bytes:
    """Build a Recover request."""
    return _build_uid_only_request(Operation.Recover, unique_id)


def build_query_request() -> bytes:
    """Build a Query request."""
    return _build_empty_payload_request(Operation.Query)


def build_poll_request() -> bytes:
    """Build a Poll request."""
    return _build_empty_payload_request(Operation.Poll)


def build_discover_versions_request() -> bytes:
    """Build a DiscoverVersions request."""
    return _build_empty_payload_request(Operation.DiscoverVersions)


def build_encrypt_request(unique_id: str, data: bytes) -> bytes:
    """Build an Encrypt request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_byte_string(Tag.Data, data),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Encrypt),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_decrypt_request(unique_id: str, data: bytes, nonce: bytes = None) -> bytes:
    """Build a Decrypt request."""
    payload_children = [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_byte_string(Tag.Data, data),
    ]
    if nonce:
        payload_children.append(encode_byte_string(Tag.IVCounterNonce, nonce))
    payload = encode_structure(Tag.RequestPayload, payload_children)
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Decrypt),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_sign_request(unique_id: str, data: bytes) -> bytes:
    """Build a Sign request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_byte_string(Tag.Data, data),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.Sign),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_signature_verify_request(unique_id: str, data: bytes, signature: bytes) -> bytes:
    """Build a SignatureVerify request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_byte_string(Tag.Data, data),
        encode_byte_string(Tag.SignatureData, signature),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.SignatureVerify),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


def build_mac_request(unique_id: str, data: bytes) -> bytes:
    """Build a MAC request."""
    payload = encode_structure(Tag.RequestPayload, [
        encode_text_string(Tag.UniqueIdentifier, unique_id),
        encode_byte_string(Tag.Data, data),
    ])
    batch_item = encode_structure(Tag.BatchItem, [
        encode_enum(Tag.Operation, Operation.MAC),
        payload,
    ])
    return encode_structure(Tag.RequestMessage, [
        _build_request_header(),
        batch_item,
    ])


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def parse_response(data: bytes) -> dict:
    """
    Parse a KMIP response message.

    Returns:
        Dict with keys: operation, result_status, result_reason, result_message, payload.

    Raises:
        ValueError: If the response tag is unexpected.
        KmipError: If the KMIP operation failed.
    """
    msg = decode_ttlv(data)
    if msg["tag"] != Tag.ResponseMessage:
        raise ValueError(
            f"Expected ResponseMessage (0x42007B), got 0x{msg['tag']:06x}"
        )

    batch_item = find_child(msg, Tag.BatchItem)
    if batch_item is None:
        raise ValueError("No BatchItem in response")

    operation_item = find_child(batch_item, Tag.Operation)
    status_item = find_child(batch_item, Tag.ResultStatus)
    reason_item = find_child(batch_item, Tag.ResultReason)
    message_item = find_child(batch_item, Tag.ResultMessage)
    payload_item = find_child(batch_item, Tag.ResponsePayload)

    result = {
        "operation": operation_item["value"] if operation_item else None,
        "result_status": status_item["value"] if status_item else None,
        "result_reason": reason_item["value"] if reason_item else None,
        "result_message": message_item["value"] if message_item else None,
        "payload": payload_item,
    }

    if result["result_status"] != ResultStatus.Success:
        msg_text = result["result_message"] or f"KMIP operation failed (status={result['result_status']})"
        raise KmipError(
            msg_text,
            result_status=result["result_status"] or 0,
            result_reason=result["result_reason"] or 0,
        )

    return result


# ---------------------------------------------------------------------------
# Payload parsers
# ---------------------------------------------------------------------------


def parse_locate_payload(payload: dict) -> dict:
    """Parse a Locate response payload."""
    ids = find_children(payload, Tag.UniqueIdentifier)
    return {
        "unique_identifiers": [item["value"] for item in ids],
    }


def parse_get_payload(payload: dict) -> dict:
    """Parse a Get response payload."""
    uid = find_child(payload, Tag.UniqueIdentifier)
    obj_type = find_child(payload, Tag.ObjectType)

    # Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
    sym_key = find_child(payload, Tag.SymmetricKey)
    key_material = None

    if sym_key:
        key_block = find_child(sym_key, Tag.KeyBlock)
        if key_block:
            key_value = find_child(key_block, Tag.KeyValue)
            if key_value:
                material = find_child(key_value, Tag.KeyMaterial)
                if material:
                    key_material = material["value"]

    return {
        "object_type": obj_type["value"] if obj_type else None,
        "unique_identifier": uid["value"] if uid else None,
        "key_material": key_material,
    }


def parse_create_payload(payload: dict) -> dict:
    """Parse a Create response payload."""
    uid = find_child(payload, Tag.UniqueIdentifier)
    obj_type = find_child(payload, Tag.ObjectType)
    return {
        "object_type": obj_type["value"] if obj_type else None,
        "unique_identifier": uid["value"] if uid else None,
    }


def parse_check_payload(payload: dict) -> dict:
    """Parse a Check response payload."""
    result = {"unique_identifier": None}
    if payload is None:
        return result
    uid = find_child(payload, Tag.UniqueIdentifier)
    if uid:
        result["unique_identifier"] = uid["value"]
    return result


def parse_re_key_payload(payload: dict) -> dict:
    """Parse a ReKey response payload."""
    result = {"unique_identifier": None}
    if payload is None:
        return result
    uid = find_child(payload, Tag.UniqueIdentifier)
    if uid:
        result["unique_identifier"] = uid["value"]
    return result


def parse_encrypt_payload(payload: dict) -> dict:
    """Parse an Encrypt response payload."""
    result = {"data": None, "nonce": None}
    if payload is None:
        return result
    data = find_child(payload, Tag.Data)
    if data:
        result["data"] = data["value"]
    nonce = find_child(payload, Tag.IVCounterNonce)
    if nonce:
        result["nonce"] = nonce["value"]
    return result


def parse_decrypt_payload(payload: dict) -> dict:
    """Parse a Decrypt response payload."""
    result = {"data": None}
    if payload is None:
        return result
    data = find_child(payload, Tag.Data)
    if data:
        result["data"] = data["value"]
    return result


def parse_sign_payload(payload: dict) -> dict:
    """Parse a Sign response payload."""
    result = {"signature_data": None}
    if payload is None:
        return result
    sig = find_child(payload, Tag.SignatureData)
    if sig:
        result["signature_data"] = sig["value"]
    return result


def parse_signature_verify_payload(payload: dict) -> dict:
    """Parse a SignatureVerify response payload."""
    result = {"valid": False}
    if payload is None:
        return result
    indicator = find_child(payload, Tag.ValidityIndicator)
    if indicator:
        # 0 = Valid, 1 = Invalid
        result["valid"] = indicator["value"] == 0
    return result


def parse_mac_payload(payload: dict) -> dict:
    """Parse a MAC response payload."""
    result = {"mac_data": None}
    if payload is None:
        return result
    mac_data = find_child(payload, Tag.MACData)
    if mac_data:
        result["mac_data"] = mac_data["value"]
    return result


def parse_query_payload(payload: dict) -> dict:
    """Parse a Query response payload."""
    result = {"operations": [], "object_types": []}
    if payload is None:
        return result
    ops = find_children(payload, Tag.Operation)
    for op in ops:
        result["operations"].append(op["value"])
    obj_types = find_children(payload, Tag.ObjectType)
    for ot in obj_types:
        result["object_types"].append(ot["value"])
    return result


def parse_discover_versions_payload(payload: dict) -> dict:
    """Parse a DiscoverVersions response payload."""
    result = {"versions": []}
    if payload is None:
        return result
    versions = find_children(payload, Tag.ProtocolVersion)
    for v in versions:
        major = find_child(v, Tag.ProtocolVersionMajor)
        minor = find_child(v, Tag.ProtocolVersionMinor)
        entry = {
            "major": major["value"] if major else 0,
            "minor": minor["value"] if minor else 0,
        }
        result["versions"].append(entry)
    return result


def parse_derive_key_payload(payload: dict) -> dict:
    """Parse a DeriveKey response payload."""
    result = {"unique_identifier": None}
    if payload is None:
        return result
    uid = find_child(payload, Tag.UniqueIdentifier)
    if uid:
        result["unique_identifier"] = uid["value"]
    return result


def parse_create_key_pair_payload(payload: dict) -> dict:
    """Parse a CreateKeyPair response payload."""
    result = {"private_key_uid": None, "public_key_uid": None}
    if payload is None:
        return result
    priv_uid = find_child(payload, Tag.PrivateKeyUniqueIdentifier)
    if priv_uid:
        result["private_key_uid"] = priv_uid["value"]
    pub_uid = find_child(payload, Tag.PublicKeyUniqueIdentifier)
    if pub_uid:
        result["public_key_uid"] = pub_uid["value"]
    return result


def parse_obtain_lease_payload(payload: dict) -> dict:
    """Parse an ObtainLease response payload."""
    result = {"lease_time": 0}
    if payload is None:
        return result
    lease = find_child(payload, Tag.LeaseTime)
    if lease:
        result["lease_time"] = lease["value"]
    return result
