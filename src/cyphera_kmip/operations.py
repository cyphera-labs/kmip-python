"""
KMIP request/response builders for Locate, Get, Create operations.
"""

from .ttlv import (
    encode_structure,
    encode_integer,
    encode_enum,
    encode_text_string,
    decode_ttlv,
    find_child,
    find_children,
)
from .tags import Tag, Operation, ObjectType, ResultStatus, Algorithm, NameType, UsageMask

# Protocol version: KMIP 1.4
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 4


def _build_request_header(batch_count: int = 1) -> bytes:
    """Build the request header (included in every request)."""
    return encode_structure(Tag.RequestHeader, [
        encode_structure(Tag.ProtocolVersion, [
            encode_integer(Tag.ProtocolVersionMajor, PROTOCOL_MAJOR),
            encode_integer(Tag.ProtocolVersionMinor, PROTOCOL_MINOR),
        ]),
        encode_integer(Tag.BatchCount, batch_count),
    ])


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


def parse_response(data: bytes) -> dict:
    """
    Parse a KMIP response message.

    Returns:
        Dict with keys: operation, result_status, result_reason, result_message, payload.

    Raises:
        ValueError: If the response tag is unexpected.
        RuntimeError: If the KMIP operation failed.
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
        raise RuntimeError(msg_text)

    return result


def parse_locate_payload(payload: dict) -> dict:
    """
    Parse a Locate response payload.

    Returns:
        Dict with key: unique_identifiers (list of str).
    """
    ids = find_children(payload, Tag.UniqueIdentifier)
    return {
        "unique_identifiers": [item["value"] for item in ids],
    }


def parse_get_payload(payload: dict) -> dict:
    """
    Parse a Get response payload.

    Returns:
        Dict with keys: object_type, unique_identifier, key_material.
    """
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
    """
    Parse a Create response payload.

    Returns:
        Dict with keys: object_type, unique_identifier.
    """
    uid = find_child(payload, Tag.UniqueIdentifier)
    obj_type = find_child(payload, Tag.ObjectType)
    return {
        "object_type": obj_type["value"] if obj_type else None,
        "unique_identifier": uid["value"] if uid else None,
    }
