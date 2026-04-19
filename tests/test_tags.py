"""Tag/enum constant tests -- full 27-operation set."""

from cyphera_kmip.tags import (
    Tag,
    Operation,
    ObjectType,
    ResultStatus,
    KeyFormatType,
    Algorithm,
    NameType,
    UsageMask,
)


# ---------------------------------------------------------------------------
# ObjectType values -- KMIP 1.4 Section 9.1.3.2.3
# ---------------------------------------------------------------------------


class TestObjectType:
    def test_certificate(self):
        assert ObjectType.Certificate == 0x00000001

    def test_symmetric_key(self):
        assert ObjectType.SymmetricKey == 0x00000002

    def test_public_key(self):
        assert ObjectType.PublicKey == 0x00000003

    def test_private_key(self):
        assert ObjectType.PrivateKey == 0x00000004

    def test_split_key(self):
        assert ObjectType.SplitKey == 0x00000005

    def test_template(self):
        assert ObjectType.Template == 0x00000006

    def test_secret_data(self):
        assert ObjectType.SecretData == 0x00000007

    def test_opaque_data(self):
        assert ObjectType.OpaqueData == 0x00000008

    def test_no_duplicate_values(self):
        values = [
            ObjectType.Certificate, ObjectType.SymmetricKey, ObjectType.PublicKey,
            ObjectType.PrivateKey, ObjectType.SplitKey, ObjectType.Template,
            ObjectType.SecretData, ObjectType.OpaqueData,
        ]
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# Operation values -- all 27 operations
# ---------------------------------------------------------------------------


class TestOperations:
    def test_create(self):
        assert Operation.Create == 0x00000001

    def test_create_key_pair(self):
        assert Operation.CreateKeyPair == 0x00000002

    def test_register(self):
        assert Operation.Register == 0x00000003

    def test_re_key(self):
        assert Operation.ReKey == 0x00000004

    def test_derive_key(self):
        assert Operation.DeriveKey == 0x00000005

    def test_locate(self):
        assert Operation.Locate == 0x00000008

    def test_check(self):
        assert Operation.Check == 0x00000009

    def test_get(self):
        assert Operation.Get == 0x0000000A

    def test_get_attributes(self):
        assert Operation.GetAttributes == 0x0000000B

    def test_get_attribute_list(self):
        assert Operation.GetAttributeList == 0x0000000C

    def test_add_attribute(self):
        assert Operation.AddAttribute == 0x0000000D

    def test_modify_attribute(self):
        assert Operation.ModifyAttribute == 0x0000000E

    def test_delete_attribute(self):
        assert Operation.DeleteAttribute == 0x0000000F

    def test_obtain_lease(self):
        assert Operation.ObtainLease == 0x00000010

    def test_activate(self):
        assert Operation.Activate == 0x00000012

    def test_revoke(self):
        assert Operation.Revoke == 0x00000013

    def test_destroy(self):
        assert Operation.Destroy == 0x00000014

    def test_archive(self):
        assert Operation.Archive == 0x00000015

    def test_recover(self):
        assert Operation.Recover == 0x00000016

    def test_query(self):
        assert Operation.Query == 0x00000018

    def test_poll(self):
        assert Operation.Poll == 0x0000001A

    def test_discover_versions(self):
        assert Operation.DiscoverVersions == 0x0000001E

    def test_encrypt(self):
        assert Operation.Encrypt == 0x0000001F

    def test_decrypt(self):
        assert Operation.Decrypt == 0x00000020

    def test_sign(self):
        assert Operation.Sign == 0x00000021

    def test_signature_verify(self):
        assert Operation.SignatureVerify == 0x00000022

    def test_mac(self):
        assert Operation.MAC == 0x00000023

    def test_no_duplicate_values(self):
        values = [
            Operation.Create, Operation.CreateKeyPair, Operation.Register,
            Operation.ReKey, Operation.DeriveKey, Operation.Locate,
            Operation.Check, Operation.Get, Operation.GetAttributes,
            Operation.GetAttributeList, Operation.AddAttribute,
            Operation.ModifyAttribute, Operation.DeleteAttribute,
            Operation.ObtainLease, Operation.Activate, Operation.Revoke,
            Operation.Destroy, Operation.Archive, Operation.Recover,
            Operation.Query, Operation.Poll, Operation.DiscoverVersions,
            Operation.Encrypt, Operation.Decrypt, Operation.Sign,
            Operation.SignatureVerify, Operation.MAC,
        ]
        assert len(values) == 27
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# ResultStatus
# ---------------------------------------------------------------------------


class TestResultStatus:
    def test_success(self):
        assert ResultStatus.Success == 0x00000000

    def test_operation_failed(self):
        assert ResultStatus.OperationFailed == 0x00000001

    def test_operation_pending(self):
        assert ResultStatus.OperationPending == 0x00000002

    def test_operation_undone(self):
        assert ResultStatus.OperationUndone == 0x00000003

    def test_no_duplicate_values(self):
        values = [
            ResultStatus.Success, ResultStatus.OperationFailed,
            ResultStatus.OperationPending, ResultStatus.OperationUndone,
        ]
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# Algorithm values -- KMIP 1.4 Section 9.1.3.2.13
# ---------------------------------------------------------------------------


class TestAlgorithms:
    def test_des(self):
        assert Algorithm.DES == 0x00000001

    def test_triple_des(self):
        assert Algorithm.TripleDES == 0x00000002

    def test_aes(self):
        assert Algorithm.AES == 0x00000003

    def test_rsa(self):
        assert Algorithm.RSA == 0x00000004

    def test_dsa(self):
        assert Algorithm.DSA == 0x00000005

    def test_ecdsa(self):
        assert Algorithm.ECDSA == 0x00000006

    def test_hmac_sha1(self):
        assert Algorithm.HMACSHA1 == 0x00000007

    def test_hmac_sha256(self):
        assert Algorithm.HMACSHA256 == 0x00000008

    def test_hmac_sha384(self):
        assert Algorithm.HMACSHA384 == 0x00000009

    def test_hmac_sha512(self):
        assert Algorithm.HMACSHA512 == 0x0000000A

    def test_no_duplicate_values(self):
        values = [
            Algorithm.DES, Algorithm.TripleDES, Algorithm.AES, Algorithm.RSA,
            Algorithm.DSA, Algorithm.ECDSA, Algorithm.HMACSHA1,
            Algorithm.HMACSHA256, Algorithm.HMACSHA384, Algorithm.HMACSHA512,
        ]
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# KeyFormatType
# ---------------------------------------------------------------------------


class TestKeyFormatType:
    def test_raw(self):
        assert KeyFormatType.Raw == 0x00000001

    def test_opaque(self):
        assert KeyFormatType.Opaque == 0x00000002

    def test_pkcs1(self):
        assert KeyFormatType.PKCS1 == 0x00000003

    def test_pkcs8(self):
        assert KeyFormatType.PKCS8 == 0x00000004

    def test_x509(self):
        assert KeyFormatType.X509 == 0x00000005

    def test_ec_private_key(self):
        assert KeyFormatType.ECPrivateKey == 0x00000006

    def test_transparent_symmetric(self):
        assert KeyFormatType.TransparentSymmetric == 0x00000007

    def test_no_duplicate_values(self):
        values = [
            KeyFormatType.Raw, KeyFormatType.Opaque, KeyFormatType.PKCS1,
            KeyFormatType.PKCS8, KeyFormatType.X509, KeyFormatType.ECPrivateKey,
            KeyFormatType.TransparentSymmetric,
        ]
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# NameType
# ---------------------------------------------------------------------------


class TestNameType:
    def test_uninterpreted_text_string(self):
        assert NameType.UninterpretedTextString == 0x00000001

    def test_uri(self):
        assert NameType.URI == 0x00000002


# ---------------------------------------------------------------------------
# UsageMask -- bitmask values
# ---------------------------------------------------------------------------


class TestUsageMask:
    def test_sign(self):
        assert UsageMask.Sign == 0x00000001

    def test_verify(self):
        assert UsageMask.Verify == 0x00000002

    def test_encrypt(self):
        assert UsageMask.Encrypt == 0x00000004

    def test_decrypt(self):
        assert UsageMask.Decrypt == 0x00000008

    def test_wrap_key(self):
        assert UsageMask.WrapKey == 0x00000010

    def test_unwrap_key(self):
        assert UsageMask.UnwrapKey == 0x00000020

    def test_export(self):
        assert UsageMask.Export == 0x00000040

    def test_derive_key(self):
        assert UsageMask.DeriveKey == 0x00000100

    def test_key_agreement(self):
        assert UsageMask.KeyAgreement == 0x00000800

    def test_encrypt_decrypt_combination(self):
        assert UsageMask.Encrypt | UsageMask.Decrypt == 0x0000000C

    def test_all_values_distinct_bits(self):
        values = [
            UsageMask.Sign, UsageMask.Verify, UsageMask.Encrypt,
            UsageMask.Decrypt, UsageMask.WrapKey, UsageMask.UnwrapKey,
            UsageMask.Export, UsageMask.DeriveKey, UsageMask.KeyAgreement,
        ]
        combined = 0
        for v in values:
            assert combined & v == 0, f"value 0x{v:08x} overlaps with previous values"
            combined |= v


# ---------------------------------------------------------------------------
# Tag values -- all should be in the 0x42XXXX range
# ---------------------------------------------------------------------------


class TestTagRange:
    def test_all_tag_values_in_kmip_range(self):
        tag_attrs = [
            attr for attr in dir(Tag)
            if not attr.startswith("_")
        ]
        for name in tag_attrs:
            value = getattr(Tag, name)
            assert 0x420000 <= value <= 0x42FFFF, (
                f"Tag.{name} = 0x{value:06x} is outside 0x42XXXX range"
            )

    def test_no_duplicate_tag_values(self):
        tag_attrs = [
            attr for attr in dir(Tag)
            if not attr.startswith("_")
        ]
        values = [getattr(Tag, name) for name in tag_attrs]
        assert len(set(values)) == len(values)


# ---------------------------------------------------------------------------
# New tags added for full 27-op support
# ---------------------------------------------------------------------------


class TestNewTags:
    def test_private_key_unique_identifier(self):
        assert Tag.PrivateKeyUniqueIdentifier == 0x420066

    def test_public_key_unique_identifier(self):
        assert Tag.PublicKeyUniqueIdentifier == 0x42006F

    def test_public_key(self):
        assert Tag.PublicKey == 0x42004E

    def test_private_key(self):
        assert Tag.PrivateKey == 0x42004D

    def test_certificate(self):
        assert Tag.Certificate == 0x420021

    def test_certificate_type(self):
        assert Tag.CertificateType == 0x42001D

    def test_certificate_value(self):
        assert Tag.CertificateValue == 0x42001E

    def test_data(self):
        assert Tag.Data == 0x420033

    def test_iv_counter_nonce(self):
        assert Tag.IVCounterNonce == 0x420047

    def test_signature_data(self):
        assert Tag.SignatureData == 0x42004F

    def test_mac_data(self):
        assert Tag.MACData == 0x420051

    def test_validity_indicator(self):
        assert Tag.ValidityIndicator == 0x420098

    def test_revocation_reason(self):
        assert Tag.RevocationReason == 0x420082

    def test_revocation_reason_code(self):
        assert Tag.RevocationReasonCode == 0x420083

    def test_query_function(self):
        assert Tag.QueryFunction == 0x420074

    def test_state(self):
        assert Tag.State == 0x42008D

    def test_derivation_method(self):
        assert Tag.DerivationMethod == 0x420031

    def test_derivation_parameters(self):
        assert Tag.DerivationParameters == 0x420032

    def test_derivation_data(self):
        assert Tag.DerivationData == 0x420030

    def test_lease_time(self):
        assert Tag.LeaseTime == 0x420049
