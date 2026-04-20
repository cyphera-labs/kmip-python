"""
KMIP client -- connects to any KMIP 1.4 server via mTLS.
Full 27-operation client matching kmip-go reference.

Usage:
    client = KmipClient(
        host="kmip-server.corp.internal",
        client_cert="/path/to/client.pem",
        client_key="/path/to/client-key.pem",
        ca_cert="/path/to/ca.pem",
    )

    key = client.fetch_key("my-key-name")
    # key is bytes of raw key material

    client.close()
"""

import socket
import ssl
import struct

from .operations import (
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
)
from .tags import Algorithm, Tag
from .ttlv import find_child, find_children


# Algorithm name -> enum value mapping
_ALGORITHM_MAP = {
    "AES": Algorithm.AES,
    "DES": Algorithm.DES,
    "TRIPLEDES": Algorithm.TripleDES,
    "3DES": Algorithm.TripleDES,
    "RSA": Algorithm.RSA,
    "DSA": Algorithm.DSA,
    "ECDSA": Algorithm.ECDSA,
    "HMACSHA1": Algorithm.HMACSHA1,
    "HMACSHA256": Algorithm.HMACSHA256,
    "HMACSHA384": Algorithm.HMACSHA384,
    "HMACSHA512": Algorithm.HMACSHA512,
}


def resolve_algorithm(name: str) -> int:
    """Convert an algorithm name string to its KMIP enum value. Raises ValueError for unknown."""
    # M3: Reject unknown algorithms instead of silently returning 0
    result = _ALGORITHM_MAP.get(name.upper())
    if result is None:
        raise ValueError(f"Unknown KMIP algorithm: {name!r}")
    return result


class KmipClient:
    """
    KMIP client with mTLS support.

    Args:
        host: KMIP server hostname.
        port: KMIP server port (default 5696).
        client_cert: Path to client certificate PEM file.
        client_key: Path to client private key PEM file.
        ca_cert: Path to CA certificate PEM file (optional, uses system roots if empty).
        timeout: Connection timeout in seconds (default 10).
        insecure_skip_verify: DANGER: disables server certificate verification (default False).
    """

    # Maximum KMIP response size (16MB).
    MAX_RESPONSE_SIZE = 16 * 1024 * 1024

    def __init__(
        self,
        host: str,
        client_cert: str,
        client_key: str,
        port: int = 5696,
        ca_cert: str = None,
        timeout: int = 10,
        insecure_skip_verify: bool = False,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None
        self._insecure_skip_verify = insecure_skip_verify
        self._credential = None  # KMIP auth credential (username, password)
        self._server_cert_fingerprint = None  # L1: Optional cert pinning (SHA-256 hex)
        self._lock = __import__("threading").Lock()  # M5: Thread safety

        # H1: Warn on insecure mode
        if insecure_skip_verify:
            import warnings
            warnings.warn(
                "KmipClient: insecure_skip_verify=True disables TLS certificate verification. "
                "NEVER use in production.",
                stacklevel=2,
            )

        self._client_cert = client_cert
        self._client_key = client_key
        self._ca_cert = ca_cert

    def set_credentials(self, username: str, password: str):
        """Set KMIP authentication credentials (UsernameAndPassword)."""
        self._credential = (username, password)

    def set_server_cert_fingerprint(self, fingerprint: str):
        """L1: Set expected server certificate SHA-256 fingerprint for pinning."""
        self._server_cert_fingerprint = fingerprint.lower().replace(":", "")

    # ------------------------------------------------------------------
    # 27 operations
    # ------------------------------------------------------------------

    def locate(self, name: str) -> list:
        """Locate keys by name. Returns list of unique identifier strings."""
        request = build_locate_request(name)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_locate_payload(response["payload"])["unique_identifiers"]

    def get(self, unique_id: str) -> dict:
        """Get key material by unique ID."""
        request = build_get_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_get_payload(response["payload"])

    def create(self, name: str, algorithm: str = None, length: int = 256) -> dict:
        """Create a new symmetric key on the server."""
        algo_enum = Algorithm.AES
        if algorithm:
            resolved = resolve_algorithm(algorithm)
            if resolved:
                algo_enum = resolved
        request = build_create_request(name, algo_enum, length)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_create_payload(response["payload"])

    def activate(self, unique_id: str) -> None:
        """Set a key's state to Active."""
        request = build_activate_request(unique_id)
        response_data = self._send(request)
        parse_response(response_data)

    def destroy(self, unique_id: str) -> None:
        """Destroy a key by unique ID."""
        request = build_destroy_request(unique_id)
        response_data = self._send(request)
        parse_response(response_data)

    def create_key_pair(self, name: str, algorithm: int, length: int) -> dict:
        """Create a new asymmetric key pair on the server."""
        request = build_create_key_pair_request(name, algorithm, length)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_create_key_pair_payload(response["payload"])

    def register(self, object_type: int, material: bytes, name: str, algorithm: int, length: int) -> dict:
        """Register existing key material on the server."""
        request = build_register_request(object_type, material, name, algorithm, length)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_create_payload(response["payload"])

    def re_key(self, unique_id: str) -> dict:
        """Re-key an existing key on the server."""
        request = build_re_key_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_re_key_payload(response["payload"])

    def derive_key(self, unique_id: str, derivation_data: bytes, name: str, length: int) -> dict:
        """Derive a new key from an existing key."""
        request = build_derive_key_request(unique_id, derivation_data, name, length)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_derive_key_payload(response["payload"])

    def check(self, unique_id: str) -> dict:
        """Check the status of a managed object."""
        request = build_check_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_check_payload(response["payload"])

    def get_attributes(self, unique_id: str) -> dict:
        """Fetch all attributes of a managed object."""
        request = build_get_attributes_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_get_payload(response["payload"])

    def get_attribute_list(self, unique_id: str) -> list:
        """Fetch the list of attribute names for a managed object."""
        request = build_get_attribute_list_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        payload = response["payload"]
        if payload is None:
            return []
        attrs = find_children(payload, Tag.AttributeName)
        return [attr["value"] for attr in attrs]

    def add_attribute(self, unique_id: str, name: str, value: str) -> None:
        """Add an attribute to a managed object."""
        request = build_add_attribute_request(unique_id, name, value)
        response_data = self._send(request)
        parse_response(response_data)

    def modify_attribute(self, unique_id: str, name: str, value: str) -> None:
        """Modify an attribute of a managed object."""
        request = build_modify_attribute_request(unique_id, name, value)
        response_data = self._send(request)
        parse_response(response_data)

    def delete_attribute(self, unique_id: str, name: str) -> None:
        """Delete an attribute from a managed object."""
        request = build_delete_attribute_request(unique_id, name)
        response_data = self._send(request)
        parse_response(response_data)

    def obtain_lease(self, unique_id: str) -> int:
        """Obtain a lease for a managed object. Returns lease time in seconds."""
        request = build_obtain_lease_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_obtain_lease_payload(response["payload"])["lease_time"]

    def revoke(self, unique_id: str, reason: int) -> None:
        """Revoke a managed object with the given reason code."""
        request = build_revoke_request(unique_id, reason)
        response_data = self._send(request)
        parse_response(response_data)

    def archive(self, unique_id: str) -> None:
        """Archive a managed object."""
        request = build_archive_request(unique_id)
        response_data = self._send(request)
        parse_response(response_data)

    def recover(self, unique_id: str) -> None:
        """Recover an archived managed object."""
        request = build_recover_request(unique_id)
        response_data = self._send(request)
        parse_response(response_data)

    def query(self) -> dict:
        """Query the server for supported operations and object types."""
        request = build_query_request()
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_query_payload(response["payload"])

    def poll(self) -> None:
        """Poll the server."""
        request = build_poll_request()
        response_data = self._send(request)
        parse_response(response_data)

    def discover_versions(self) -> dict:
        """Discover the KMIP versions supported by the server."""
        request = build_discover_versions_request()
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_discover_versions_payload(response["payload"])

    def encrypt(self, unique_id: str, data: bytes) -> dict:
        """Encrypt data using a managed key."""
        request = build_encrypt_request(unique_id, data)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_encrypt_payload(response["payload"])

    def decrypt(self, unique_id: str, data: bytes, nonce: bytes = None) -> dict:
        """Decrypt data using a managed key."""
        request = build_decrypt_request(unique_id, data, nonce)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_decrypt_payload(response["payload"])

    def sign(self, unique_id: str, data: bytes) -> dict:
        """Sign data using a managed key."""
        request = build_sign_request(unique_id, data)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_sign_payload(response["payload"])

    def signature_verify(self, unique_id: str, data: bytes, signature: bytes) -> dict:
        """Verify a signature using a managed key."""
        request = build_signature_verify_request(unique_id, data, signature)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_signature_verify_payload(response["payload"])

    def mac(self, unique_id: str, data: bytes) -> dict:
        """Compute a MAC using a managed key."""
        request = build_mac_request(unique_id, data)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_mac_payload(response["payload"])

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def fetch_key(self, name: str) -> bytes:
        """Convenience: locate by name + get material in one call."""
        ids = self.locate(name)
        if not ids:
            raise RuntimeError(f'KMIP: no key found with name "{name}"')
        result = self.get(ids[0])
        if not result["key_material"]:
            raise RuntimeError(
                f'KMIP: key "{name}" ({ids[0]}) has no extractable material'
            )
        return result["key_material"]

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def close(self):
        """Close the TLS connection."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def _send(self, request: bytes) -> bytes:
        """Send a KMIP request and receive the response."""
        sock = self._connect()
        try:
            sock.sendall(request)
        except OSError:
            self._sock = None  # Mark connection as stale.
            raise

        # Read TTLV header (8 bytes) to determine total length
        try:
            header = self._recv_exact(sock, 8)
        except (OSError, ConnectionError):
            self._sock = None  # Mark connection as stale.
            raise

        value_length = struct.unpack(">I", header[4:8])[0]

        # Validate response size before allocating.
        if value_length > self.MAX_RESPONSE_SIZE:
            self._sock = None  # Mark connection as stale.
            raise RuntimeError(
                f"KMIP: response too large ({value_length} bytes, max {self.MAX_RESPONSE_SIZE})"
            )

        try:
            body = self._recv_exact(sock, value_length)
        except (OSError, ConnectionError):
            self._sock = None  # Mark connection as stale.
            raise

        return header + body

    def _recv_exact(self, sock, n: int) -> bytes:
        """Receive exactly n bytes from the socket."""
        data = bytearray()
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("KMIP connection closed unexpectedly")
            data.extend(chunk)
        return bytes(data)

    def _connect(self):
        """Establish or reuse the mTLS connection."""
        with self._lock:  # M5: Thread safety
            if self._sock is not None:
                return self._sock

            ctx = ssl.create_default_context()
            # M2: Explicit TLS version floor
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(
                certfile=self._client_cert,
                keyfile=self._client_key,
            )
            if self._ca_cert:
                ctx.load_verify_locations(self._ca_cert)

            if self._insecure_skip_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
            self._sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)

            # L1: Certificate pinning
            if self._server_cert_fingerprint:
                import hashlib
                der = self._sock.getpeercert(binary_form=True)
                fp = hashlib.sha256(der).hexdigest()
                if fp != self._server_cert_fingerprint:
                    self._sock.close()
                    self._sock = None
                    raise ssl.SSLError(
                        f"Server certificate fingerprint mismatch (expected {self._server_cert_fingerprint}, got {fp})"
                    )

            return self._sock
