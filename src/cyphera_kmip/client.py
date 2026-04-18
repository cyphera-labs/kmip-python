"""
KMIP client -- connects to any KMIP 1.4 server via mTLS.

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

import os
import socket
import ssl
import struct

from .operations import (
    build_locate_request,
    build_get_request,
    build_create_request,
    parse_response,
    parse_locate_payload,
    parse_get_payload,
    parse_create_payload,
)
from .tags import Algorithm


class KmipClient:
    """
    KMIP client with mTLS support.

    Args:
        host: KMIP server hostname.
        port: KMIP server port (default 5696).
        client_cert: Path to client certificate PEM file.
        client_key: Path to client private key PEM file.
        ca_cert: Path to CA certificate PEM file (optional).
        timeout: Connection timeout in seconds (default 10).
    """

    def __init__(
        self,
        host: str,
        client_cert: str,
        client_key: str,
        port: int = 5696,
        ca_cert: str = None,
        timeout: int = 10,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None

        self._client_cert = client_cert
        self._client_key = client_key
        self._ca_cert = ca_cert

    def locate(self, name: str) -> list:
        """
        Locate keys by name.

        Args:
            name: Key name to search for.

        Returns:
            List of unique identifier strings.
        """
        request = build_locate_request(name)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_locate_payload(response["payload"])["unique_identifiers"]

    def get(self, unique_id: str) -> dict:
        """
        Get key material by unique ID.

        Args:
            unique_id: The unique identifier of the key.

        Returns:
            Dict with keys: object_type, unique_identifier, key_material.
        """
        request = build_get_request(unique_id)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_get_payload(response["payload"])

    def create(self, name: str, algorithm: str = None, length: int = 256) -> dict:
        """
        Create a new symmetric key on the server.

        Args:
            name: Key name.
            algorithm: Algorithm name (e.g., "AES"). Defaults to AES.
            length: Key length in bits. Defaults to 256.

        Returns:
            Dict with keys: object_type, unique_identifier.
        """
        algo_enum = Algorithm.AES
        if algorithm:
            algo_enum = getattr(Algorithm, algorithm, None) or getattr(
                Algorithm, algorithm.upper(), Algorithm.AES
            )
        request = build_create_request(name, algo_enum, length)
        response_data = self._send(request)
        response = parse_response(response_data)
        return parse_create_payload(response["payload"])

    def fetch_key(self, name: str) -> bytes:
        """
        Convenience: locate by name + get material in one call.

        Args:
            name: Key name.

        Returns:
            Raw key bytes.
        """
        ids = self.locate(name)
        if not ids:
            raise RuntimeError(f'KMIP: no key found with name "{name}"')
        result = self.get(ids[0])
        if not result["key_material"]:
            raise RuntimeError(
                f'KMIP: key "{name}" ({ids[0]}) has no extractable material'
            )
        return result["key_material"]

    def close(self):
        """Close the TLS connection."""
        if self._sock:
            self._sock.close()
            self._sock = None

    def _send(self, request: bytes) -> bytes:
        """Send a KMIP request and receive the response."""
        sock = self._connect()
        sock.sendall(request)

        # Read TTLV header (8 bytes) to determine total length
        header = self._recv_exact(sock, 8)
        value_length = struct.unpack(">I", header[4:8])[0]
        body = self._recv_exact(sock, value_length)
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
        if self._sock is not None:
            return self._sock

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(
            certfile=self._client_cert,
            keyfile=self._client_key,
        )
        if self._ca_cert:
            ctx.load_verify_locations(self._ca_cert)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        raw_sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        )
        self._sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        return self._sock
