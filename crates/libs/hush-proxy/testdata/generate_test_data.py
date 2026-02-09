#!/usr/bin/env python3
"""Generate TLS ClientHello test data for SNI extraction tests."""

import struct

def build_client_hello(hostname: str | None = None) -> bytes:
    """Build a minimal TLS 1.2 ClientHello with optional SNI extension."""

    # Build extensions
    extensions = b''

    if hostname:
        # SNI extension (type 0x0000)
        hostname_bytes = hostname.encode('ascii')
        # SNI list: name_type (1) + name_length (2) + name
        sni_list = struct.pack('!BH', 0, len(hostname_bytes)) + hostname_bytes
        # SNI extension data: list_length (2) + list
        sni_data = struct.pack('!H', len(sni_list)) + sni_list
        # Extension: type (2) + length (2) + data
        extensions += struct.pack('!HH', 0, len(sni_data)) + sni_data

    # Add a dummy extension to make it more realistic (supported_versions)
    supported_versions = struct.pack('!HH', 0x002b, 3) + b'\x02\x03\x03'
    extensions += supported_versions

    # Build ClientHello body
    hello_body = b''
    hello_body += struct.pack('!H', 0x0303)  # Version: TLS 1.2
    hello_body += b'\x00' * 32               # Random (32 bytes)
    hello_body += b'\x00'                    # Session ID length (0)
    hello_body += struct.pack('!H', 2)       # Cipher suites length
    hello_body += struct.pack('!H', 0x1301)  # TLS_AES_128_GCM_SHA256
    hello_body += b'\x01\x00'                # Compression methods: null
    hello_body += struct.pack('!H', len(extensions))  # Extensions length
    hello_body += extensions

    # Build Handshake message
    handshake = b''
    handshake += b'\x01'                               # Type: ClientHello
    handshake += struct.pack('!I', len(hello_body))[1:]  # Length (3 bytes)
    handshake += hello_body

    # Build TLS record
    record = b''
    record += b'\x16'                           # Content type: Handshake
    record += struct.pack('!H', 0x0301)         # Version: TLS 1.0 (in record layer)
    record += struct.pack('!H', len(handshake)) # Record length
    record += handshake

    return record


def main():
    # Generate ClientHello with SNI
    with_sni = build_client_hello("example.com")
    with open("client_hello_example.bin", "wb") as f:
        f.write(with_sni)
    print(f"Generated client_hello_example.bin ({len(with_sni)} bytes)")

    # Generate ClientHello without SNI
    without_sni = build_client_hello(None)
    with open("client_hello_no_sni.bin", "wb") as f:
        f.write(without_sni)
    print(f"Generated client_hello_no_sni.bin ({len(without_sni)} bytes)")


if __name__ == "__main__":
    main()
