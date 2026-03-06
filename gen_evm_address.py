from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from ecdsa import SECP256k1, SigningKey


@dataclass
class EVMAddress:
    private_key: str
    public_key: str
    address: str



def _keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak  # pip install pycryptodome
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def _eip55_checksum(addr_bytes: bytes) -> str:
    """Apply EIP-55 mixed-case checksum encoding."""
    hex_addr: str = addr_bytes.hex()                  # lowercase hex, no prefix
    addr_hash: str = _keccak256(hex_addr.encode()).hex()

    checksummed: str = "0x"
    for i, ch in enumerate(hex_addr):
        if ch.isdigit():
            checksummed += ch
        elif int(addr_hash[i], 16) >= 8:
            checksummed += ch.upper()
        else:
            checksummed += ch.lower()
    return checksummed


def generate_evm_address() -> EVMAddress:
    # 1. Generate random 32-byte private key
    private_key: SigningKey = SigningKey.generate(curve=SECP256k1)
    priv_bytes: bytes = private_key.to_string()

    # 2. Derive uncompressed public key (64 bytes, no 0x04 prefix)
    pub_key: bytes = private_key.get_verifying_key().to_string()  # 64 bytes

    # 3. Keccak-256 hash of the public key
    pub_hash: bytes = _keccak256(pub_key)

    # 4. Take last 20 bytes
    raw_address: bytes = pub_hash[-20:]

    # 5. Hex encode
    address_lower: str = "0x" + raw_address.hex()

    # 6. Apply EIP-55 checksum
    address: str = _eip55_checksum(raw_address)

    return EVMAddress(
        private_key=f"0x{priv_bytes.hex()}",
        public_key=f"0x04{pub_key.hex()}",      # uncompressed with prefix
        address=address,
    )




if __name__ == "__main__":
    print("Generating EVM (ERC20-compatible) address...\n")
    result: EVMAddress = generate_evm_address()
    print(f"Private Key : {result.private_key}")
    print(f"Public Key  : {result.public_key}")
    print(f"Address     : {result.address}")
    print("\n⚠️  Keep your private key secret! Never share it.")
