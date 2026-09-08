"""Cryptographic building blocks for wallet-owned pairwise identities."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

DERIVATION_CONTEXT = b"anon-identity/pairwise-key/v1"


@dataclass(frozen=True)
class PairwiseIdentity:
    """A service-specific identifier and the key that controls it."""

    subject: str
    private_key: Ed25519PrivateKey

    @property
    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def canonical_service_id(service_id: str) -> str:
    """Normalize a service identifier so harmless casing changes do not change IDs."""
    normalized = service_id.strip().lower()
    if not normalized or any(character.isspace() for character in normalized):
        raise ValueError("service_id must be a non-empty identifier without whitespace")
    return normalized


def subject_for_public_key(service_id: str, public_key: bytes) -> str:
    """Build the pseudonymous subject a service receives for a public key."""
    normalized_service = canonical_service_id(service_id)
    digest = hashlib.sha256(normalized_service.encode("utf-8") + b"\x00" + public_key).digest()
    encoded_digest = base64.b32encode(digest[:15]).decode("ascii").rstrip("=").lower()
    return f"anon_{encoded_digest}"


def derive_pairwise_identity(root_secret: bytes, service_id: str) -> PairwiseIdentity:
    """Derive the wallet identity used only with one service.

    HKDF separates each service into its own cryptographic context. The root secret
    never leaves the wallet, and knowing one derived public key does not reveal the
    root secret or another service's key. This prototype requires 32 random bytes;
    production wallets should protect that secret with platform-backed secure storage.
    """
    if len(root_secret) != 32:
        raise ValueError("root_secret must contain exactly 32 bytes")

    normalized_service = canonical_service_id(service_id)
    derived_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=DERIVATION_CONTEXT + b"\x00" + normalized_service.encode("utf-8"),
    ).derive(root_secret)
    private_key = Ed25519PrivateKey.from_private_bytes(derived_seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # The service sees only this compact fingerprint. Including the service ID in
    # the hash prevents accidental reuse if key derivation rules change later.
    return PairwiseIdentity(
        subject=subject_for_public_key(normalized_service, public_key),
        private_key=private_key,
    )

