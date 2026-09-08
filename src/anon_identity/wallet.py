# Local wallet operations; 
# root secrets must never be sent to the provider

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anon_identity.crypto import canonical_service_id, derive_pairwise_identity


def encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_bytes(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def wallet_id_for_public_key(root_public_key: bytes) -> str:
    digest = hashlib.sha256(root_public_key).digest()
    return "wallet_" + base64.b32encode(digest[:15]).decode("ascii").rstrip("=").lower()


def build_attestation_message(service_id: str, pairwise_public_key: bytes) -> bytes:
    normalized_service = canonical_service_id(service_id)
    return b"anon-identity/attestation/v1\x00" + normalized_service.encode() + b"\x00" + pairwise_public_key


def build_challenge_message(
    challenge_id: str,
    challenge: bytes,
    service_id: str,
    pairwise_public_key: bytes,
) -> bytes:
    normalized_service = canonical_service_id(service_id)
    return b"\x00".join(
        (
            b"anon-identity/challenge/v1",
            challenge_id.encode(),
            challenge,
            normalized_service.encode(),
            pairwise_public_key,
        )
    )


@dataclass(frozen=True)
class WalletProof:
    subject: str
    pairwise_public_key: str
    root_attestation: str
    challenge_signature: str


@dataclass(frozen=True)
class Wallet:
    """A wallet whose 32-byte root secret remains on the user's device."""

    root_secret: bytes

    def __post_init__(self) -> None:
        if len(self.root_secret) != 32:
            raise ValueError("root_secret must contain exactly 32 bytes")

    @classmethod
    def generate(cls) -> Wallet:
        return cls(os.urandom(32))

    @property
    def root_private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.root_secret)

    @property
    def root_public_key(self) -> bytes:
        return self.root_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def wallet_id(self) -> str:
        return wallet_id_for_public_key(self.root_public_key)

    def prove(self, challenge_id: str, challenge: str, service_id: str) -> WalletProof:
        """Answer a provider challenge without disclosing the wallet root secret.

        The root signature certifies that this wallet authorized the service-specific
        key. The second signature proves current control of that key and binds it to
        this exact challenge, preventing a captured response from being reused.
        """
        pairwise_identity = derive_pairwise_identity(self.root_secret, service_id)
        pairwise_public_key = pairwise_identity.public_key_bytes
        challenge_bytes = decode_bytes(challenge)

        root_attestation = self.root_private_key.sign(
            build_attestation_message(service_id, pairwise_public_key)
        )
        challenge_signature = pairwise_identity.private_key.sign(
            build_challenge_message(
                challenge_id,
                challenge_bytes,
                service_id,
                pairwise_public_key,
            )
        )
        return WalletProof(
            subject=pairwise_identity.subject,
            pairwise_public_key=encode_bytes(pairwise_public_key),
            root_attestation=encode_bytes(root_attestation),
            challenge_signature=encode_bytes(challenge_signature),
        )
