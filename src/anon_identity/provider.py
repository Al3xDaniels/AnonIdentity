"""SQLite-backed identity provider domain service."""

from __future__ import annotations

import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anon_identity.crypto import canonical_service_id, subject_for_public_key
from anon_identity.wallet import (
    WalletProof,
    build_attestation_message,
    build_challenge_message,
    decode_bytes,
    encode_bytes,
    wallet_id_for_public_key,
)


class AuthenticationError(ValueError):
    """Raised when enrollment or authentication data cannot be trusted."""


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    challenge: str
    service_id: str
    expires_at: int


class IdentityProvider:
    def __init__(self, database_path: str | Path, issuer_secret: str) -> None:
        if len(issuer_secret) < 32:
            raise ValueError("issuer_secret must contain at least 32 characters")
        self.database_path = str(database_path)
        self.issuer_secret = issuer_secret
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS wallets (
                    wallet_id TEXT PRIMARY KEY,
                    root_public_key BLOB NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS challenges (
                    challenge_id TEXT PRIMARY KEY,
                    wallet_id TEXT NOT NULL REFERENCES wallets(wallet_id),
                    service_id TEXT NOT NULL,
                    challenge BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                """
            )

    def enroll(self, wallet_id: str, encoded_root_public_key: str) -> None:
        root_public_key = decode_bytes(encoded_root_public_key)
        expected_wallet_id = wallet_id_for_public_key(root_public_key)
        if wallet_id != expected_wallet_id:
            raise AuthenticationError("wallet_id does not match the root public key")

        with self._connect() as connection:
            existing = connection.execute(
                "SELECT root_public_key FROM wallets WHERE wallet_id = ?", (wallet_id,)
            ).fetchone()
            if existing and existing["root_public_key"] != root_public_key:
                raise AuthenticationError("wallet_id is already enrolled")
            connection.execute(
                "INSERT OR IGNORE INTO wallets (wallet_id, root_public_key) VALUES (?, ?)",
                (wallet_id, root_public_key),
            )

    def create_challenge(self, wallet_id: str, service_id: str, lifetime_seconds: int = 300) -> Challenge:
        normalized_service = canonical_service_id(service_id)
        with self._connect() as connection:
            wallet = connection.execute(
                "SELECT revoked FROM wallets WHERE wallet_id = ?", (wallet_id,)
            ).fetchone()
        if wallet is None or wallet["revoked"]:
            raise AuthenticationError("wallet is unknown or revoked")

        challenge_id = str(uuid.uuid4())
        challenge_bytes = secrets.token_bytes(32)
        expires_at = int(time.time()) + lifetime_seconds
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO challenges VALUES (?, ?, ?, ?, ?, 0)",
                (challenge_id, wallet_id, normalized_service, challenge_bytes, expires_at),
            )
        return Challenge(challenge_id, encode_bytes(challenge_bytes), normalized_service, expires_at)

    def verify(self, challenge_id: str, proof: WalletProof) -> str:
        """Verify both signatures, consume the challenge, and issue a short-lived token."""
        with self._connect() as connection:
            record = connection.execute(
                """
                SELECT c.*, w.root_public_key, w.revoked
                FROM challenges c JOIN wallets w ON w.wallet_id = c.wallet_id
                WHERE c.challenge_id = ?
                """,
                (challenge_id,),
            ).fetchone()

        if record is None or record["used"] or record["revoked"]:
            raise AuthenticationError("challenge is unavailable")
        if record["expires_at"] < int(time.time()):
            raise AuthenticationError("challenge has expired")

        pairwise_public_key = decode_bytes(proof.pairwise_public_key)
        expected_subject = subject_for_public_key(record["service_id"], pairwise_public_key)
        if not secrets.compare_digest(proof.subject, expected_subject):
            raise AuthenticationError("subject does not match the pairwise public key")

        # Verification happens before the challenge is consumed. Ed25519 rejects any
        # changed service, key, challenge, or signature rather than trusting client data.
        try:
            Ed25519PublicKey.from_public_bytes(record["root_public_key"]).verify(
                decode_bytes(proof.root_attestation),
                build_attestation_message(record["service_id"], pairwise_public_key),
            )
            Ed25519PublicKey.from_public_bytes(pairwise_public_key).verify(
                decode_bytes(proof.challenge_signature),
                build_challenge_message(
                    challenge_id,
                    record["challenge"],
                    record["service_id"],
                    pairwise_public_key,
                ),
            )
        except (InvalidSignature, ValueError) as error:
            raise AuthenticationError("proof signature is invalid") from error

        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE challenges SET used = 1 WHERE challenge_id = ? AND used = 0",
                (challenge_id,),
            )
            if updated.rowcount != 1:
                raise AuthenticationError("challenge was already used")

        now = int(time.time())
        return jwt.encode(
            {
                "iss": "anon-identity",
                "sub": proof.subject,
                "aud": record["service_id"],
                "iat": now,
                "exp": now + 600,
            },
            self.issuer_secret,
            algorithm="HS256",
        )
