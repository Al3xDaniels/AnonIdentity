"""Encrypted wallet document persistence and metadata operations."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from anon_identity.age_assurance import StoredAgeCredential
from anon_identity.crypto import canonical_service_id
from anon_identity.keyring_store import KWalletError, KWalletSettings, write_kwallet_document
from anon_identity.wallet import Wallet, decode_bytes, encode_bytes
from anon_identity.wallet_encryption import (
    FORMAT_NAME,
    WalletEncryptionError,
    decrypt_wallet_document,
    encrypt_wallet_document,
)


def _write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    """Replace a wallet without exposing a partially written encrypted file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as temporary_file:
        json.dump(document, temporary_file, indent=2)
        temporary_file.write("\n")
        temporary_path = Path(temporary_file.name)
    temporary_path.chmod(0o600)
    temporary_path.replace(path)


def _load_encrypted_document(
    path: Path,
    recovery_phrase: str,
) -> tuple[dict[str, Any], int]:
    envelope = json.loads(path.read_text())
    if envelope.get("format") != FORMAT_NAME:
        raise WalletEncryptionError(
            "legacy plaintext wallet; run 'anon-wallet migrate' before using it"
        )
    return decrypt_wallet_document(envelope, recovery_phrase), envelope["revision"]


def persist_wallet_document(
    path: Path,
    document: dict[str, Any],
    recovery_phrase: str,
    *,
    revision: int,
) -> None:
    """Encrypt a wallet update and synchronize the same ciphertext to KWallet."""
    envelope = encrypt_wallet_document(document, recovery_phrase, revision=revision)
    _write_json_atomic(path, envelope)

    settings = KWalletSettings.from_document(document)
    if settings is not None:
        write_kwallet_document(envelope, settings)


def save_wallet(
    path: Path,
    wallet: Wallet,
    recovery_phrase: str,
    services: dict[str, Any] | None = None,
) -> None:
    """Create a new encrypted wallet with owner-only permissions."""
    document = {
        "root_secret": encode_bytes(wallet.root_secret),
        "services": services or {},
    }
    persist_wallet_document(path, document, recovery_phrase, revision=1)


def load_wallet(path: Path, recovery_phrase: str) -> Wallet:
    document, _ = _load_encrypted_document(path, recovery_phrase)
    return Wallet(decode_bytes(document["root_secret"]))


def record_service(path: Path, recovery_phrase: str, service_id: str, subject: str) -> None:
    """Record successful service activity without storing derived secret keys."""
    document, revision = _load_encrypted_document(path, recovery_phrase)
    services = document.setdefault("services", {})
    normalized_service = canonical_service_id(service_id)
    existing = services.get(normalized_service, {})
    now = datetime.now(UTC).isoformat()
    services[normalized_service] = {
        "subject": subject,
        "created_at": existing.get("created_at", now),
        "last_used_at": now,
        "label": existing.get("label", normalized_service),
    }
    persist_wallet_document(path, document, recovery_phrase, revision=revision + 1)


def record_age_credential(
    path: Path,
    recovery_phrase: str,
    credential: StoredAgeCredential,
) -> None:
    """Append an age credential to the encrypted wallet document."""
    document, revision = _load_encrypted_document(path, recovery_phrase)
    credentials = document.setdefault("age_credentials", [])
    credentials.append(
        {
            "issuer": credential.issuer,
            "format": credential.format,
            "assurance_level": credential.assurance_level,
            "jurisdiction": credential.jurisdiction,
            "age_over": sorted(credential.age_over),
            "expires_at": credential.expires_at,
            "credential": credential.credential,
        }
    )
    persist_wallet_document(path, document, recovery_phrase, revision=revision + 1)


def load_age_credentials(
    path: Path,
    recovery_phrase: str,
) -> list[StoredAgeCredential]:
    document, _ = _load_encrypted_document(path, recovery_phrase)
    return [
        StoredAgeCredential(
            issuer=item["issuer"],
            format=item["format"],
            assurance_level=item["assurance_level"],
            jurisdiction=item["jurisdiction"],
            age_over=frozenset(item["age_over"]),
            expires_at=item["expires_at"],
            credential=item["credential"],
        )
        for item in document.get("age_credentials", [])
    ]


def list_services(path: Path, recovery_phrase: str) -> dict[str, Any]:
    document, _ = _load_encrypted_document(path, recovery_phrase)
    return document.get("services", {})


def enable_keyring(
    path: Path,
    recovery_phrase: str,
    wallet_name: str = "kdewallet",
    folder: str = "Passwords",
) -> KWalletSettings:
    """Configure KWallet and mirror only the encrypted wallet envelope."""
    document, revision = _load_encrypted_document(path, recovery_phrase)
    wallet = Wallet(decode_bytes(document["root_secret"]))
    settings = KWalletSettings(
        wallet=wallet_name,
        folder=folder,
        entry=f"AnonIdentity - {wallet.wallet_id}",
    )
    document["keyring"] = settings.as_document()
    envelope = encrypt_wallet_document(document, recovery_phrase, revision=revision + 1)

    # Store the mirror first so failed KWallet access cannot half-enable syncing.
    write_kwallet_document(envelope, settings)
    _write_json_atomic(path, envelope)
    return settings


def sync_keyring(path: Path, recovery_phrase: str) -> KWalletSettings:
    envelope = json.loads(path.read_text())
    document, _ = _load_encrypted_document(path, recovery_phrase)
    settings = KWalletSettings.from_document(document)
    if settings is None:
        raise KWalletError("KWallet mirroring is not enabled for this wallet")
    write_kwallet_document(envelope, settings)
    return settings


def migrate_wallet(path: Path, recovery_phrase: str) -> Wallet:
    """Replace a legacy plaintext wallet with an encrypted version in place."""
    document = json.loads(path.read_text())
    if document.get("format") == FORMAT_NAME:
        raise WalletEncryptionError("wallet is already encrypted")
    wallet = Wallet(decode_bytes(document["root_secret"]))
    envelope = encrypt_wallet_document(document, recovery_phrase, revision=1)

    settings = KWalletSettings.from_document(document)
    if settings is not None:
        write_kwallet_document(envelope, settings)
    _write_json_atomic(path, envelope)
    return wallet