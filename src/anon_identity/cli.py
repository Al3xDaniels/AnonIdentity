"""Command-line wallet for creating local identities and completing logins."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict
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
    generate_recovery_phrase,
    recover_wallet,
    recovery_phrase_for_wallet,
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


def _load_encrypted_document(path: Path, recovery_phrase: str) -> tuple[dict[str, Any], int]:
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
    """Store useful account metadata while continuing to derive secret child keys.

    We retain `created_at` across logins and update `last_used_at` only after the
    provider accepts a proof, so failed attempts do not appear as successful
    service activity.
    """
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


def _add_unlock_option(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--recovery-phrase-file",
        type=Path,
        help="read the recovery phrase from a file instead of prompting",
    )


def _read_recovery_phrase(arguments: argparse.Namespace) -> str:
    phrase_file = getattr(arguments, "recovery_phrase_file", None)
    if phrase_file is not None:
        return phrase_file.read_text().strip()
    environment_phrase = os.environ.get("ANON_IDENTITY_RECOVERY_PHRASE")
    if environment_phrase:
        return environment_phrase.strip()
    return getpass.getpass("Recovery phrase: ").strip()


def _write_recovery_phrase(path: Path, recovery_phrase: str) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SystemExit(f"Refusing to overwrite recovery phrase: {path}")
    with os.fdopen(descriptor, "w") as recovery_file:
        recovery_file.write(recovery_phrase + "\n")


def request_json(method: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode()
        raise SystemExit(f"Provider rejected the request ({error.code}): {detail}") from error


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="anon-wallet")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="create a local wallet file")
    create.add_argument("wallet_file", type=Path)
    create.add_argument("--recovery-output", type=Path)

    migrate = commands.add_parser("migrate", help="encrypt a legacy plaintext wallet")
    migrate.add_argument("wallet_file", type=Path)
    migrate.add_argument("--recovery-output", type=Path)

    restore = commands.add_parser("restore", help="restore an identity from its recovery phrase")
    restore.add_argument("wallet_file", type=Path)
    _add_unlock_option(restore)

    enroll = commands.add_parser("enroll", help="enroll the wallet's public key")
    enroll.add_argument("wallet_file", type=Path)
    enroll.add_argument("--provider", default="http://localhost:8000")
    _add_unlock_option(enroll)

    login = commands.add_parser("login", help="complete a login challenge")
    login.add_argument("wallet_file", type=Path)
    login.add_argument("--service", required=True)
    login.add_argument("--provider", default="http://localhost:8000")
    login.add_argument("--token-only", action="store_true")
    _add_unlock_option(login)

    services = commands.add_parser("services", help="list service identities known to the wallet")
    services.add_argument("wallet_file", type=Path)
    _add_unlock_option(services)

    keyring_enable = commands.add_parser("keyring-enable", help="mirror a JSON wallet into KDE Wallet")
    keyring_enable.add_argument("wallet_file", type=Path)
    keyring_enable.add_argument("--wallet", default="kdewallet", dest="kwallet_name")
    keyring_enable.add_argument("--folder", default="Passwords")
    _add_unlock_option(keyring_enable)

    keyring_sync = commands.add_parser("keyring-sync", help="rewrite the configured KDE Wallet mirror")
    keyring_sync.add_argument("wallet_file", type=Path)
    _add_unlock_option(keyring_sync)
    return parser


def _run(arguments: argparse.Namespace) -> None:
    if arguments.command == "create":
        if arguments.wallet_file.exists():
            raise SystemExit(f"Refusing to overwrite existing wallet: {arguments.wallet_file}")
        recovery_phrase = generate_recovery_phrase()
        wallet = recover_wallet(recovery_phrase)
        if arguments.recovery_output is not None:
            _write_recovery_phrase(arguments.recovery_output, recovery_phrase)
        save_wallet(arguments.wallet_file, wallet, recovery_phrase)
        result = {"wallet_id": wallet.wallet_id, "wallet_file": str(arguments.wallet_file)}
        if arguments.recovery_output is None:
            result["recovery_phrase"] = recovery_phrase
        else:
            result["recovery_phrase_file"] = str(arguments.recovery_output)
        print(json.dumps(result))
        return

    if arguments.command == "migrate":
        legacy_document = json.loads(arguments.wallet_file.read_text())
        legacy_wallet = Wallet(decode_bytes(legacy_document["root_secret"]))
        recovery_phrase = recovery_phrase_for_wallet(legacy_wallet)
        if arguments.recovery_output is not None:
            _write_recovery_phrase(arguments.recovery_output, recovery_phrase)
        wallet = migrate_wallet(arguments.wallet_file, recovery_phrase)
        result = {"wallet_id": wallet.wallet_id, "wallet_file": str(arguments.wallet_file)}
        if arguments.recovery_output is None:
            result["recovery_phrase"] = recovery_phrase
        else:
            result["recovery_phrase_file"] = str(arguments.recovery_output)
        print(json.dumps(result))
        return

    recovery_phrase = _read_recovery_phrase(arguments)

    if arguments.command == "restore":
        if arguments.wallet_file.exists():
            raise SystemExit(f"Refusing to overwrite existing wallet: {arguments.wallet_file}")
        wallet = recover_wallet(recovery_phrase)
        save_wallet(arguments.wallet_file, wallet, recovery_phrase)
        print(json.dumps({"wallet_id": wallet.wallet_id, "wallet_file": str(arguments.wallet_file)}))
        return

    if arguments.command == "services":
        print(json.dumps(list_services(arguments.wallet_file, recovery_phrase), indent=2))
        return

    if arguments.command in {"keyring-enable", "keyring-sync"}:
        try:
            if arguments.command == "keyring-enable":
                settings = enable_keyring(
                    arguments.wallet_file,
                    recovery_phrase,
                    arguments.kwallet_name,
                    arguments.folder,
                )
            else:
                settings = sync_keyring(arguments.wallet_file, recovery_phrase)
        except KWalletError as error:
            raise SystemExit(f"Could not update KDE Wallet: {error}") from error
        print(json.dumps({"status": "synchronized", **settings.as_document()}))
        return

    wallet = load_wallet(arguments.wallet_file, recovery_phrase)
    provider_url = arguments.provider.rstrip("/")
    if arguments.command == "enroll":
        result = request_json(
            "POST",
            f"{provider_url}/v1/wallets",
            {"wallet_id": wallet.wallet_id, "root_public_key": encode_bytes(wallet.root_public_key)},
        )
        print(json.dumps(result))
        return

    # A login performs three protocol steps: request a fresh challenge, sign it
    # locally with pairwise keys, then exchange the proof for a short-lived token.
    challenge = request_json(
        "POST",
        f"{provider_url}/v1/challenges",
        {"wallet_id": wallet.wallet_id, "service_id": arguments.service},
    )
    proof = wallet.prove(challenge["challenge_id"], challenge["challenge"], challenge["service_id"])
    result = request_json(
        "POST",
        f"{provider_url}/v1/challenges/{challenge['challenge_id']}/verify",
        asdict(proof),
    )
    try:
        record_service(
            arguments.wallet_file,
            recovery_phrase,
            challenge["service_id"],
            proof.subject,
        )
    except KWalletError as error:
        raise SystemExit(f"Login succeeded, but the KDE Wallet mirror failed: {error}") from error
    print(result["access_token"] if arguments.token_only else json.dumps(result))


def main() -> None:
    arguments = create_parser().parse_args()
    try:
        _run(arguments)
    except WalletEncryptionError as error:
        raise SystemExit(f"Could not unlock wallet: {error}") from error


if __name__ == "__main__":
    main()
