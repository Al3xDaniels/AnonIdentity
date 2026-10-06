"""Command-line wallet for creating local identities and completing logins."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path
from typing import Any

from anon_identity.keyring_store import KWalletError
from anon_identity.wallet import decode_bytes, encode_bytes
from anon_identity.wallet_documents import (
    enable_keyring,
    list_services,
    load_wallet,
    migrate_wallet,
    record_service,
    save_wallet,
    sync_keyring,
)
from anon_identity.wallet_encryption import (
    WalletEncryptionError,
    generate_recovery_phrase,
    recover_wallet,
    recovery_phrase_for_wallet,
)


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
