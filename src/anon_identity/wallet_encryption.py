"""Versioned, authenticated encryption for portable wallet documents."""

from __future__ import annotations

import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from mnemonic import Mnemonic

from anon_identity.wallet import Wallet, decode_bytes, encode_bytes

FORMAT_NAME = "anon-identity-wallet"
FORMAT_VERSION = 1
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class WalletEncryptionError(ValueError):
    """Raised when an encrypted wallet cannot be safely decoded."""


def generate_recovery_phrase() -> str:
    """Generate a checksum-protected 24-word phrase with 256 bits of entropy."""
    return Mnemonic("english").generate(strength=256)


def recovery_phrase_for_wallet(wallet: Wallet) -> str:
    """Encode an existing wallet root as a checksum-protected 24-word phrase."""
    return Mnemonic("english").to_mnemonic(wallet.root_secret)


def recover_wallet(recovery_phrase: str) -> Wallet:
    """Restore the root identity represented by a recovery phrase."""
    return Wallet(_recovery_entropy(recovery_phrase))


def _recovery_entropy(recovery_phrase: str) -> bytes:
    normalized_phrase = Mnemonic.normalize_string(recovery_phrase.strip())
    mnemonic = Mnemonic("english")
    if not mnemonic.check(normalized_phrase):
        raise WalletEncryptionError("recovery phrase is invalid")
    return bytes(mnemonic.to_entropy(normalized_phrase))


def _derive_key(recovery_phrase: str, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(_recovery_entropy(recovery_phrase))


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_wallet_document(
    document: dict[str, Any],
    recovery_phrase: str,
    *,
    revision: int = 1,
) -> dict[str, Any]:
    """Encrypt all wallet secrets and metadata in a portable JSON envelope."""
    if revision < 1:
        raise WalletEncryptionError("wallet revision must be positive")
    try:
        root_secret = decode_bytes(document["root_secret"])
    except (KeyError, TypeError, ValueError) as error:
        raise WalletEncryptionError("wallet payload has no valid root secret") from error
    if root_secret != _recovery_entropy(recovery_phrase):
        raise WalletEncryptionError("recovery phrase does not represent this wallet")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    header: dict[str, Any] = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "revision": revision,
        "kdf": {
            "name": "scrypt",
            "salt": encode_bytes(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": encode_bytes(nonce),
        },
    }
    ciphertext = AESGCM(_derive_key(recovery_phrase, salt)).encrypt(
        nonce,
        _canonical_json(document),
        _canonical_json(header),
    )
    return {**header, "ciphertext": encode_bytes(ciphertext)}


def decrypt_wallet_document(
    envelope: dict[str, Any],
    recovery_phrase: str,
) -> dict[str, Any]:
    """Authenticate and decrypt a version 1 wallet envelope."""
    try:
        if envelope["format"] != FORMAT_NAME or envelope["version"] != FORMAT_VERSION:
            raise WalletEncryptionError("unsupported wallet format or version")
        if envelope["revision"] < 1:
            raise WalletEncryptionError("wallet revision must be positive")

        kdf = envelope["kdf"]
        cipher = envelope["cipher"]
        if kdf["name"] != "scrypt" or cipher["name"] != "aes-256-gcm":
            raise WalletEncryptionError("unsupported wallet encryption parameters")
        if (kdf["n"], kdf["r"], kdf["p"]) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
            raise WalletEncryptionError("unsupported scrypt parameters")

        header = {key: value for key, value in envelope.items() if key != "ciphertext"}
        plaintext = AESGCM(
            _derive_key(recovery_phrase, decode_bytes(kdf["salt"]))
        ).decrypt(
            decode_bytes(cipher["nonce"]),
            decode_bytes(envelope["ciphertext"]),
            _canonical_json(header),
        )
        document = json.loads(plaintext)
        if not isinstance(document, dict) or "root_secret" not in document:
            raise WalletEncryptionError("decrypted wallet payload is invalid")
        return document
    except WalletEncryptionError:
        raise
    except (InvalidTag, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise WalletEncryptionError(
            "wallet authentication failed; the phrase is wrong or the file was modified"
        ) from error