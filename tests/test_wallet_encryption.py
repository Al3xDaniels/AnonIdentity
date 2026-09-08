import copy

import pytest

from anon_identity.wallet import Wallet, encode_bytes
from anon_identity.wallet_encryption import (
    WalletEncryptionError,
    decrypt_wallet_document,
    encrypt_wallet_document,
    generate_recovery_phrase,
    recover_wallet,
    recovery_phrase_for_wallet,
)


def test_encrypted_wallet_round_trip_hides_plaintext() -> None:
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)
    document = {
        "root_secret": encode_bytes(wallet.root_secret),
        "services": {"forum.com": {"subject": "anon_example"}},
    }
    encrypted = encrypt_wallet_document(document, recovery_phrase)

    assert encrypted["format"] == "anon-identity-wallet"
    assert encrypted["version"] == 1
    assert encode_bytes(wallet.root_secret) not in str(encrypted)
    assert "forum.com" not in str(encrypted)
    assert decrypt_wallet_document(encrypted, recovery_phrase) == document


def test_wrong_recovery_phrase_is_rejected() -> None:
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)
    encrypted = encrypt_wallet_document(
        {"root_secret": encode_bytes(wallet.root_secret)},
        recovery_phrase,
    )

    with pytest.raises(WalletEncryptionError, match="authentication failed"):
        decrypt_wallet_document(encrypted, generate_recovery_phrase())


@pytest.mark.parametrize("field", ["revision", "ciphertext"])
def test_authenticated_wallet_mutation_is_rejected(field: str) -> None:
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)
    encrypted = encrypt_wallet_document(
        {"root_secret": encode_bytes(wallet.root_secret)},
        recovery_phrase,
    )
    modified = copy.deepcopy(encrypted)
    if field == "revision":
        modified[field] += 1
    else:
        modified[field] = ("A" if modified[field][0] != "A" else "B") + modified[field][1:]

    with pytest.raises(WalletEncryptionError, match="authentication failed"):
        decrypt_wallet_document(modified, recovery_phrase)


def test_recovery_phrase_restores_existing_wallet_identity() -> None:
    wallet = Wallet.generate()

    recovery_phrase = recovery_phrase_for_wallet(wallet)

    assert len(recovery_phrase.split()) == 24
    assert recover_wallet(recovery_phrase) == wallet