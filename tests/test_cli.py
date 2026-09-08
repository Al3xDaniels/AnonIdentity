import json

from anon_identity.cli import (
    enable_keyring,
    list_services,
    load_wallet,
    migrate_wallet,
    record_service,
    save_wallet,
)
from anon_identity.keyring_store import KWalletSettings, write_kwallet_document
from anon_identity.wallet import Wallet, encode_bytes
from anon_identity.wallet_encryption import (
    decrypt_wallet_document,
    generate_recovery_phrase,
    recover_wallet,
    recovery_phrase_for_wallet,
)


def test_new_wallet_file_contains_an_empty_service_catalog(tmp_path) -> None:
    path = tmp_path / "wallet.json"
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)

    save_wallet(path, wallet, recovery_phrase)

    envelope = json.loads(path.read_text())
    assert decrypt_wallet_document(envelope, recovery_phrase) == {
        "root_secret": encode_bytes(wallet.root_secret),
        "services": {},
    }
    assert "root_secret" not in envelope
    assert load_wallet(path, recovery_phrase) == wallet


def test_record_service_upgrades_old_wallet_and_preserves_creation_time(tmp_path) -> None:
    path = tmp_path / "wallet.json"
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)
    save_wallet(path, wallet, recovery_phrase)

    record_service(path, recovery_phrase, "FooFoo.COM", "anon_first")
    first_record = list_services(path, recovery_phrase)["foofoo.com"]
    record_service(path, recovery_phrase, "foofoo.com", "anon_first")
    second_record = list_services(path, recovery_phrase)["foofoo.com"]

    assert first_record["subject"] == "anon_first"
    assert second_record["created_at"] == first_record["created_at"]
    assert second_record["label"] == "foofoo.com"
    assert load_wallet(path, recovery_phrase) == wallet


def test_kwallet_adapter_writes_document_through_standard_input() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.calls = []

        def write_and_verify(self, settings, value) -> None:
            self.calls.append((settings, value))

    settings = KWalletSettings("kdewallet", "Passwords", "AnonIdentity - wallet_test")
    document = {"root_secret": "secret", "services": {}}
    client = FakeClient()

    write_kwallet_document(document, settings, client=client)

    written_settings, written_value = client.calls[0]
    assert written_settings == settings
    assert json.loads(written_value) == document


def test_enabling_keyring_adds_configuration_after_successful_write(tmp_path, monkeypatch) -> None:
    path = tmp_path / "wallet.json"
    recovery_phrase = generate_recovery_phrase()
    wallet = recover_wallet(recovery_phrase)
    save_wallet(path, wallet, recovery_phrase)
    mirrored_documents = []
    monkeypatch.setattr(
        "anon_identity.cli.write_kwallet_document",
        lambda document, settings: mirrored_documents.append(document.copy()),
    )

    settings = enable_keyring(path, recovery_phrase)

    envelope = json.loads(path.read_text())
    stored_document = decrypt_wallet_document(envelope, recovery_phrase)
    assert stored_document["keyring"] == settings.as_document()
    assert mirrored_documents[0] == envelope
    assert "root_secret" not in mirrored_documents[0]


def test_migrate_wallet_replaces_plaintext_without_changing_identity(tmp_path) -> None:
    path = tmp_path / "legacy.wallet.json"
    wallet = Wallet.generate()
    recovery_phrase = recovery_phrase_for_wallet(wallet)
    path.write_text(json.dumps({"root_secret": encode_bytes(wallet.root_secret), "services": {}}))

    migrated_wallet = migrate_wallet(path, recovery_phrase)

    envelope = json.loads(path.read_text())
    assert migrated_wallet == wallet
    assert "root_secret" not in envelope
    assert load_wallet(path, recovery_phrase) == wallet