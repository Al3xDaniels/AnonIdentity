import json

import pytest

from anon_identity.keyring_store import KWalletEnvelopeStore
from anon_identity.secure_storage import (
    SecureStorageError,
    configured_store,
    create_store,
    register_store,
)


def test_registered_backend_is_resolved_from_current_configuration() -> None:
    class MemoryStore:
        backend = "memory-test"

        def read(self, configuration):
            return {"slot": configuration["slot"]}

        def write(self, configuration, envelope):
            pass

    register_store("memory-test", MemoryStore)

    resolved = configured_store(
        {"secure_storage": {"backend": "memory-test", "slot": "alice"}}
    )

    assert resolved is not None
    store, configuration = resolved
    assert store.backend == "memory-test"
    assert store.read(configuration) == {"slot": "alice"}


def test_unknown_backend_is_rejected() -> None:
    with pytest.raises(SecureStorageError, match="unsupported"):
        create_store("does-not-exist")


def test_backend_registration_cannot_be_silently_replaced() -> None:
    class FirstStore:
        backend = "collision-test"

        def read(self, configuration):
            return {}

        def write(self, configuration, envelope):
            pass

    class ReplacementStore:
        backend = "collision-test"

        def read(self, configuration):
            return {}

        def write(self, configuration, envelope):
            pass

    register_store("collision-test", FirstStore)

    with pytest.raises(ValueError, match="already registered"):
        register_store("collision-test", ReplacementStore)


def test_kwallet_adapter_reads_and_writes_opaque_envelopes() -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.value = ""

        def read(self, settings) -> str:
            return self.value

        def write_and_verify(self, settings, value: str) -> None:
            self.value = value

    configuration = {
        "backend": "kwallet",
        "wallet": "kdewallet",
        "folder": "Passwords",
        "entry": "AnonIdentity - wallet_test",
    }
    envelope = {"format": "anon-identity-wallet", "ciphertext": "opaque"}
    client = FakeClient()
    store = KWalletEnvelopeStore(client)

    store.write(configuration, envelope)

    assert json.loads(client.value) == envelope
    assert store.read(configuration) == envelope