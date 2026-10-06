"""Provider-neutral storage boundary for encrypted wallet envelopes."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from importlib.metadata import entry_points
from typing import Any, Protocol


class SecureStorageError(RuntimeError):
    """Raised when an encrypted envelope cannot be read or written."""


class EncryptedEnvelopeStore(Protocol):
    """Store opaque encrypted wallets without receiving decryption material."""

    backend: str

    def read(self, configuration: dict[str, Any]) -> dict[str, Any]: ...

    def write(
        self,
        configuration: dict[str, Any],
        envelope: dict[str, Any],
    ) -> None: ...


StoreFactory = Callable[[], EncryptedEnvelopeStore]
_STORE_FACTORIES: dict[str, StoreFactory] = {}
_PLUGINS_LOADED = False


def register_store(backend: str, factory: StoreFactory) -> None:
    """Register a secure-storage backend by its stable configuration name."""
    normalized_backend = backend.strip().lower()
    if not normalized_backend:
        raise ValueError("secure-storage backend must not be empty")
    existing_factory = _STORE_FACTORIES.get(normalized_backend)
    if existing_factory is not None and existing_factory is not factory:
        raise ValueError(f"secure-storage backend is already registered: {normalized_backend}")
    _STORE_FACTORIES[normalized_backend] = factory


def create_store(backend: str) -> EncryptedEnvelopeStore:
    """Create a configured backend without coupling callers to its implementation."""
    global _PLUGINS_LOADED
    normalized_backend = backend.strip().lower()
    if normalized_backend == "kwallet" and normalized_backend not in _STORE_FACTORIES:
        import_module("anon_identity.keyring_store")
    if not _PLUGINS_LOADED:
        for entry_point in entry_points(group="anon_identity.secure_storage"):
            register_store(entry_point.name, entry_point.load())
        _PLUGINS_LOADED = True
    try:
        factory = _STORE_FACTORIES[normalized_backend]
    except KeyError as error:
        raise SecureStorageError(f"unsupported secure-storage backend: {backend}") from error
    return factory()


def configured_store(document: dict[str, Any]) -> tuple[EncryptedEnvelopeStore, dict[str, Any]] | None:
    """Resolve current or legacy storage configuration from a wallet document."""
    configuration = document.get("secure_storage") or document.get("keyring")
    if not isinstance(configuration, dict):
        return None
    backend = configuration.get("backend")
    if not isinstance(backend, str):
        raise SecureStorageError("secure-storage configuration has no backend")
    return create_store(backend), configuration