"""Encrypted wallet repositories used by local clients and storage adapters."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Protocol

from anon_identity.secure_storage import EncryptedEnvelopeStore


class WalletRepository(Protocol):
    """Read and replace opaque encrypted wallet envelopes."""

    backend: str

    def read(self) -> dict[str, Any]: ...

    def write(self, envelope: dict[str, Any]) -> None: ...


class FileWalletRepository:
    backend = "file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self) -> dict[str, Any]:
        document = json.loads(self.path.read_text())
        if not isinstance(document, dict):
            raise ValueError("wallet envelope is not a JSON object")
        return document

    def write(self, envelope: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            delete=False,
        ) as temporary_file:
            json.dump(envelope, temporary_file, indent=2)
            temporary_file.write("\n")
            temporary_path = Path(temporary_file.name)
        temporary_path.chmod(0o600)
        temporary_path.replace(self.path)


class SecureStoreWalletRepository:
    def __init__(
        self,
        store: EncryptedEnvelopeStore,
        configuration: dict[str, Any],
    ) -> None:
        self.store = store
        self.configuration = configuration
        self.backend = store.backend

    def read(self) -> dict[str, Any]:
        return self.store.read(self.configuration)

    def write(self, envelope: dict[str, Any]) -> None:
        self.store.write(self.configuration, envelope)