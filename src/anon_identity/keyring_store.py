"""Native KDE Wallet integration for mirroring a development wallet."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Protocol, cast

from dbus_next.aio.message_bus import MessageBus

from anon_identity.secure_storage import SecureStorageError, register_store

KWALLET_SERVICE = "org.kde.kwalletd6"
KWALLET_PATH = "/modules/kwalletd6"
KWALLET_INTERFACE = "org.kde.KWallet"
APPLICATION_ID = "AnonIdentity"


class KWalletError(RuntimeError):
    """Raised when KDE Wallet cannot store the mirrored wallet."""


@dataclass(frozen=True)
class KWalletSettings:
    wallet: str
    folder: str
    entry: str

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> KWalletSettings | None:
        configuration = document.get("keyring")
        if not isinstance(configuration, dict):
            return None
        return cls.from_configuration(configuration)

    @classmethod
    def from_configuration(cls, configuration: dict[str, Any]) -> KWalletSettings | None:
        if configuration.get("backend") != "kwallet":
            return None
        return cls(
            wallet=configuration.get("wallet", "kdewallet"),
            folder=configuration.get("folder", "Passwords"),
            entry=configuration["entry"],
        )

    def as_document(self) -> dict[str, str]:
        return {
            "backend": "kwallet",
            "wallet": self.wallet,
            "folder": self.folder,
            "entry": self.entry,
        }


class KWalletClient(Protocol):
    def write_and_verify(self, settings: KWalletSettings, value: str) -> None: ...

    def read(self, settings: KWalletSettings) -> str: ...


class KWalletProxy(Protocol):
    """Typed view of methods generated dynamically from KWallet introspection."""

    async def call_open(self, wallet: str, window_id: int, application_id: str) -> int: ...
    async def call_has_folder(self, handle: int, folder: str, application_id: str) -> bool: ...
    async def call_create_folder(self, handle: int, folder: str, application_id: str) -> bool: ...
    async def call_write_password(
        self, handle: int, folder: str, entry: str, value: str, application_id: str
    ) -> int: ...
    async def call_read_password(
        self, handle: int, folder: str, entry: str, application_id: str
    ) -> str: ...


class NativeKWalletClient:
    """Small D-Bus client for password entries displayed by KWallet Manager."""

    def write_and_verify(self, settings: KWalletSettings, value: str) -> None:
        asyncio.run(self._write_and_verify(settings, value))

    def read(self, settings: KWalletSettings) -> str:
        return asyncio.run(self._read(settings))

    async def _write_and_verify(self, settings: KWalletSettings, value: str) -> None:
        try:
            bus = await MessageBus().connect()
            introspection = await bus.introspect(KWALLET_SERVICE, KWALLET_PATH)
            proxy = bus.get_proxy_object(KWALLET_SERVICE, KWALLET_PATH, introspection)
            wallet = cast(KWalletProxy, proxy.get_interface(KWALLET_INTERFACE))
            handle = await wallet.call_open(settings.wallet, 0, APPLICATION_ID)
            if handle < 0:
                raise KWalletError("KWallet could not be opened")

            # A dedicated folder makes the protected mirror easy to find in the GUI.
            if not await wallet.call_has_folder(handle, settings.folder, APPLICATION_ID):
                if not await wallet.call_create_folder(handle, settings.folder, APPLICATION_ID):
                    raise KWalletError(f"KWallet folder could not be created: {settings.folder}")

            result = await wallet.call_write_password(
                handle,
                settings.folder,
                settings.entry,
                value,
                APPLICATION_ID,
            )
            if result != 0:
                raise KWalletError(f"KWallet rejected the write with status {result}")
            if await wallet.call_read_password(
                handle,
                settings.folder,
                settings.entry,
                APPLICATION_ID,
            ) != value:
                raise KWalletError("KWallet did not preserve the mirrored wallet document")
        except KWalletError:
            raise
        except Exception as error:
            raise KWalletError(f"KWallet D-Bus operation failed: {error}") from error

    async def _read(self, settings: KWalletSettings) -> str:
        try:
            bus = await MessageBus().connect()
            introspection = await bus.introspect(KWALLET_SERVICE, KWALLET_PATH)
            proxy = bus.get_proxy_object(KWALLET_SERVICE, KWALLET_PATH, introspection)
            wallet = cast(KWalletProxy, proxy.get_interface(KWALLET_INTERFACE))
            handle = await wallet.call_open(settings.wallet, 0, APPLICATION_ID)
            if handle < 0:
                raise KWalletError("KWallet could not be opened")
            value = await wallet.call_read_password(
                handle,
                settings.folder,
                settings.entry,
                APPLICATION_ID,
            )
            if not value:
                raise KWalletError(f"KWallet entry was empty or missing: {settings.entry}")
            return value
        except KWalletError:
            raise
        except Exception as error:
            raise KWalletError(f"KWallet D-Bus operation failed: {error}") from error


class KWalletEnvelopeStore:
    """Provider-neutral adapter for encrypted envelopes stored in KWallet."""

    backend = "kwallet"

    def __init__(self, client: KWalletClient | None = None) -> None:
        self.client = client or NativeKWalletClient()

    def read(self, configuration: dict[str, Any]) -> dict[str, Any]:
        settings = KWalletSettings.from_configuration(configuration)
        if settings is None:
            raise SecureStorageError("invalid KWallet configuration")
        try:
            document = json.loads(self.client.read(settings))
        except (KWalletError, json.JSONDecodeError) as error:
            raise SecureStorageError(f"could not read KWallet envelope: {error}") from error
        if not isinstance(document, dict):
            raise SecureStorageError("KWallet entry is not a JSON object")
        return document

    def write(self, configuration: dict[str, Any], envelope: dict[str, Any]) -> None:
        settings = KWalletSettings.from_configuration(configuration)
        if settings is None:
            raise SecureStorageError("invalid KWallet configuration")
        try:
            self.client.write_and_verify(settings, json.dumps(envelope, indent=2))
        except KWalletError as error:
            raise SecureStorageError(f"could not write KWallet envelope: {error}") from error


def write_kwallet_document(
    document: dict[str, Any],
    settings: KWalletSettings,
    client: KWalletClient | None = None,
) -> None:
    """Mirror a wallet through D-Bus so its secret never appears in process arguments.

    The complete JSON document is one native KWallet password entry, while the
    local JSON remains readable for development and protocol inspection.
    """
    serialized_document = json.dumps(document, indent=2)
    (client or NativeKWalletClient()).write_and_verify(settings, serialized_document)


register_store("kwallet", KWalletEnvelopeStore)
