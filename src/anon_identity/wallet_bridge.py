"""Local, consent-gated bridge between browsers and an encrypted wallet."""

from __future__ import annotations

import argparse
import getpass
import json
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from threading import Lock
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from anon_identity.secure_storage import create_store
from anon_identity.wallet import Wallet, decode_bytes, encode_bytes
from anon_identity.wallet_encryption import decrypt_wallet_document
from anon_identity.wallet_repository import (
    FileWalletRepository,
    SecureStoreWalletRepository,
    WalletRepository,
)


class ProofRequest(BaseModel):
    challenge_id: str = Field(min_length=1, max_length=128)
    challenge: str = Field(min_length=1, max_length=256)
    service_id: str = Field(min_length=1, max_length=255)
    expires_at: int


ApprovalCallback = Callable[[str, ProofRequest], bool]


def create_bridge_app(
    repository: WalletRepository,
    recovery_phrase: str,
    allowed_services: dict[str, set[str]],
    approve: ApprovalCallback,
) -> FastAPI:
    """Create a bridge whose callers never receive wallet secrets or plaintext."""
    if not allowed_services:
        raise ValueError("at least one browser origin and service must be allowed")

    initial_document = decrypt_wallet_document(repository.read(), recovery_phrase)
    wallet = Wallet(decode_bytes(initial_document["root_secret"]))
    pending_challenges: set[str] = set()
    consumed_challenges: set[str] = set()
    challenge_lock = Lock()
    approval_lock = Lock()
    app = FastAPI(title="Anonymous Identity Local Wallet Bridge", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(allowed_services),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )

    def require_origin(origin: str | None) -> str:
        if origin is None or origin not in allowed_services:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Browser origin is not allowed")
        return origin

    @app.get("/v1/wallet")
    def wallet_information(origin: str | None = Header(default=None)) -> dict[str, str]:
        require_origin(origin)
        return {
            "wallet_id": wallet.wallet_id,
            "root_public_key": encode_bytes(wallet.root_public_key),
            "storage_backend": repository.backend,
        }

    @app.post("/v1/proofs")
    def create_proof(
        request: ProofRequest,
        origin: str | None = Header(default=None),
    ) -> dict[str, str]:
        approved_origin = require_origin(origin)
        now = int(time.time())
        if request.expires_at < now:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Challenge has expired")
        if request.expires_at > now + 300:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Challenge expiry is too far away")
        if request.service_id not in allowed_services[approved_origin]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Service is not allowed for this browser origin",
            )
        with challenge_lock:
            if (
                request.challenge_id in pending_challenges
                or request.challenge_id in consumed_challenges
            ):
                raise HTTPException(status.HTTP_409_CONFLICT, "Challenge was already requested")
            pending_challenges.add(request.challenge_id)

        try:
            with approval_lock:
                approved = approve(approved_origin, request)
            if not approved:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "Wallet owner denied the request")
            if request.expires_at < int(time.time()):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    "Challenge expired before approval",
                )

            proof = wallet.prove(request.challenge_id, request.challenge, request.service_id)
            with challenge_lock:
                consumed_challenges.add(request.challenge_id)
            return asdict(proof)
        finally:
            with challenge_lock:
                pending_challenges.discard(request.challenge_id)

    return app


def _terminal_approval(origin: str, request: ProofRequest) -> bool:
    answer = input(
        f"Allow {origin} to authenticate as a pairwise identity for "
        f"{request.service_id}? [y/N] "
    )
    return answer.strip().lower() in {"y", "yes"}


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="anon-wallet-bridge")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--wallet-file", type=Path)
    source.add_argument("--storage-backend")
    parser.add_argument(
        "--storage-config",
        type=json.loads,
        default={},
        help="JSON object passed only to the selected secure-storage adapter",
    )
    parser.add_argument(
        "--allow",
        action="append",
        required=True,
        metavar="ORIGIN=SERVICE_ID",
        help="allow an exact browser origin to request one service identity",
    )
    parser.add_argument("--recovery-phrase-file", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    return parser


def main() -> None:
    arguments = create_parser().parse_args()
    if arguments.recovery_phrase_file:
        recovery_phrase = arguments.recovery_phrase_file.read_text().strip()
    else:
        recovery_phrase = getpass.getpass("Recovery phrase: ").strip()

    if arguments.wallet_file:
        repository: WalletRepository = FileWalletRepository(arguments.wallet_file)
    else:
        store = create_store(arguments.storage_backend)
        repository = SecureStoreWalletRepository(store, arguments.storage_config)

    allowed_services: dict[str, set[str]] = {}
    for rule in arguments.allow:
        try:
            origin, service_id = rule.rsplit("=", 1)
        except ValueError as error:
            raise SystemExit("--allow must use ORIGIN=SERVICE_ID") from error
        allowed_services.setdefault(origin, set()).add(service_id)

    app = create_bridge_app(
        repository,
        recovery_phrase,
        allowed_services,
        _terminal_approval,
    )
    uvicorn.run(app, host="127.0.0.1", port=arguments.port)


if __name__ == "__main__":
    main()