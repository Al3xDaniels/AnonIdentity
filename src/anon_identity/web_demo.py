"""Interactive proof-of-concept for the pairwise identity flow."""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import asdict
from importlib.resources import files
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from anon_identity.age_assurance import (
        AgeAssuranceError,
        AgeProofRequest,
        AgeTrustPolicy,
        select_age_credential,
)
from anon_identity.wallet_documents import (
        load_age_credentials,
        load_wallet,
        record_age_credential,
        record_service,
        save_wallet,
)
from anon_identity.demo_service import validate_token
from anon_identity.provider import AuthenticationError, IdentityProvider
from anon_identity.simulated_age_provider import (
        SIMULATED_FORMAT,
        SimulatedAgeCredentialProvider,
)
from anon_identity.wallet import Wallet, WalletProof, encode_bytes
from anon_identity.wallet_encryption import (
    decrypt_wallet_document,
    recovery_phrase_for_wallet,
)


class AuthenticationRequest(BaseModel):
    demo_session: str
    service_id: str


class ConnectedChallengeRequest(BaseModel):
    wallet_id: str
    root_public_key: str
    service_id: str


class ConnectedProofRequest(BaseModel):
    challenge_id: str
    service_id: str
    subject: str
    pairwise_public_key: str
    root_attestation: str
    challenge_signature: str


class DemoAgeRequest(BaseModel):
    demo_session: str
    service_id: str
    minimum_age: int


class DemoAgeCredentialRequest(BaseModel):
        demo_session: str


class DemoAgePresentationRequest(BaseModel):
    demo_session: str
    request_id: str


def _short(value: str, visible: int = 12) -> str:
    return value if len(value) <= visible * 2 else f"{value[:visible]}...{value[-visible:]}"


def _wallet_views(path: Path, recovery_phrase: str, wallet: Wallet) -> dict[str, object]:
    envelope = json.loads(path.read_text())
    document = decrypt_wallet_document(envelope, recovery_phrase)
    encrypted_view = {**envelope, "ciphertext": _short(envelope["ciphertext"], 24)}
    age_credentials = [
        {key: value for key, value in credential.items() if key != "credential"}
        for credential in document.get("age_credentials", [])
    ]
    return {
        "revision": envelope["revision"],
        "logical": {
            "wallet_id": wallet.wallet_id,
            "services": document.get("services", {}),
            "age_credentials": age_credentials,
            "root_secret": "[hidden]",
        },
        "encrypted": encrypted_view,
    }


def create_app(
    database_path: str | None = None,
    issuer_secret: str | None = None,
) -> FastAPI:
    resolved_database = database_path or os.getenv(
        "ANON_IDENTITY_DEMO_DATABASE", "data/web-demo.db"
    )
    resolved_secret = issuer_secret or os.getenv(
        "ANON_IDENTITY_ISSUER_SECRET",
        "development-only-secret-change-before-deployment",
    )
    provider = IdentityProvider(resolved_database, resolved_secret)
    age_provider = SimulatedAgeCredentialProvider(f"{resolved_secret}:age-demo")
    age_policy = AgeTrustPolicy(
        trusted_issuers=(age_provider.issuer,),
        accepted_formats=(SIMULATED_FORMAT,),
        accepted_assurance_levels=(age_provider.assurance_level,),
        accepted_jurisdictions=(age_provider.jurisdiction,),
    )
    wallet_directory = Path(resolved_database).parent / "demo-wallets"
    wallet_directory.mkdir(parents=True, exist_ok=True)
    wallets: dict[str, tuple[Path, str]] = {}
    age_requests: dict[str, tuple[str, AgeProofRequest]] = {}
    app = FastAPI(title="Anonymous Identity Visual Demo", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return DEMO_HTML

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/demo/wallet", status_code=status.HTTP_201_CREATED)
    def create_demo_wallet() -> dict[str, object]:
        """Persist an encrypted wallet for this browser demo session."""
        wallet = Wallet.generate()
        demo_session = secrets.token_urlsafe(24)
        phrase = recovery_phrase_for_wallet(wallet)
        wallet_file = wallet_directory / f"{demo_session}.wallet.json"
        save_wallet(wallet_file, wallet, phrase)
        wallets[demo_session] = (wallet_file, phrase)
        provider.enroll(wallet.wallet_id, encode_bytes(wallet.root_public_key))
        return {
            "demo_session": demo_session,
            "wallet_id": wallet.wallet_id,
            "root_public_key": _short(encode_bytes(wallet.root_public_key)),
            "wallet_state": dict(_wallet_views(wallet_file, phrase, wallet)),
        }

    @app.post("/api/demo/authenticate")
    def authenticate(request: AuthenticationRequest) -> dict[str, object]:
        """Authenticate and persist an accepted service in the wallet."""
        stored_wallet = wallets.get(request.demo_session)
        if stored_wallet is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo wallet has expired")
        wallet_file, phrase = stored_wallet
        wallet = load_wallet(wallet_file, phrase)

        try:
            challenge = provider.create_challenge(wallet.wallet_id, request.service_id)
            proof = wallet.prove(
                challenge.challenge_id,
                challenge.challenge,
                challenge.service_id,
            )
            token = provider.verify(challenge.challenge_id, proof)
            session = validate_token(token, challenge.service_id, resolved_secret)
            record_service(
                wallet_file,
                phrase,
                session["service_id"],
                session["anonymous_subject"],
            )
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error

        return {
            "service_id": session["service_id"],
            "subject": session["anonymous_subject"],
            "pairwise_public_key": _short(proof.pairwise_public_key),
            "steps": [
                {
                    "label": "Challenge created",
                    "detail": f"One-time nonce {_short(challenge.challenge, 9)}",
                },
                {
                    "label": "Pairwise key derived",
                    "detail": f"HKDF context: {challenge.service_id}",
                },
                {
                    "label": "Proof verified",
                    "detail": "Root attestation + Ed25519 challenge signature",
                },
                {
                    "label": "Scoped token accepted",
                    "detail": f"Audience locked to {challenge.service_id}",
                },
            ],
            "proof": {
                key: _short(value) for key, value in asdict(proof).items()
            },
            "wallet_state": _wallet_views(wallet_file, phrase, wallet),
        }

    @app.post("/api/demo/age/credentials", status_code=status.HTTP_201_CREATED)
    def issue_demo_age_credential(request: DemoAgeCredentialRequest) -> dict[str, object]:
        stored_wallet = wallets.get(request.demo_session)
        if stored_wallet is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo wallet has expired")
        wallet_file, phrase = stored_wallet
        credential = age_provider.issue(frozenset({13, 16, 18, 21}))
        record_age_credential(wallet_file, phrase, credential)
        wallet = load_wallet(wallet_file, phrase)
        return {
            "issuer": credential.issuer,
            "age_over": sorted(credential.age_over),
            "expires_at": credential.expires_at,
            "mode": "simulated",
            "security": "not cryptographically unlinkable",
            "wallet_state": _wallet_views(wallet_file, phrase, wallet),
        }

    @app.post("/api/demo/age/requests", status_code=status.HTTP_201_CREATED)
    def create_demo_age_request(request: DemoAgeRequest) -> dict[str, object]:
        if request.demo_session not in wallets:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo wallet has expired")
        now = int(time.time())
        try:
            proof_request = AgeProofRequest(
                service_id=request.service_id,
                minimum_age=request.minimum_age,
                nonce=secrets.token_urlsafe(24),
                expires_at=now + 120,
                policy=age_policy,
            )
        except AgeAssuranceError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        request_id = secrets.token_urlsafe(18)
        age_requests[request_id] = (request.demo_session, proof_request)
        return {
            "request_id": request_id,
            "service_id": proof_request.service_id,
            "minimum_age": proof_request.minimum_age,
            "expires_at": proof_request.expires_at,
            "issuer": age_provider.issuer,
        }

    @app.post("/api/demo/age/presentations")
    def present_demo_age_proof(
        request: DemoAgePresentationRequest,
    ) -> dict[str, object]:
        stored_wallet = wallets.get(request.demo_session)
        stored_request = age_requests.get(request.request_id)
        if stored_wallet is None or stored_request is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Demo age request has expired")
        request_session, proof_request = stored_request
        if request_session != request.demo_session:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Age request belongs to another wallet")
        wallet_file, phrase = stored_wallet
        try:
            credential = select_age_credential(
                load_age_credentials(wallet_file, phrase),
                proof_request,
            )
            presentation = age_provider.create_presentation(credential, proof_request)
            verified = age_provider.verify_presentation(presentation, proof_request)
        except AgeAssuranceError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return {
            "service_id": verified.service_id,
            "claim": f"age_over_{verified.minimum_age}",
            "value": True,
            "issuer": verified.issuer,
            "assurance_level": verified.assurance_level,
            "jurisdiction": verified.jurisdiction,
            "mode": "simulated",
            "security": "not cryptographically unlinkable",
            "steps": [
                {"label": "Policy matched", "detail": "Wallet selected a trusted credential locally"},
                {"label": "Consent granted", "detail": f"Only age_over_{verified.minimum_age} was requested"},
                {"label": "Presentation derived", "detail": "Fresh demo token bound to audience and nonce"},
                {"label": "Proof accepted", "detail": "Verifier consumed the one-time request"},
            ],
        }

    @app.post("/api/connected/challenge", status_code=status.HTTP_201_CREATED)
    def issue_connected_challenge(request: ConnectedChallengeRequest) -> dict[str, str | int]:
        """Enroll public wallet data and issue a challenge for local signing."""
        try:
            provider.enroll(request.wallet_id, request.root_public_key)
            challenge = provider.create_challenge(request.wallet_id, request.service_id)
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return {
            "challenge_id": challenge.challenge_id,
            "challenge": challenge.challenge,
            "service_id": challenge.service_id,
            "expires_at": challenge.expires_at,
        }

    @app.post("/api/connected/verify")
    def verify_connected_proof(request: ConnectedProofRequest) -> dict[str, str]:
        """Verify a bridge-created proof and validate its relying-service token."""
        proof = WalletProof(
            subject=request.subject,
            pairwise_public_key=request.pairwise_public_key,
            root_attestation=request.root_attestation,
            challenge_signature=request.challenge_signature,
        )
        try:
            token = provider.verify(request.challenge_id, proof)
            session = validate_token(token, request.service_id, resolved_secret)
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
        return {
            "service_id": session["service_id"],
            "subject": session["anonymous_subject"],
        }

    return app


DEMO_HTML = files("anon_identity").joinpath("templates/web_demo.html").read_text(encoding="utf-8")


app = create_app()