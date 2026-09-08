"""HTTP API for the anonymous identity provider prototype."""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from anon_identity.provider import AuthenticationError, IdentityProvider
from anon_identity.wallet import WalletProof


class EnrollmentRequest(BaseModel):
    wallet_id: str
    root_public_key: str


class ChallengeRequest(BaseModel):
    wallet_id: str
    service_id: str


class ProofRequest(BaseModel):
    subject: str
    pairwise_public_key: str
    root_attestation: str
    challenge_signature: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default=600)


def create_app(
    database_path: str | None = None,
    issuer_secret: str | None = None,
) -> FastAPI:
    """Create an app with explicit settings for tests or environment settings in Docker."""
    resolved_database = database_path or os.getenv("ANON_IDENTITY_DATABASE", "data/identity.db")
    resolved_secret = issuer_secret or os.getenv(
        "ANON_IDENTITY_ISSUER_SECRET",
        "development-only-secret-change-before-deployment",
    )
    provider = IdentityProvider(resolved_database, resolved_secret)
    app = FastAPI(title="Anonymous Identity Provider", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/wallets", status_code=status.HTTP_201_CREATED)
    def enroll_wallet(request: EnrollmentRequest) -> dict[str, str]:
        try:
            provider.enroll(request.wallet_id, request.root_public_key)
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return {"wallet_id": request.wallet_id, "status": "enrolled"}

    @app.post("/v1/challenges", status_code=status.HTTP_201_CREATED)
    def create_challenge(request: ChallengeRequest) -> dict[str, str | int]:
        try:
            challenge = provider.create_challenge(request.wallet_id, request.service_id)
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return {
            "challenge_id": challenge.challenge_id,
            "challenge": challenge.challenge,
            "service_id": challenge.service_id,
            "expires_at": challenge.expires_at,
        }

    @app.post("/v1/challenges/{challenge_id}/verify", response_model=TokenResponse)
    def verify_challenge(challenge_id: str, request: ProofRequest) -> TokenResponse:
        # Pydantic validates the transport shape; the provider independently verifies
        # all cryptographic relationships before issuing a bearer token.
        proof = WalletProof(**request.model_dump())
        try:
            token = provider.verify(challenge_id, proof)
        except (AuthenticationError, ValueError) as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
        return TokenResponse(access_token=token)

    return app
