"""Small relying service that accepts tokens issued for its own audience."""

from __future__ import annotations

import os

import jwt
from fastapi import FastAPI, Header, HTTPException, status


def validate_token(token: str, service_id: str, issuer_secret: str) -> dict[str, str]:
    """Validate an issued token for exactly one relying-service audience."""
    try:
        claims = jwt.decode(
            token,
            issuer_secret,
            algorithms=["HS256"],
            audience=service_id,
            issuer="anon-identity",
        )
    except jwt.PyJWTError as error:
        raise ValueError("Token is invalid") from error
    return {"service_id": service_id, "anonymous_subject": claims["sub"]}


def create_app(
    service_id: str | None = None,
    issuer_secret: str | None = None,
) -> FastAPI:
    resolved_service = service_id or os.getenv("DEMO_SERVICE_ID", "forum.com")
    resolved_secret = issuer_secret or os.getenv(
        "ANON_IDENTITY_ISSUER_SECRET",
        "development-only-secret-change-before-deployment",
    )
    app = FastAPI(title="Anonymous Identity Demo Service", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service_id": resolved_service}

    @app.get("/session")
    def session(authorization: str = Header()) -> dict[str, str]:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer token required")

        # Audience validation is essential: a token issued for shop.com must not be
        # accepted by forum.com, even if both services trust the same prototype issuer.
        try:
            return validate_token(
                authorization.removeprefix("Bearer "),
                resolved_service,
                resolved_secret,
            )
        except ValueError as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error

    return app
