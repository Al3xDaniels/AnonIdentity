"""Demo-only age credential orchestration without production privacy claims."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from threading import Lock
from typing import Any, Protocol

from anon_identity.age_assurance import (
    AgeAssuranceError,
    AgeProofRequest,
    StoredAgeCredential,
)

SIMULATED_FORMAT = "demo-simulated-proof-v1"


@dataclass(frozen=True)
class VerifiedAgePresentation:
    service_id: str
    minimum_age: int
    issuer: str
    assurance_level: str
    jurisdiction: str
    expires_at: int


class AgeCredentialIssuer(Protocol):
    def issue(
        self,
        age_over: frozenset[int],
        *,
        now: int | None = None,
    ) -> StoredAgeCredential: ...


class AgePresentationAdapter(Protocol):
    def create_presentation(
        self,
        credential: StoredAgeCredential,
        request: AgeProofRequest,
        *,
        now: int | None = None,
    ) -> str: ...


class AgePresentationVerifier(Protocol):
    def verify_presentation(
        self,
        presentation: str,
        request: AgeProofRequest,
        *,
        now: int | None = None,
    ) -> VerifiedAgePresentation: ...


class SimulatedAgeCredentialProvider:
    """Exercise the age flow while real anonymous holder binding remains gated.

    This adapter uses a shared HMAC key and is not a BBS implementation. It does
    not provide cryptographic unlinkability or production-grade holder binding.
    """

    issuer = "https://demo-age-issuer.example"
    format = SIMULATED_FORMAT
    assurance_level = "document-verified-demo"
    jurisdiction = "US"

    def __init__(self, secret: str, *, credential_lifetime: int = 86_400) -> None:
        if len(secret.encode()) < 32:
            raise ValueError("simulated provider secret must be at least 32 bytes")
        if credential_lifetime < 1:
            raise ValueError("credential lifetime must be positive")
        self._secret = secret.encode()
        self._credential_lifetime = credential_lifetime
        self._consumed_requests: dict[tuple[str, str], int] = {}
        self._consumed_requests_lock = Lock()

    def issue(
        self,
        age_over: frozenset[int],
        *,
        now: int | None = None,
    ) -> StoredAgeCredential:
        issued_at = int(time.time()) if now is None else now
        expires_at = issued_at + self._credential_lifetime
        payload = {
            "age_over": sorted(age_over),
            "assurance_level": self.assurance_level,
            "credential_id": secrets.token_urlsafe(18),
            "exp": expires_at,
            "format": self.format,
            "issuer": self.issuer,
            "jurisdiction": self.jurisdiction,
        }
        return StoredAgeCredential(
            issuer=self.issuer,
            format=self.format,
            assurance_level=self.assurance_level,
            jurisdiction=self.jurisdiction,
            age_over=age_over,
            expires_at=expires_at,
            credential=self._sign(payload, "credential"),
        )

    def create_presentation(
        self,
        credential: StoredAgeCredential,
        request: AgeProofRequest,
        *,
        now: int | None = None,
    ) -> str:
        current_time = int(time.time()) if now is None else now
        credential_payload = self._verify_token(credential.credential, "credential")
        if credential_payload["exp"] <= current_time:
            raise AgeAssuranceError("age credential has expired")
        if request.minimum_age not in credential_payload["age_over"]:
            raise AgeAssuranceError("credential does not support the requested threshold")
        if request.expires_at <= current_time:
            raise AgeAssuranceError("age-proof request has expired")

        presentation = {
            "age_over": request.minimum_age,
            "assurance_level": credential_payload["assurance_level"],
            "aud": request.service_id,
            "exp": request.expires_at,
            "format": credential_payload["format"],
            "issuer": credential_payload["issuer"],
            "jurisdiction": credential_payload["jurisdiction"],
            "nonce": request.nonce,
            "presentation_id": secrets.token_urlsafe(18),
        }
        return self._sign(presentation, "presentation")

    def verify_presentation(
        self,
        presentation: str,
        request: AgeProofRequest,
        *,
        now: int | None = None,
    ) -> VerifiedAgePresentation:
        current_time = int(time.time()) if now is None else now
        payload = self._verify_token(presentation, "presentation")
        if payload["exp"] <= current_time or request.expires_at <= current_time:
            raise AgeAssuranceError("age presentation has expired")
        if payload["aud"] != request.service_id:
            raise AgeAssuranceError("age presentation audience does not match")
        if payload["nonce"] != request.nonce:
            raise AgeAssuranceError("age presentation nonce does not match")
        if payload["age_over"] != request.minimum_age:
            raise AgeAssuranceError("age presentation threshold does not match")
        if payload["issuer"] not in request.policy.trusted_issuers:
            raise AgeAssuranceError("age presentation issuer is not trusted")
        if payload["format"] not in request.policy.accepted_formats:
            raise AgeAssuranceError("age presentation format is not accepted")
        if payload["assurance_level"] not in request.policy.accepted_assurance_levels:
            raise AgeAssuranceError("age presentation assurance level is not accepted")
        if payload["jurisdiction"] not in request.policy.accepted_jurisdictions:
            raise AgeAssuranceError("age presentation jurisdiction is not accepted")

        request_key = (request.service_id, request.nonce)
        with self._consumed_requests_lock:
            self._consumed_requests = {
                key: expires_at
                for key, expires_at in self._consumed_requests.items()
                if expires_at > current_time
            }
            if request_key in self._consumed_requests:
                raise AgeAssuranceError("age presentation request was already consumed")
            self._consumed_requests[request_key] = request.expires_at
        return VerifiedAgePresentation(
            service_id=request.service_id,
            minimum_age=request.minimum_age,
            issuer=payload["issuer"],
            assurance_level=payload["assurance_level"],
            jurisdiction=payload["jurisdiction"],
            expires_at=payload["exp"],
        )

    def _sign(self, payload: dict[str, Any], purpose: str) -> str:
        encoded_payload = _encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        message = f"{purpose}.{encoded_payload}".encode()
        signature = _encode(hmac.new(self._secret, message, hashlib.sha256).digest())
        return f"{encoded_payload}.{signature}"

    def _verify_token(self, token: str, purpose: str) -> dict[str, Any]:
        try:
            encoded_payload, signature = token.split(".")
            message = f"{purpose}.{encoded_payload}".encode()
            expected = hmac.new(self._secret, message, hashlib.sha256).digest()
            if not hmac.compare_digest(_decode(signature), expected):
                raise AgeAssuranceError("simulated age token signature is invalid")
            payload = json.loads(_decode(encoded_payload))
            if not isinstance(payload, dict):
                raise ValueError
            _validate_payload(payload, purpose)
            return payload
        except AgeAssuranceError:
            raise
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            raise AgeAssuranceError("simulated age token is invalid") from error


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _validate_payload(payload: dict[str, Any], purpose: str) -> None:
    string_fields = {"assurance_level", "format", "issuer", "jurisdiction"}
    if purpose == "credential":
        string_fields.add("credential_id")
        age_over = payload.get("age_over")
        if not isinstance(age_over, list) or not age_over or any(
            type(age) is not int for age in age_over
        ):
            raise ValueError
    elif purpose == "presentation":
        string_fields.update({"aud", "nonce", "presentation_id"})
        if type(payload.get("age_over")) is not int:
            raise ValueError
    else:
        raise ValueError

    if type(payload.get("exp")) is not int or any(
        not isinstance(payload.get(field), str) or not payload[field]
        for field in string_fields
    ):
        raise ValueError