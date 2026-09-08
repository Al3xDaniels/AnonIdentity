"""Protocol-neutral domain types for future age-assurance credentials."""

from __future__ import annotations

import time
from dataclasses import dataclass

from anon_identity.crypto import canonical_service_id


class AgeAssuranceError(ValueError):
    """Raised when an age-proof request or credential candidate is invalid."""


@dataclass(frozen=True)
class AgeProofRequest:
    """A service-bound request for one minimum-age predicate."""

    service_id: str
    minimum_age: int
    nonce: str
    expires_at: int
    trusted_issuers: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", canonical_service_id(self.service_id))
        if not 1 <= self.minimum_age <= 150:
            raise AgeAssuranceError("minimum_age must be between 1 and 150")
        if not self.nonce.strip():
            raise AgeAssuranceError("nonce must not be empty")
        if not self.trusted_issuers or any(not issuer.strip() for issuer in self.trusted_issuers):
            raise AgeAssuranceError("at least one trusted issuer is required")


@dataclass(frozen=True)
class StoredAgeCredential:
    """Encrypted-wallet metadata plus an opaque standards-based credential."""

    issuer: str
    format: str
    age_over: frozenset[int]
    expires_at: int
    credential: str

    def __post_init__(self) -> None:
        if not self.issuer.strip() or not self.format.strip() or not self.credential:
            raise AgeAssuranceError("credential issuer, format, and payload are required")
        if not self.age_over or any(age < 1 or age > 150 for age in self.age_over):
            raise AgeAssuranceError("credential must contain valid age-over thresholds")


def select_age_credential(
    credentials: list[StoredAgeCredential],
    request: AgeProofRequest,
    *,
    now: int | None = None,
) -> StoredAgeCredential:
    """Select local credential material suitable for a presentation adapter.

    This performs wallet-side metadata filtering only. The eventual presentation
    adapter and relying service must still verify cryptographic proof and status.
    """
    current_time = int(time.time()) if now is None else now
    if request.expires_at <= current_time:
        raise AgeAssuranceError("age-proof request has expired")

    for credential in credentials:
        if (
            credential.issuer in request.trusted_issuers
            and credential.expires_at > current_time
            and request.minimum_age in credential.age_over
        ):
            return credential
    raise AgeAssuranceError("no trusted credential satisfies the requested age threshold")