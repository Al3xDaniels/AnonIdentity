"""Protocol-neutral domain types for future age-assurance credentials."""

from __future__ import annotations

import time
from dataclasses import dataclass

from anon_identity.crypto import canonical_service_id


class AgeAssuranceError(ValueError):
    """Raised when an age-proof request or credential candidate is invalid."""


def _required_values(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    normalized = tuple(value.strip() for value in values)
    if not normalized or any(not value for value in normalized):
        raise AgeAssuranceError(f"at least one {field_name} is required")
    if len(set(normalized)) != len(normalized):
        raise AgeAssuranceError(f"{field_name} must not contain duplicates")
    return normalized


@dataclass(frozen=True)
class AgeTrustPolicy:
    """Relying-party requirements used only for local credential selection."""

    trusted_issuers: tuple[str, ...]
    accepted_formats: tuple[str, ...]
    accepted_assurance_levels: tuple[str, ...]
    accepted_jurisdictions: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "trusted_issuers",
            _required_values(self.trusted_issuers, "trusted issuer"),
        )
        object.__setattr__(
            self,
            "accepted_formats",
            _required_values(self.accepted_formats, "accepted credential format"),
        )
        object.__setattr__(
            self,
            "accepted_assurance_levels",
            _required_values(self.accepted_assurance_levels, "accepted assurance level"),
        )
        object.__setattr__(
            self,
            "accepted_jurisdictions",
            _required_values(self.accepted_jurisdictions, "accepted jurisdiction"),
        )


@dataclass(frozen=True)
class AgeProofRequest:
    """A service-bound request for one minimum-age predicate."""

    service_id: str
    minimum_age: int
    nonce: str
    expires_at: int
    policy: AgeTrustPolicy

    def __post_init__(self) -> None:
        object.__setattr__(self, "service_id", canonical_service_id(self.service_id))
        if not 1 <= self.minimum_age <= 150:
            raise AgeAssuranceError("minimum_age must be between 1 and 150")
        normalized_nonce = self.nonce.strip()
        if not normalized_nonce or len(normalized_nonce) > 256:
            raise AgeAssuranceError("nonce must contain between 1 and 256 characters")
        object.__setattr__(self, "nonce", normalized_nonce)


@dataclass(frozen=True)
class AgeCredentialOffer:
    """Opaque issuer offer plus the metadata needed for informed consent."""

    issuer: str
    format: str
    assurance_level: str
    jurisdiction: str
    supported_age_over: frozenset[int]
    expires_at: int
    offer: str

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.issuer,
                self.format,
                self.assurance_level,
                self.jurisdiction,
                self.offer,
            )
        ):
            raise AgeAssuranceError("age credential offer metadata is incomplete")
        if not self.supported_age_over or any(
            age < 1 or age > 150 for age in self.supported_age_over
        ):
            raise AgeAssuranceError("offer must contain valid age-over thresholds")


@dataclass(frozen=True)
class StoredAgeCredential:
    """Encrypted-wallet metadata plus an opaque standards-based credential."""

    issuer: str
    format: str
    assurance_level: str
    jurisdiction: str
    age_over: frozenset[int]
    expires_at: int
    credential: str

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.issuer,
                self.format,
                self.assurance_level,
                self.jurisdiction,
                self.credential,
            )
        ):
            raise AgeAssuranceError("credential metadata and payload are required")
        if not self.age_over or any(age < 1 or age > 150 for age in self.age_over):
            raise AgeAssuranceError("credential must contain valid age-over thresholds")


def select_age_credential(
    credentials: list[StoredAgeCredential],
    request: AgeProofRequest,
    *,
    now: int | None = None,
    maximum_request_lifetime: int = 300,
) -> StoredAgeCredential:
    """Select local credential material suitable for a presentation adapter.

    This performs wallet-side metadata filtering only. The eventual presentation
    adapter and relying service must still verify cryptographic proof and status.
    """
    current_time = int(time.time()) if now is None else now
    if maximum_request_lifetime < 1:
        raise AgeAssuranceError("maximum request lifetime must be positive")
    if request.expires_at <= current_time:
        raise AgeAssuranceError("age-proof request has expired")
    if request.expires_at > current_time + maximum_request_lifetime:
        raise AgeAssuranceError("age-proof request expiry is too far away")

    for credential in credentials:
        if (
            credential.issuer in request.policy.trusted_issuers
            and credential.format in request.policy.accepted_formats
            and credential.assurance_level in request.policy.accepted_assurance_levels
            and credential.jurisdiction in request.policy.accepted_jurisdictions
            and credential.expires_at > current_time
            and request.minimum_age in credential.age_over
        ):
            return credential
    raise AgeAssuranceError("no trusted credential satisfies the requested age threshold")