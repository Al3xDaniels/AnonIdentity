import pytest

from anon_identity.age_assurance import (
    AgeAssuranceError,
    AgeProofRequest,
    StoredAgeCredential,
    select_age_credential,
)


def test_request_contains_only_threshold_and_verifier_binding() -> None:
    request = AgeProofRequest(
        service_id=" Store.COM ",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=2_000,
        trusted_issuers=("https://age-verifier.example",),
    )

    assert request.service_id == "store.com"
    assert request.minimum_age == 18
    assert not hasattr(request, "birth_date")
    assert not hasattr(request, "exact_age")


def test_selects_unexpired_credential_from_trusted_issuer() -> None:
    credential = StoredAgeCredential(
        issuer="https://age-verifier.example",
        format="future-reviewed-format",
        age_over=frozenset({18, 21}),
        expires_at=3_000,
        credential="opaque-signed-credential",
    )
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=2_000,
        trusted_issuers=(credential.issuer,),
    )

    assert select_age_credential([credential], request, now=1_000) is credential


@pytest.mark.parametrize("trusted,credential_expiry", [(False, 3_000), (True, 999)])
def test_rejects_untrusted_or_expired_credentials(
    trusted: bool,
    credential_expiry: int,
) -> None:
    credential = StoredAgeCredential(
        issuer="https://age-verifier.example",
        format="future-reviewed-format",
        age_over=frozenset({18}),
        expires_at=credential_expiry,
        credential="opaque-signed-credential",
    )
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=2_000,
        trusted_issuers=(credential.issuer if trusted else "https://other.example",),
    )

    with pytest.raises(AgeAssuranceError, match="no trusted credential"):
        select_age_credential([credential], request, now=1_000)


def test_rejects_expired_request() -> None:
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=999,
        trusted_issuers=("https://age-verifier.example",),
    )

    with pytest.raises(AgeAssuranceError, match="request has expired"):
        select_age_credential([], request, now=999)