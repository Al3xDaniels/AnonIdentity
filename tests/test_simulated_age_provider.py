from concurrent.futures import ThreadPoolExecutor

import pytest

from anon_identity.age_assurance import AgeAssuranceError, AgeProofRequest, AgeTrustPolicy
from anon_identity.simulated_age_provider import SimulatedAgeCredentialProvider

SECRET = "test-only-simulated-provider-secret"


def create_request(
    provider: SimulatedAgeCredentialProvider,
    *,
    service_id: str = "shop.example",
    nonce: str = "fresh-nonce",
) -> AgeProofRequest:
    return AgeProofRequest(
        service_id=service_id,
        minimum_age=18,
        nonce=nonce,
        expires_at=1_100,
        policy=AgeTrustPolicy(
            trusted_issuers=(provider.issuer,),
            accepted_formats=(provider.format,),
            accepted_assurance_levels=(provider.assurance_level,),
            accepted_jurisdictions=(provider.jurisdiction,),
        ),
    )


def test_simulated_presentations_are_fresh_and_request_bound() -> None:
    provider = SimulatedAgeCredentialProvider(SECRET)
    credential = provider.issue(frozenset({18, 21}), now=1_000)
    first_request = create_request(provider, nonce="nonce-1")
    second_request = create_request(provider, nonce="nonce-2")

    first = provider.create_presentation(credential, first_request, now=1_000)
    second = provider.create_presentation(credential, second_request, now=1_000)

    assert first != second
    assert provider.verify_presentation(first, first_request, now=1_000).minimum_age == 18
    with pytest.raises(AgeAssuranceError, match="audience does not match"):
        provider.verify_presentation(
            second,
            create_request(provider, service_id="forum.example", nonce="nonce-2"),
            now=1_000,
        )


def test_simulated_verifier_rejects_tampering_and_replay() -> None:
    provider = SimulatedAgeCredentialProvider(SECRET)
    credential = provider.issue(frozenset({18}), now=1_000)
    request = create_request(provider)
    presentation = provider.create_presentation(credential, request, now=1_000)

    provider.verify_presentation(presentation, request, now=1_000)

    with pytest.raises(AgeAssuranceError, match="already consumed"):
        provider.verify_presentation(presentation, request, now=1_000)
    encoded_payload, signature = presentation.split(".")
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{encoded_payload}.{replacement}{signature[1:]}"
    with pytest.raises(AgeAssuranceError, match="signature is invalid"):
        provider.verify_presentation(tampered, create_request(provider), now=1_000)


def test_simulated_verifier_rejects_malformed_tokens_cleanly() -> None:
    provider = SimulatedAgeCredentialProvider(SECRET)

    with pytest.raises(AgeAssuranceError, match="token is invalid"):
        provider.verify_presentation("not-a-token", create_request(provider), now=1_000)


def test_simulated_verifier_consumes_concurrent_request_once() -> None:
    provider = SimulatedAgeCredentialProvider(SECRET)
    credential = provider.issue(frozenset({18}), now=1_000)
    request = create_request(provider)
    presentation = provider.create_presentation(credential, request, now=1_000)

    def verify_once() -> bool:
        try:
            provider.verify_presentation(presentation, request, now=1_000)
            return True
        except AgeAssuranceError as error:
            assert str(error) == "age presentation request was already consumed"
            return False

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: verify_once(), range(8)))

    assert results.count(True) == 1