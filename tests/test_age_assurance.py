import json
from typing import Any

import pytest

from anon_identity.age_assurance import (
    AgeAssuranceError,
    AgeCredentialOffer,
    AgeProofRequest,
    AgeTrustPolicy,
    StoredAgeCredential,
    select_age_credential,
)
from anon_identity.wallet_documents import load_age_credentials, record_age_credential, save_wallet
from anon_identity.wallet import Wallet
from anon_identity.wallet_encryption import decrypt_wallet_document, recovery_phrase_for_wallet


POLICY = AgeTrustPolicy(
    trusted_issuers=("https://age-verifier.example",),
    accepted_formats=("future-reviewed-format",),
    accepted_assurance_levels=("document-verified",),
    accepted_jurisdictions=("US",),
)


def create_credential(**overrides: Any) -> StoredAgeCredential:
    values: dict[str, Any] = {
        "issuer": "https://age-verifier.example",
        "format": "future-reviewed-format",
        "assurance_level": "document-verified",
        "jurisdiction": "US",
        "age_over": frozenset({18}),
        "expires_at": 3_000,
        "credential": "opaque-signed-credential",
    }
    values.update(overrides)
    return StoredAgeCredential(**values)


def test_request_contains_only_threshold_and_verifier_binding() -> None:
    request = AgeProofRequest(
        service_id=" Store.COM ",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=2_000,
        policy=POLICY,
    )

    assert request.service_id == "store.com"
    assert request.minimum_age == 18
    assert not hasattr(request, "birth_date")
    assert not hasattr(request, "exact_age")


def test_offer_contains_no_identity_or_birth_date() -> None:
    offer = AgeCredentialOffer(
        issuer="https://age-verifier.example",
        format="future-reviewed-format",
        assurance_level="document-verified",
        jurisdiction="US",
        supported_age_over=frozenset({18, 21}),
        expires_at=2_000,
        offer="opaque-issuance-offer",
    )

    assert offer.supported_age_over == frozenset({18, 21})
    assert not hasattr(offer, "birth_date")
    assert not hasattr(offer, "credential_id")


def test_selects_unexpired_credential_from_trusted_issuer() -> None:
    credential = StoredAgeCredential(
        issuer="https://age-verifier.example",
        format="future-reviewed-format",
        assurance_level="document-verified",
        jurisdiction="US",
        age_over=frozenset({18, 21}),
        expires_at=3_000,
        credential="opaque-signed-credential",
    )
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=1_200,
        policy=POLICY,
    )

    assert select_age_credential([credential], request, now=1_000) is credential


@pytest.mark.parametrize(
    "changed_field,changed_value",
    [
        ("issuer", "https://other.example"),
        ("format", "unaccepted-format"),
        ("assurance_level", "self-asserted"),
        ("jurisdiction", "CA"),
        ("expires_at", 999),
    ],
)
def test_rejects_credentials_outside_policy(
    changed_field: str,
    changed_value: str | int,
) -> None:
    credential = create_credential(**{changed_field: changed_value})
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=1_200,
        policy=POLICY,
    )

    with pytest.raises(AgeAssuranceError, match="no trusted credential"):
        select_age_credential([credential], request, now=1_000)


def test_rejects_expired_request() -> None:
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=999,
        policy=POLICY,
    )

    with pytest.raises(AgeAssuranceError, match="request has expired"):
        select_age_credential([], request, now=999)


def test_rejects_request_with_excessive_lifetime() -> None:
    request = AgeProofRequest(
        service_id="store.com",
        minimum_age=18,
        nonce="fresh-challenge",
        expires_at=1_301,
        policy=POLICY,
    )

    with pytest.raises(AgeAssuranceError, match="too far away"):
        select_age_credential([], request, now=1_000)


def test_age_credential_is_stored_inside_encrypted_wallet(tmp_path) -> None:
    wallet = Wallet.generate()
    phrase = recovery_phrase_for_wallet(wallet)
    path = tmp_path / "wallet.json"
    credential = create_credential()
    save_wallet(path, wallet, phrase)

    record_age_credential(path, phrase, credential)

    envelope = json.loads(path.read_text())
    assert envelope["revision"] == 2
    assert credential.credential not in path.read_text()
    document = decrypt_wallet_document(envelope, phrase)
    assert document["age_credentials"][0]["credential"] == credential.credential
    assert load_age_credentials(path, phrase) == [credential]