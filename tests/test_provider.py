import jwt
import pytest

from anon_identity.provider import AuthenticationError, IdentityProvider
from anon_identity.wallet import Wallet, encode_bytes

ISSUER_SECRET = "test-only-secret-that-is-at-least-32-characters"


def test_wallet_completes_login_and_challenge_cannot_be_replayed(tmp_path) -> None:
    provider = IdentityProvider(tmp_path / "identity.db", ISSUER_SECRET)
    wallet = Wallet.generate()
    provider.enroll(wallet.wallet_id, encode_bytes(wallet.root_public_key))
    challenge = provider.create_challenge(wallet.wallet_id, "forum.com")
    proof = wallet.prove(challenge.challenge_id, challenge.challenge, challenge.service_id)

    token = provider.verify(challenge.challenge_id, proof)
    claims = jwt.decode(token, ISSUER_SECRET, algorithms=["HS256"], audience="forum.com")

    assert claims["sub"] == proof.subject
    assert claims["aud"] == "forum.com"
    with pytest.raises(AuthenticationError, match="unavailable"):
        provider.verify(challenge.challenge_id, proof)


def test_services_receive_different_subjects(tmp_path) -> None:
    provider = IdentityProvider(tmp_path / "identity.db", ISSUER_SECRET)
    wallet = Wallet.generate()
    provider.enroll(wallet.wallet_id, encode_bytes(wallet.root_public_key))

    forum = provider.create_challenge(wallet.wallet_id, "forum.com")
    shop = provider.create_challenge(wallet.wallet_id, "shop.com")

    forum_proof = wallet.prove(forum.challenge_id, forum.challenge, forum.service_id)
    shop_proof = wallet.prove(shop.challenge_id, shop.challenge, shop.service_id)

    assert forum_proof.subject != shop_proof.subject