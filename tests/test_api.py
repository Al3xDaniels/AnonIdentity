from dataclasses import asdict

from fastapi.testclient import TestClient

from anon_identity.api import create_app as create_provider_app
from anon_identity.demo_service import create_app as create_demo_app
from anon_identity.wallet import Wallet, encode_bytes

ISSUER_SECRET = "test-only-secret-that-is-at-least-32-characters"


def test_http_login_flow_reaches_the_demo_service(tmp_path) -> None:
    provider = TestClient(create_provider_app(str(tmp_path / "identity.db"), ISSUER_SECRET))
    service = TestClient(create_demo_app("forum.com", ISSUER_SECRET))
    wallet = Wallet.generate()

    enrollment = provider.post(
        "/v1/wallets",
        json={"wallet_id": wallet.wallet_id, "root_public_key": encode_bytes(wallet.root_public_key)},
    )
    assert enrollment.status_code == 201

    challenge_response = provider.post(
        "/v1/challenges",
        json={"wallet_id": wallet.wallet_id, "service_id": "forum.com"},
    )
    assert challenge_response.status_code == 201
    challenge = challenge_response.json()
    proof = wallet.prove(challenge["challenge_id"], challenge["challenge"], challenge["service_id"])

    token_response = provider.post(
        f"/v1/challenges/{challenge['challenge_id']}/verify",
        json=asdict(proof),
    )
    assert token_response.status_code == 200

    session = service.get(
        "/session",
        headers={"Authorization": f"Bearer {token_response.json()['access_token']}"},
    )
    assert session.status_code == 200
    assert session.json() == {
        "service_id": "forum.com",
        "anonymous_subject": proof.subject,
    }