from fastapi.testclient import TestClient

from anon_identity.wallet import Wallet, encode_bytes
from anon_identity.web_demo import create_app

ISSUER_SECRET = "test-only-secret-that-is-at-least-32-characters"


def test_visual_demo_serves_interactive_page(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "demo.db"), ISSUER_SECRET))

    response = client.get("/")

    assert response.status_code == 200
    assert "One wallet." in response.text
    assert "forum.example" in response.text
    assert "shop.example" in response.text
    assert "Current wallet state" in response.text
    assert "Approve in bridge terminal" in response.text
    assert "Prove a threshold, not a birth date" in response.text
    assert "not cryptographically unlinkable" in response.text


def test_visual_demo_produces_stable_distinct_service_identities(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "demo.db"), ISSUER_SECRET))
    wallet = client.post("/api/demo/wallet").json()

    forum = client.post(
        "/api/demo/authenticate",
        json={"demo_session": wallet["demo_session"], "service_id": "forum.example"},
    )
    repeated_forum = client.post(
        "/api/demo/authenticate",
        json={"demo_session": wallet["demo_session"], "service_id": "forum.example"},
    )
    shop = client.post(
        "/api/demo/authenticate",
        json={"demo_session": wallet["demo_session"], "service_id": "shop.example"},
    )

    assert forum.status_code == repeated_forum.status_code == shop.status_code == 200
    assert forum.json()["subject"] == repeated_forum.json()["subject"]
    assert forum.json()["subject"] != shop.json()["subject"]
    assert forum.json()["steps"][-1]["detail"] == "Audience locked to forum.example"
    assert wallet["wallet_state"]["revision"] == 1
    assert forum.json()["wallet_state"]["revision"] == 2
    assert repeated_forum.json()["wallet_state"]["revision"] == 3
    assert shop.json()["wallet_state"]["revision"] == 4
    assert set(shop.json()["wallet_state"]["logical"]["services"]) == {
        "forum.example",
        "shop.example",
    }
    assert shop.json()["wallet_state"]["logical"]["root_secret"] == "[hidden]"
    assert "root_secret" not in shop.json()["wallet_state"]["encrypted"]


def test_visual_demo_rejects_an_unknown_wallet(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "demo.db"), ISSUER_SECRET))

    response = client.post(
        "/api/demo/authenticate",
        json={"demo_session": "missing", "service_id": "forum.example"},
    )

    assert response.status_code == 404


def test_connected_wallet_completes_provider_flow(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "demo.db"), ISSUER_SECRET))
    wallet = Wallet.generate()
    challenge_response = client.post(
        "/api/connected/challenge",
        json={
            "wallet_id": wallet.wallet_id,
            "root_public_key": encode_bytes(wallet.root_public_key),
            "service_id": "forum.example",
        },
    )
    challenge = challenge_response.json()
    proof = wallet.prove(
        challenge["challenge_id"],
        challenge["challenge"],
        challenge["service_id"],
    )

    response = client.post(
        "/api/connected/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "service_id": challenge["service_id"],
            "subject": proof.subject,
            "pairwise_public_key": proof.pairwise_public_key,
            "root_attestation": proof.root_attestation,
            "challenge_signature": proof.challenge_signature,
        },
    )

    assert challenge_response.status_code == 201
    assert response.status_code == 200
    assert response.json() == {
        "service_id": "forum.example",
        "subject": proof.subject,
    }


def test_demo_age_flow_issues_persists_and_verifies_once(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path / "demo.db"), ISSUER_SECRET))
    wallet = client.post("/api/demo/wallet").json()

    issued = client.post(
        "/api/demo/age/credentials",
        json={"demo_session": wallet["demo_session"]},
    )
    proof_request = client.post(
        "/api/demo/age/requests",
        json={
            "demo_session": wallet["demo_session"],
            "service_id": "shop.example",
            "minimum_age": 18,
        },
    )
    presentation_payload = {
        "demo_session": wallet["demo_session"],
        "request_id": proof_request.json()["request_id"],
    }
    presented = client.post("/api/demo/age/presentations", json=presentation_payload)
    replay = client.post("/api/demo/age/presentations", json=presentation_payload)

    assert issued.status_code == proof_request.status_code == 201
    assert issued.json()["wallet_state"]["revision"] == 2
    assert issued.json()["wallet_state"]["logical"]["age_credentials"][0]["age_over"] == [
        13,
        16,
        18,
        21,
    ]
    assert "credential" not in issued.json()["wallet_state"]["logical"]["age_credentials"][0]
    assert presented.status_code == 200
    assert presented.json()["claim"] == "age_over_18"
    assert presented.json()["value"] is True
    assert presented.json()["mode"] == "simulated"
    assert presented.json()["security"] == "not cryptographically unlinkable"
    assert replay.status_code == 400
    assert replay.json()["detail"] == "age presentation request was already consumed"