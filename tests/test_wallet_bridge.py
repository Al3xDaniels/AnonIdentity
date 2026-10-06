import time
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from fastapi.testclient import TestClient

from anon_identity.cli import save_wallet
from anon_identity.wallet import Wallet, encode_bytes
from anon_identity.wallet_bridge import create_bridge_app
from anon_identity.wallet_encryption import recovery_phrase_for_wallet
from anon_identity.wallet_repository import FileWalletRepository

ORIGIN = "http://localhost:8002"


def create_client(tmp_path, approve=lambda origin, request: True):
    wallet = Wallet.generate()
    phrase = recovery_phrase_for_wallet(wallet)
    path = tmp_path / "wallet.json"
    save_wallet(path, wallet, phrase)
    repository = FileWalletRepository(path)
    app = create_bridge_app(repository, phrase, {ORIGIN: {"forum.example"}}, approve)
    return TestClient(app), wallet


def test_bridge_returns_only_public_wallet_information(tmp_path) -> None:
    client, wallet = create_client(tmp_path)

    response = client.get("/v1/wallet", headers={"Origin": ORIGIN})

    assert response.status_code == 200
    assert response.json() == {
        "wallet_id": wallet.wallet_id,
        "root_public_key": encode_bytes(wallet.root_public_key),
        "storage_backend": "file",
    }
    assert "root_secret" not in response.text


def test_bridge_requires_allowed_origin_and_owner_approval(tmp_path) -> None:
    client, _ = create_client(tmp_path, approve=lambda origin, request: False)
    payload = {
        "challenge_id": "challenge-1",
        "challenge": encode_bytes(b"a" * 32),
        "service_id": "forum.example",
        "expires_at": int(time.time()) + 60,
    }

    assert client.post("/v1/proofs", json=payload).status_code == 403
    denied = client.post("/v1/proofs", json=payload, headers={"Origin": ORIGIN})
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Wallet owner denied the request"


def test_bridge_signs_each_approved_challenge_once(tmp_path) -> None:
    client, wallet = create_client(tmp_path)
    payload = {
        "challenge_id": "challenge-1",
        "challenge": encode_bytes(b"a" * 32),
        "service_id": "forum.example",
        "expires_at": int(time.time()) + 60,
    }

    response = client.post("/v1/proofs", json=payload, headers={"Origin": ORIGIN})
    replay = client.post("/v1/proofs", json=payload, headers={"Origin": ORIGIN})

    assert response.status_code == 200
    assert response.json()["subject"] == wallet.prove(
        payload["challenge_id"], payload["challenge"], payload["service_id"]
    ).subject
    assert replay.status_code == 409


def test_bridge_binds_allowed_origin_to_service(tmp_path) -> None:
    client, _ = create_client(tmp_path)

    response = client.post(
        "/v1/proofs",
        json={
            "challenge_id": "challenge-1",
            "challenge": encode_bytes(b"a" * 32),
            "service_id": "shop.example",
            "expires_at": int(time.time()) + 60,
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Service is not allowed for this browser origin"


def test_bridge_reserves_challenge_while_consent_is_pending(tmp_path) -> None:
    approval_started = Event()
    release_approval = Event()

    def approve(origin, request):
        approval_started.set()
        assert release_approval.wait(timeout=2)
        return True

    client, _ = create_client(tmp_path, approve=approve)
    payload = {
        "challenge_id": "challenge-1",
        "challenge": encode_bytes(b"a" * 32),
        "service_id": "forum.example",
        "expires_at": int(time.time()) + 60,
    }

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            client.post,
            "/v1/proofs",
            json=payload,
            headers={"Origin": ORIGIN},
        )
        assert approval_started.wait(timeout=2)
        duplicate = client.post("/v1/proofs", json=payload, headers={"Origin": ORIGIN})
        release_approval.set()

    assert first.result().status_code == 200
    assert duplicate.status_code == 409