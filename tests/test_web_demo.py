from fastapi.testclient import TestClient

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