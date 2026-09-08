import os

import pytest

from anon_identity.crypto import derive_pairwise_identity


def test_pairwise_identity_is_stable_for_the_same_service() -> None:
    root_secret = os.urandom(32)

    first = derive_pairwise_identity(root_secret, "Forum.COM")
    second = derive_pairwise_identity(root_secret, "forum.com")

    assert first.subject == second.subject
    assert first.public_key_bytes == second.public_key_bytes


def test_pairwise_identity_differs_between_services() -> None:
    root_secret = os.urandom(32)

    forum_identity = derive_pairwise_identity(root_secret, "forum.com")
    shop_identity = derive_pairwise_identity(root_secret, "shop.com")

    assert forum_identity.subject != shop_identity.subject
    assert forum_identity.public_key_bytes != shop_identity.public_key_bytes


def test_root_secret_must_be_32_bytes() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        derive_pairwise_identity(b"too-short", "forum.com")