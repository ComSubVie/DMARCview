"""Password hashing and login throttling."""

from __future__ import annotations

from app.security import LoginThrottle, hash_password, verify_password


def test_hash_roundtrip():
    encoded = hash_password("correct horse battery staple", iterations=1000)
    assert encoded.startswith("pbkdf2_sha256$1000$")
    assert verify_password("correct horse battery staple", encoded) is True
    assert verify_password("wrong", encoded) is False


def test_hash_is_salted():
    assert hash_password("same", iterations=1000) != hash_password("same", iterations=1000)


def test_malformed_hash_is_rejected():
    assert verify_password("x", "not-a-hash") is False
    assert verify_password("x", "md5$1$abc$def") is False
    assert verify_password("", "") is False


def test_throttle_blocks_after_failures():
    throttle = LoginThrottle(max_failures=3, window=60, block_for=120)
    for _ in range(3):
        assert throttle.is_blocked("1.2.3.4") == 0
        throttle.register_failure("1.2.3.4")
    assert throttle.is_blocked("1.2.3.4") > 0
    assert throttle.is_blocked("5.6.7.8") == 0
    throttle.reset("1.2.3.4")
    assert throttle.is_blocked("1.2.3.4") == 0


def test_login_throttle_via_api(client):
    for _ in range(8):
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 401
    blocked = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
