"""Password hashing and login throttling.

PBKDF2-SHA256 from the standard library keeps the dependency footprint small
while remaining a sound choice for a self-hosted single-admin app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass

ITERATIONS = 310_000


class PasswordError(ValueError):
    pass


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    if not password:
        raise PasswordError("password must not be empty")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    if not password or not encoded:
        return False
    try:
        algorithm, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


@dataclass
class _Attempts:
    count: int = 0
    first: float = 0.0
    blocked_until: float = 0.0


class LoginThrottle:
    """Tiny in-memory lockout: 8 failures per IP inside 15 minutes."""

    def __init__(self, max_failures: int = 8, window: int = 900, block_for: int = 900) -> None:
        self.max_failures = max_failures
        self.window = window
        self.block_for = block_for
        self._attempts: dict[str, _Attempts] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> int:
        now = time.time()
        with self._lock:
            entry = self._attempts.get(key)
            if entry and entry.blocked_until > now:
                return int(entry.blocked_until - now)
            return 0

    def register_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            entry = self._attempts.get(key)
            if entry is None or now - entry.first > self.window:
                entry = _Attempts(count=0, first=now)
                self._attempts[key] = entry
            entry.count += 1
            if entry.count >= self.max_failures:
                entry.blocked_until = now + self.block_for
                entry.count = 0
                entry.first = now
            if len(self._attempts) > 2048:
                cutoff = now - self.window
                for candidate, value in list(self._attempts.items()):
                    if value.first < cutoff and value.blocked_until < now:
                        self._attempts.pop(candidate, None)

    def reset(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


login_throttle = LoginThrottle()
