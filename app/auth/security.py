"""Password hashing and login rate limiting."""

import time
from collections import deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


class LoginLimiter:
    """In-memory sliding window of failed logins (the web service is a single process)."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = {}

    def _recent(self, key: str, now: float) -> deque[float]:
        hits = self._failures.setdefault(key, deque())
        while hits and hits[0] <= now - self.window_seconds:
            hits.popleft()
        return hits

    def is_blocked(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return len(self._recent(key, now)) >= self.max_attempts

    def register_failure(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._recent(key, now).append(now)

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)

    def clear(self) -> None:
        self._failures.clear()
