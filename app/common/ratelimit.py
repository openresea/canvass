import threading
import time
from typing import Dict, List

from fastapi import Request


class RateLimiter:
    """
    Sliding-window rate limiter backed by an in-memory dict.
    Per-process only. Production requires shared edge limits across replicas.
    """

    def __init__(self, max_calls: int, window_seconds: int) -> None:
        self._max = max_calls
        self._window = window_seconds
        self._lock = threading.Lock()
        self._hits: Dict[str, List[float]] = {}

    def is_allowed(self, key: str) -> bool:
        """Return True if the request is within the rate limit, False otherwise."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(hits) >= self._max:
                self._hits[key] = hits
                return False
            if key not in self._hits and len(self._hits) >= 10000:
                self._hits = {
                    k: ts for k, ts in self._hits.items() if ts and ts[-1] > cutoff
                }
                if len(self._hits) >= 10000:
                    return False
            hits.append(now)
            self._hits[key] = hits
            # Prevent unbounded growth under sustained attack.
            if len(self._hits) > 10_000:
                stale = [
                    k for k, ts in self._hits.items() if not any(t > cutoff for t in ts)
                ]
                for k in stale:
                    del self._hits[k]
            return True


def client_ip(request: Request) -> str:
    """Use ASGI's peer, set only by the server's trusted proxy configuration."""
    return str(request.client.host) if request.client else "unknown"
