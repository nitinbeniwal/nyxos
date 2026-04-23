"""
NyxOS Rate Limiter
Location: nyxos/core/security/rate_limiter.py

Protects against:
- API abuse (token exhaustion)
- Brute force attacks
- Denial of service
- Runaway AI loops
"""

import time
from collections import defaultdict
from typing import Tuple
from loguru import logger


class RateLimiter:
    """
    Token bucket rate limiter.
    Configurable per action type.
    """

    def __init__(self):
        self._buckets: dict = defaultdict(lambda: {"tokens": 0, "last_refill": 0})

        # Rate limit configurations
        self._limits = {
            "api_call": {"max_tokens": 60, "refill_rate": 1.0, "refill_interval": 1},  # 60/min
            "command_exec": {"max_tokens": 30, "refill_rate": 0.5, "refill_interval": 1},  # 30/min
            "login_attempt": {"max_tokens": 5, "refill_rate": 0.08, "refill_interval": 1},  # 5/min
            "scan_start": {"max_tokens": 10, "refill_rate": 0.17, "refill_interval": 1},  # 10/min
            "ai_request": {"max_tokens": 30, "refill_rate": 0.5, "refill_interval": 1},  # 30/min
        }

    def check(self, action: str, identifier: str = "default") -> Tuple[bool, str]:
        """
        Check if action is allowed under rate limits.
        Returns (allowed, reason).
        """
        key = f"{action}:{identifier}"
        limit = self._limits.get(action)

        if not limit:
            return True, "No rate limit configured"

        bucket = self._buckets[key]
        now = time.time()

        # Refill tokens
        time_passed = now - bucket["last_refill"]
        new_tokens = time_passed * limit["refill_rate"]
        bucket["tokens"] = min(limit["max_tokens"], bucket["tokens"] + new_tokens)
        bucket["last_refill"] = now

        # Check if token available
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True, "Allowed"
        else:
            wait_time = (1 - bucket["tokens"]) / limit["refill_rate"]
            return False, f"Rate limited. Try again in {wait_time:.1f}s"

