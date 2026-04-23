"""
NyxOS AI Response Cache
Location: nyxos/core/ai_engine/cache.py

Caches AI responses to save tokens and reduce latency.
Uses content-based hashing for cache keys.

Strategy:
- Exact match: Same prompt + system prompt → cached response
- TTL-based expiration (default 24 hours)
- LRU eviction when cache is full
"""

import os
import json
import hashlib
import time
from typing import Optional
from collections import OrderedDict
from loguru import logger
from .adapter import AIResponse


class ResponseCache:
    """
    LRU cache with TTL for AI responses.
    Stored in memory with periodic disk persistence.
    """

    CACHE_FILE = os.path.expanduser("~/.nyxos/cache/ai_responses.json")
    MAX_ENTRIES = 1000
    DEFAULT_TTL = 86400  # 24 hours in seconds

    def __init__(self, enabled: bool = True, ttl: int = DEFAULT_TTL):
        self.enabled = enabled
        self.ttl = ttl
        self._cache: OrderedDict = OrderedDict()
        self._load_from_disk()

    def _make_key(self, prompt: str, system_prompt: str) -> str:
        """Create a cache key from prompt + system prompt"""
        combined = f"{system_prompt}|||{prompt}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def get(self, prompt: str, system_prompt: str) -> Optional[AIResponse]:
        """Get cached response if available and not expired"""
        if not self.enabled:
            return None

        key = self._make_key(prompt, system_prompt)

        if key not in self._cache:
            return None

        entry = self._cache[key]

        # Check TTL
        if time.time() - entry["timestamp"] > self.ttl:
            del self._cache[key]
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)

        logger.debug(f"Cache hit for key {key[:8]}...")

        return AIResponse(
            content=entry["content"],
            model=entry["model"],
            provider=entry["provider"],
            tokens_used=0,
            cached=True
        )

    def store(self, prompt: str, system_prompt: str, response: AIResponse):
        """Store a response in cache"""
        if not self.enabled or response.error:
            return

        key = self._make_key(prompt, system_prompt)

        # Evict oldest if at capacity
        while len(self._cache) >= self.MAX_ENTRIES:
            self._cache.popitem(last=False)

        self._cache[key] = {
            "content": response.content,
            "model": response.model,
            "provider": response.provider,
            "timestamp": time.time(),
            "prompt_preview": prompt[:100]
        }

        # Periodic save (every 10 new entries)
        if len(self._cache) % 10 == 0:
            self._save_to_disk()

    def clear(self):
        """Clear all cached responses"""
        self._cache.clear()
        if os.path.exists(self.CACHE_FILE):
            os.remove(self.CACHE_FILE)
        logger.info("AI response cache cleared")

    def get_stats(self) -> dict:
        """Get cache statistics"""
        valid = sum(
            1 for entry in self._cache.values()
            if time.time() - entry["timestamp"] <= self.ttl
        )
        return {
            "total_entries": len(self._cache),
            "valid_entries": valid,
            "expired_entries": len(self._cache) - valid,
            "max_entries": self.MAX_ENTRIES
        }

    def _save_to_disk(self):
        """Persist cache to disk"""
        try:
            os.makedirs(os.path.dirname(self.CACHE_FILE), mode=0o700, exist_ok=True)
            with open(self.CACHE_FILE, "w") as f:
                json.dump(dict(self._cache), f, default=str)
            os.chmod(self.CACHE_FILE, 0o600)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    def _load_from_disk(self):
        """Load cache from disk"""
        if not os.path.exists(self.CACHE_FILE):
            return

        try:
            with open(self.CACHE_FILE, "r") as f:
                data = json.load(f)

            # Only load entries that haven't expired
            now = time.time()
            for key, entry in data.items():
                if now - entry.get("timestamp", 0) <= self.ttl:
                    self._cache[key] = entry

            logger.info(f"Loaded {len(self._cache)} cached responses from disk")
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
