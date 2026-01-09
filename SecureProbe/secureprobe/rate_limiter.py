"""
Token bucket rate limiter for controlled request pacing.

Implements an async-friendly token bucket algorithm with
configurable capacity and refill rates.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class TokenBucketRateLimiter:
    """
    Token bucket rate limiter with async support.

    Provides smooth rate limiting with burst capacity.
    Tokens are refilled at a constant rate up to max capacity.
    """

    rate: float = 2.0
    capacity: float = field(init=False)
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __post_init__(self) -> None:
        """Initialize bucket with full capacity."""
        self.capacity = self.rate * 2
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        refill_amount = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + refill_amount)
        self.last_refill = now

    async def acquire(self, tokens: float = 1.0) -> None:
        """
        Acquire tokens, waiting if necessary.

        Args:
            tokens: Number of tokens to acquire (default 1.0)

        Raises:
            ValueError: If requested tokens exceed capacity
        """
        if tokens > self.capacity:
            raise ValueError(f"Requested {tokens} tokens exceeds capacity {self.capacity}")

        async with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return

            deficit = tokens - self.tokens
            wait_time = deficit / self.rate

            await asyncio.sleep(wait_time)

            self._refill()
            self.tokens -= tokens

    async def try_acquire(self, tokens: float = 1.0) -> bool:
        """
        Try to acquire tokens without waiting.

        Args:
            tokens: Number of tokens to acquire (default 1.0)

        Returns:
            True if tokens were acquired, False otherwise
        """
        async with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    @property
    def available_tokens(self) -> float:
        """Get current available tokens (read-only snapshot)."""
        self._refill()
        return self.tokens

    def reset(self) -> None:
        """Reset bucket to full capacity."""
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
