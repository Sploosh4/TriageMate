import os
import time


class TokenBucket:
    def __init__(self, rate_per_minute: int, burst_size: int):
        self.rate = rate_per_minute / 60.0
        self.burst = burst_size
        self.tokens = float(burst_size)
        self.last_refill = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> float:
        if self.tokens >= 1.0:
            return 0.0
        return max(0.0, (1.0 - self.tokens) / self.rate)


ingest_bucket = TokenBucket(
    rate_per_minute=int(os.getenv("INGEST_RATE_PER_MIN", "30")),
    burst_size=int(os.getenv("INGEST_BURST_SIZE", "50")),
)
demo_bucket = TokenBucket(
    rate_per_minute=int(os.getenv("DEMO_RATE_PER_MIN", "10")),
    burst_size=int(os.getenv("DEMO_BURST_SIZE", "15")),
)
clear_bucket = TokenBucket(
    rate_per_minute=int(os.getenv("CLEAR_RATE_PER_MIN", "2")),
    burst_size=int(os.getenv("CLEAR_BURST_SIZE", "3")),
)
