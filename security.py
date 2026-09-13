"""
UNG-HELIOS security layer.
Shared by both api.py (server) and client.py (each system) — deploy
this file alongside both.
Everything here takes `now` as an explicit argument instead of
calling time.time() itself, the same way core.py's Relay takes an
injected sender_fn. That's what makes rate limiting, lockout timing,
and anomaly detection testable in seconds instead of needing to
actually wait 5 minutes for a lockout to expire.
What this does NOT do, on purpose: nothing here attacks, probes, or
retaliates against anything else. It only ever protects HELIOS and
the services behind it — verifying who's really sending a message,
noticing when a service is behaving strangely, and shutting off
access to a specific compromised-looking service. It never reaches
out toward whatever might be attacking it.
"""
import hmac
import hashlib
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Optional

def sign(secret: str, timestamp: str, body: bytes) -> str:
    message = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

def verify(secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    expected = sign(secret, timestamp, body)
    return hmac.compare_digest(expected, signature)

class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
    def _trim(self, service_id: str, now: float) -> deque:
        q = self._events[service_id]
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        return q
    def allow(self, service_id: str, now: float) -> bool:
        q = self._trim(service_id, now)
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True
    def current_count(self, service_id: str, now: float) -> int:
        return len(self._trim(service_id, now))

class LockoutTracker:
    def __init__(self, max_failures: int, window_seconds: float, lockout_seconds: float):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, deque] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
    def record_failure(self, service_id: str, now: float) -> bool:
        q = self._failures[service_id]
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        q.append(now)
        if len(q) >= self.max_failures and service_id not in self._locked_until:
            self._locked_until[service_id] = now + self.lockout_seconds
            return True
        return False
    def is_locked_out(self, service_id: str, now: float) -> bool:
        until = self._locked_until.get(service_id)
        if until is None:
            return False
        if now >= until:
            del self._locked_until[service_id]
            self._failures[service_id].clear()
            return False
        return True
    def reset(self, service_id: str) -> None:
        self._failures[service_id].clear()
        self._locked_until.pop(service_id, None)

@dataclass
class Baseline:
    ema_per_minute: float = 0.0
    samples: int = 0
    last_update: float = 0.0

class AnomalyDetector:
    def __init__(self, spike_multiplier: float = 5.0, min_samples: int = 5,
                 min_baseline: float = 1.0, burst_window: float = 10.0):
        self.spike_multiplier = spike_multiplier
        self.min_samples = min_samples
        self.min_baseline = min_baseline
        self.burst_window = burst_window
        self._baselines: dict[str, Baseline] = {}
        self._first_seen: dict[str, float] = {}
        self._recent: dict[str, deque] = defaultdict(deque)
    def record_and_check(self, service_id: str, now: float,
                          burst_window: Optional[float] = None) -> Optional[str]:
        bw = burst_window if burst_window is not None else self.burst_window
        recent = self._recent[service_id]
        recent.append(now)
        cutoff = now - bw
        while recent and recent[0] < cutoff:
            recent.popleft()
        current_rate = len(recent) * (60.0 / bw)
        b = self._baselines.setdefault(service_id, Baseline())
        if service_id not in self._first_seen:
            self._first_seen[service_id] = now
        b.samples += 1
        b.last_update = now
        elapsed_minutes = max((now - self._first_seen[service_id]) / 60.0, 1e-9)
        b.ema_per_minute = b.samples / elapsed_minutes
        anomaly = None
        effective_baseline = max(b.ema_per_minute, self.min_baseline)
        if b.samples >= self.min_samples and current_rate > effective_baseline * self.spike_multiplier:
            anomaly = (f"rate spike: {current_rate:.1f}/min vs long-run baseline "
                       f"{b.ema_per_minute:.1f}/min (threshold x{self.spike_multiplier})")
        return anomaly
    def baseline_for(self, service_id: str) -> Optional[Baseline]:
        return self._baselines.get(service_id)
