"""
UNG-HELIOS core logic.
Pure Python, zero external dependencies. This is the part that gets
actually tested and run in this environment — the HTTP/API layer
(api.py) is a thin wrapper around this that just moves data in and out.
Design choices made specifically to avoid repeating past problems:
- No field named "from" anywhere (that needed special-case aliasing
  before and was never actually verified to work). Here it's just
  "sender_id" — an ordinary field name, no aliasing tricks needed.
- Delivery function is injected (see Relay.__init__), so this file
  never assumes anything about HTTP, requests, or network libraries.
  That keeps the retry/backoff/error-classification logic testable
  without needing a live server or a network call.
"""
from __future__ import annotations
import time
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional
class DeliveryError(Exception):
    """Base class for delivery failures."""
class TargetUnreachable(DeliveryError):
    """The target could not be contacted at all (network/DNS/timeout)."""
class TargetErrored(DeliveryError):
    """The target was contacted but responded with an error."""
class TargetDeactivated(DeliveryError):
    """The target is registered but currently marked inactive."""
class TargetUnknown(DeliveryError):
    """No service is registered under that ID."""
@dataclass
class Service:
    service_id: str
    name: str
    capabilities: list[str]
    endpoint: str
    auth_key: str
    active: bool = True
@dataclass
class DeliveryRecord:
    sender_id: str
    target_id: str
    message_type: str
    attempts: int
    success: bool
    error: Optional[str]
    timestamp: float = field(default_factory=time.time)
class Registry:
    """Tracks which services/vendors exist and what they can do."""
    def __init__(self):
        self._services: dict[str, Service] = {}
    def register(self, service_id: str, name: str, capabilities: list[str],
                 endpoint: str, auth_key: str) -> Service:
        svc = Service(service_id, name, list(capabilities), endpoint, auth_key)
        self._services[service_id] = svc
        return svc
    def deactivate(self, service_id: str) -> None:
        if service_id in self._services:
            self._services[service_id].active = False
    def reactivate(self, service_id: str) -> None:
        if service_id in self._services:
            self._services[service_id].active = True
    def get(self, service_id: str) -> Optional[Service]:
        return self._services.get(service_id)
    def find_by_capability(self, capability: str) -> list[Service]:
        return [s for s in self._services.values()
                if s.active and capability in s.capabilities]
    def all_active(self) -> list[Service]:
        return [s for s in self._services.values() if s.active]
class Relay:
    """
    Handles message delivery with retry/backoff, on top of a Registry.
    `sender_fn` is injected: a callable (endpoint, auth_key, payload) -> None
    that raises TargetUnreachable or TargetErrored on failure. This file
    has no idea whether that's HTTP, a queue, or a test stub — which is
    what makes it possible to test the retry logic without a network.
    """
    def __init__(self, registry: Registry, sender_fn: Callable,
                 max_attempts: int = 4, base_delay: float = 0.5,
                 sleep_fn: Callable[[float], None] = time.sleep):
        self.registry = registry
        self.sender_fn = sender_fn
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.sleep_fn = sleep_fn
        self.log: list[DeliveryRecord] = []
    def send(self, sender_id: str, target_id: str, message_type: str,
              payload: dict) -> DeliveryRecord:
        target = self.registry.get(target_id)
        if target is None:
            rec = DeliveryRecord(sender_id, target_id, message_type, 0,
                                  False, "unknown_target")
            self.log.append(rec)
            raise TargetUnknown(f"No service registered as '{target_id}'")
        if not target.active:
            rec = DeliveryRecord(sender_id, target_id, message_type, 0,
                                  False, "target_deactivated")
            self.log.append(rec)
            raise TargetDeactivated(f"'{target_id}' is deactivated")
        last_error = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                self.sender_fn(target.endpoint, target.auth_key, {
                    "sender_id": sender_id,
                    "target_id": target_id,
                    "message_type": message_type,
                    "payload": payload,
                })
                rec = DeliveryRecord(sender_id, target_id, message_type,
                                      attempt, True, None)
                self.log.append(rec)
                return rec
            except TargetErrored as e:
                last_error = f"target_errored: {e}"
                if attempt < self.max_attempts:
                    self._backoff(attempt)
                    continue
                break
            except TargetUnreachable as e:
                last_error = f"target_unreachable: {e}"
                if attempt < self.max_attempts:
                    self._backoff(attempt)
                    continue
                break
        rec = DeliveryRecord(sender_id, target_id, message_type,
                              self.max_attempts, False, last_error)
        self.log.append(rec)
        raise DeliveryError(last_error)
    def _backoff(self, attempt: int) -> None:
        delay = self.base_delay * (2 ** (attempt - 1))
        delay += random.uniform(0, self.base_delay)
        self.sleep_fn(delay)
    def broadcast(self, sender_id: str, capability: str, message_type: str,
                   payload: dict) -> list[DeliveryRecord]:
        """Send to every active service that has a given capability."""
        results = []
        for svc in self.registry.find_by_capability(capability):
            try:
                results.append(self.send(sender_id, svc.service_id,
                                          message_type, payload))
            except DeliveryError:
                results.append(self.log[-1])
        return results
