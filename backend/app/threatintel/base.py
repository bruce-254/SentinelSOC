"""Threat-intelligence provider interface.

Providers are pluggable. Each provider implements ``fetch`` and returns a list
of :class:`Indicator` objects. Providers are disabled by default and never
require external API keys for development. We never fabricate indicators of
compromise — the bundled demo provider ships with an *empty* dataset so the
plumbing works end-to-end without pretending real threat data exists.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Indicator:
    indicator_type: str  # ip | domain | hash | url
    value: str
    provider: str
    confidence: float = 0.0
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw: dict | None = None


class ThreatIntelProvider(abc.ABC):
    """Base class for external threat-intel providers."""

    name: str = "base"
    enabled: bool = False
    requires_api_key: bool = False

    @abc.abstractmethod
    async def fetch(self) -> list[Indicator]:
        """Fetch indicators. Must not raise on transient failures."""


class Registry:
    """Registers all configured providers."""

    def __init__(self):
        self._providers: list[ThreatIntelProvider] = []

    def register(self, provider: ThreatIntelProvider) -> None:
        self._providers.append(provider)

    def active(self) -> list[ThreatIntelProvider]:
        return [p for p in self._providers if p.enabled]

    @property
    def providers(self) -> list[ThreatIntelProvider]:
        return self._providers


registry = Registry()
