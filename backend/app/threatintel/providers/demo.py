"""Bundled threat-intel provider used for development and testing.

This provider intentionally returns an empty dataset: it exercises the full
provider plumbing (registration, fetching, persistence, API surface) without
fabricating indicators of compromise. In production you would add a real
provider (e.g. abuse.ch / AlienVault OTX / MISP) implementing the same
interface, configured with the API key it requires.
"""
from __future__ import annotations

from ..base import Indicator, ThreatIntelProvider


class DemoThreatIntelProvider(ThreatIntelProvider):
    name = "demo-local"
    enabled = True
    requires_api_key = False

    async def fetch(self) -> list[Indicator]:
        # No indicators provided out of the box. Add real provider data here.
        return []
