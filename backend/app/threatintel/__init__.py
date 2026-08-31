from .base import Indicator, ThreatIntelProvider, registry  # noqa: F401
from .providers.demo import DemoThreatIntelProvider  # noqa: F401

# Register bundled providers.
registry.register(DemoThreatIntelProvider())


def get_providers():
    return registry.providers
