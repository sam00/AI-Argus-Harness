"""Plugin-based deterministic scanners.

Scanners produce *structured evidence and candidate findings only*. They never
call an LLM and never invent claims — this is the foundation of the harness's
hallucination-reduction strategy.

Built-in scanners self-register on import via the ``@register`` decorator.
External scanners can be added through Python entry points in the
``ai_argus.scanners`` group (see :mod:`ai_argus.core.plugin_loader`).
"""

from .base import Scanner, ScannerResult, register, REGISTRY, get_scanner, all_scanners

# Import built-ins so they register.
from . import domain          # noqa: F401
from . import network         # noqa: F401
from . import secrets         # noqa: F401
from . import supply_chain    # noqa: F401
from . import cloud           # noqa: F401
from . import kubernetes      # noqa: F401
from . import saas            # noqa: F401
from . import cicd            # noqa: F401
from . import data_exposure   # noqa: F401
from . import application     # noqa: F401
from . import endpoint        # noqa: F401

__all__ = [
    "Scanner", "ScannerResult", "register", "REGISTRY",
    "get_scanner", "all_scanners",
]
