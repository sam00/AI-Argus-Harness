"""Plugin loader.

Built-in scanners register on import. Third-party scanners are discovered via
the ``ai_argus.scanners`` setuptools entry-point group, so enterprises can ship
private scanner packages (``argus plugin install ...``) without forking core.
"""

from __future__ import annotations

from typing import List

from ..scanners.base import REGISTRY, Scanner


def load_builtin() -> None:
    # Importing the package triggers built-in registration.
    import ai_argus.scanners  # noqa: F401


def load_entrypoints() -> List[str]:
    """Load external scanner plugins. Returns names of newly loaded scanners."""
    loaded: List[str] = []
    try:
        from importlib import metadata
    except Exception:  # pragma: no cover
        return loaded

    try:
        eps = metadata.entry_points()
        group = eps.select(group="ai_argus.scanners") if hasattr(eps, "select") \
            else eps.get("ai_argus.scanners", [])  # type: ignore[attr-defined]
    except Exception:
        return loaded

    for ep in group:
        try:
            obj = ep.load()
            if isinstance(obj, type) and issubclass(obj, Scanner):
                REGISTRY[obj.name] = obj
                loaded.append(obj.name)
        except Exception:
            continue
    return loaded


def load_all() -> List[str]:
    load_builtin()
    return load_entrypoints()
