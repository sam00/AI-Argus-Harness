"""AI-Argus-Harness — evidence-first enterprise security intelligence harness.

The package is organized to mirror the enterprise architecture:

    ai_argus.core         Harness core: orchestrator, plugin loader, context
    ai_argus.graph        Asset graph + identity graph engines
    ai_argus.evidence     Evidence store + normalizer
    ai_argus.reliability  Hallucination-reduction / validation layer
    ai_argus.scoring      Deterministic risk scoring + deduplication
    ai_argus.chaining     Attack-path chain construction
    ai_argus.reporting    SARIF / JSON / Markdown / executive reporting
    ai_argus.scanners     Plugin-based deterministic scanners
    ai_argus.llm          Model-agnostic provider abstraction (offline default)
"""

__version__ = "0.1.0"
__author__ = "Sam Gupta"
__all__ = ["__version__", "__author__"]
