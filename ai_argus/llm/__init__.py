"""Model-agnostic LLM provider abstraction.

Core principle: **AI is an evidence interpreter, never an
evidence creator.** The harness works fully offline; LLM providers only enhance
prioritization, correlation, and summarization when configured and within budget.
"""

from .provider import (
    LLMProvider,
    OfflineProvider,
    ModelResponse,
    get_provider,
    CostTracker,
)

__all__ = [
    "LLMProvider",
    "OfflineProvider",
    "ModelResponse",
    "get_provider",
    "CostTracker",
]
