"""Pipeline package -- backend-agnostic stage logic + orchestration adapters."""

__all__ = [
    "types",
    "stages",
    "async_runner",
]

try:
    from . import temporal_runner
    __all__.append("temporal_runner")
except ImportError:
    pass
