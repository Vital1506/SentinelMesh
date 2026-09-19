"""SentinelMesh package."""

__all__ = ["__version__"]

__version__ = "2.0.0"


def __getattr__(name: str):
    if name == "__version__":
        return __version__
    raise AttributeError(f"module SentinelMesh has no attribute {name!r}")