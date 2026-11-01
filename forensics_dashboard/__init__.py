"""Forensic dashboard and evaluation adapter for CyberTrace."""

def create_app(*args, **kwargs):
    """Import Flask lazily so evaluation works without dashboard extras installed."""
    from .web import create_app as factory
    return factory(*args, **kwargs)

__all__ = ["create_app"]
