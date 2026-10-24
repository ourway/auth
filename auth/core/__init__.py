__author__ = "Farshid Ashouri"

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auth.client import Client, EnhancedAuthClient

__all__ = ["Client", "EnhancedAuthClient"]


def __getattr__(name: str):
    if name in __all__:
        import auth.client

        value = getattr(auth.client, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module 'auth.core' has no attribute {name!r}")
