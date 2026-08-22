"""
Enhanced client library with connection pooling, retry logic, and circuit breaker

The implementation is split across :mod:`auth.client._transport`,
:mod:`auth.client.base` and the per-resource mixins, but this package stays the
public import path: ``from auth.client import EnhancedAuthClient`` resolves
exactly as it did before the split, and both classes keep ``auth.client`` as
their ``__module__``.
"""

# Re-exported so it still resolves through this module, as it did when the
# client was a single file.
from auth.circuit_breaker import circuit_breaker
from auth.client._transport import (
    _RETRY_METHODS,
    AuthTransportError,
    RetryableHTTPAdapter,
    _build_retry,
)
from auth.client.base import ClientBase
from auth.client.keys import ApiKeyMixin
from auth.client.rbac import RbacMixin
from auth.client.workflow import WorkflowMixin


class EnhancedAuthClient(WorkflowMixin):
    """Enhanced client with connection pooling, retry logic, and circuit breaker.

    Error contract (3.0.0): every method raises :class:`AuthTransportError`
    on transport failure — connection error, exhausted retries, open circuit
    breaker, or a non-2xx status. A transport failure can therefore never
    reach your authorization logic as a value: catch the exception and map it
    to your unavailable/503 path, never to a denial. Success payloads are
    unchanged from 2.x.
    """


# For backward compatibility with the old client
class Client(EnhancedAuthClient):
    """Legacy client class for backward compatibility"""

    pass


__all__ = [
    "ApiKeyMixin",
    "AuthTransportError",
    "Client",
    "ClientBase",
    "EnhancedAuthClient",
    "RbacMixin",
    "RetryableHTTPAdapter",
    "WorkflowMixin",
    "circuit_breaker",
    "_RETRY_METHODS",
    "_build_retry",
]
