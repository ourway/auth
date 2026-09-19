"""Transport layer for the REST client: retry policy, adapter, error type."""

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Methods eligible for retry. The auth server's write endpoints are
# idempotent upserts, so retrying POST/PUT/DELETE is safe here.
_RETRY_METHODS = ["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]


class AuthTransportError(Exception):
    """The client could not get an answer from the auth service.

    Raised by every client method when no answer could be obtained:
    connection failure, exhausted retries, open circuit breaker, or a 5xx.
    A 4xx raises :class:`AuthRefused`, a subclass — the service DID answer,
    it refused the request.
    Distinguishes "we could not ask" from a genuine negative answer such as
    ``has_permission: false`` — map it to your unavailable/503 path, never
    to a denial.
    """


class AuthRefused(AuthTransportError):
    """The auth service answered and refused the request (a 4xx).

    Subclasses :class:`AuthTransportError` so existing handlers keep working,
    but lets a caller tell "auth would not accept this" from "auth could not be
    reached". Reported by a consumer whose platform-admin check logged "auth
    unreachable at login" while auth was up, answering, and simply rejecting a
    subject containing ``|``: that sends whoever reads the log to the health
    endpoint and the network when the cause is the shape of a string.

    ``status`` is the HTTP status; ``payload`` is the decoded body when there
    was one, so actionable errors (such as the 409 ``user_not_key_backed`` hint)
    survive instead of being flattened into a transport message.
    """

    def __init__(self, message: str, status: int, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload


def _build_retry(total, backoff_factor, status_forcelist) -> Retry:
    """Build a Retry that works on both urllib3 1.x and 2.x.

    urllib3 renamed ``method_whitelist`` to ``allowed_methods`` in 1.26 and
    removed the old name in 2.0.
    """
    kwargs = {
        "total": total,
        "backoff_factor": backoff_factor,
        "status_forcelist": list(status_forcelist),
    }
    try:
        return Retry(allowed_methods=_RETRY_METHODS, **kwargs)
    except TypeError:  # urllib3 < 1.26
        return Retry(method_whitelist=_RETRY_METHODS, **kwargs)  # type: ignore[call-arg]


class RetryableHTTPAdapter(HTTPAdapter):
    """HTTP adapter with retry logic"""

    def __init__(
        self, retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), **kwargs
    ):
        self.retries = retries
        self.backoff_factor = backoff_factor
        self.status_forcelist = status_forcelist
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["retries"] = Retry(
            total=self.retries,
            read=self.retries,
            connect=self.retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=self.status_forcelist,
        )
        return super().init_poolmanager(*args, **kwargs)
