from datetime import datetime, timedelta, timezone
from typing import Optional

MAX_KEY_LIFETIME = timedelta(days=365)


class KeyExpiryError(ValueError):
    pass


def parse_expiry(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise KeyExpiryError("expires_at must be an ISO-8601 date-time string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise KeyExpiryError(
            f"expires_at is not an ISO-8601 date-time: {value!r}"
        ) from None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def check_expiry(
    expires_at: datetime, now: datetime, current: Optional[datetime] = None
) -> None:
    if expires_at <= now:
        raise KeyExpiryError("expires_at must be in the future")
    if expires_at > now + MAX_KEY_LIFETIME:
        raise KeyExpiryError("expires_at may be at most 365 days from now")
    if current is not None and expires_at >= current:
        raise KeyExpiryError(
            "expires_at may only be moved earlier than the key's current expiry "
            f"({current.isoformat()})"
        )
