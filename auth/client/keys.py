"""Client key rotation, per-user API keys, and tenant settings."""

from typing import Any, Dict, Optional

from auth.client.rbac import RbacMixin


class ApiKeyMixin(RbacMixin):
    """Key rotation, per-user API keys and tenant settings."""

    def rotate_key(self) -> Dict[str, Any]:
        """Rotate this client's API key (atomic cutover).

        The server mints a fresh key, moves the whole namespace onto it, and
        returns it in ``data.new_key``. On success this client is updated in
        place — ``self.api_key`` and the session ``Authorization`` header switch
        to the new key — so subsequent calls on this instance keep working. The
        returned key is the ONLY copy: persist ``data.new_key`` (e.g. to your
        secret store) or you lose access to the namespace.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["rotate_key"]
        try:
            response = self._make_request("POST", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={})

        new_key = (response or {}).get("data", {}).get("new_key")
        if new_key:
            self.api_key = new_key
            self.session.headers["Authorization"] = f"Bearer {new_key}"
        return response

    # Per-user API keys (SPEC 0004)
    def create_api_key(self, user: str, label: Optional[str] = None) -> Dict[str, Any]:
        """Mint an API key for a user; ``data.api_key`` is shown only once.

        Sent WITHOUT automatic retries: create is not idempotent, and a blind
        retry after an ambiguous failure could mint a second key whose secret
        nobody ever saw. On an ambiguous failure, list and revoke instead.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikeys_user"].format(user=user)
        payload = {"label": label} if label is not None else None
        try:
            return self._make_request("POST", endpoint, retry=False, json=payload)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "label": label})

    def list_api_keys(self, user: str) -> Dict[str, Any]:
        """List a user's API keys (metadata only; never the secrets).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikeys_user"].format(user=user)
        try:
            return self._make_request("GET", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user})

    def revoke_api_key(self, user: str, key_id: str) -> Dict[str, Any]:
        """Revoke one of a user's API keys by its public key_id (idempotent).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        endpoint = self.endpoints["apikey_revoke"].format(user=user, key_id=key_id)
        try:
            return self._make_request("DELETE", endpoint)
        except Exception as e:
            return self._transport_failure(e, data={"user": user, "key_id": key_id})

    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Validate an API-key secret; answers ``data.valid`` true/false.

        The secret travels in the JSON body, never a URL, and never rides
        on an exception.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "POST", self.endpoints["apikey_validate"], json={"api_key": api_key}
            )
        except Exception as e:
            return self._transport_failure(e, data={"key_prefix": api_key[:12]})

    def check_api_key_permission(self, api_key: str, permission: str) -> Dict[str, Any]:
        """Validate a secret AND check its subject's permission in one call.

        ``data.valid`` false → the key failed (reason as in validate_api_key);
        true → ``data.has_permission`` answers for the key's user. The secret
        travels in the JSON body and never rides on an exception.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "POST",
                self.endpoints["apikey_check_permission"],
                json={"api_key": api_key, "permission": permission},
            )
        except Exception as e:
            return self._transport_failure(
                e, data={"key_prefix": api_key[:12], "permission": permission}
            )

    # Tenant settings (SPEC 0010)
    def get_settings(self) -> Dict[str, Any]:
        """This tenant's settings (``data.strict_users``).

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request("GET", self.endpoints["settings"])
        except Exception as e:
            return self._transport_failure(e)

    def set_strict_users(self, enabled: bool) -> Dict[str, Any]:
        """Enable/disable strict user identity for this tenant (idempotent).

        While enabled, authorization decisions about users with no live API
        key answer negatively (``reason: user_not_key_backed``) — issue keys
        before flipping this on.

        Transport failure raises :class:`AuthTransportError` — map it to
        your unavailable/503 path, never to a denial.
        """
        try:
            return self._make_request(
                "PUT", self.endpoints["settings"], json={"strict_users": enabled}
            )
        except Exception as e:
            return self._transport_failure(e, data={"strict_users": enabled})
