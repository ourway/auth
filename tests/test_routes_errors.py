"""
Error-path tests for the Flask API: header parsing, status codes, and the
JSON error handler. Success shapes are pinned by test_flask.py; these pin
the failure contract.
"""

import uuid
from unittest.mock import patch

import pytest

from auth.main import create_app

KEY = str(uuid.uuid4())


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_missing_authorization_header_is_401(client):
    assert client.get("/api/roles").status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        " ",  # whitespace-only: was IndexError -> 500
        "Bearer",  # no token
        "Bearer a b",  # too many parts
        "Token xyz",  # wrong scheme
    ],
)
def test_malformed_authorization_header_is_401(client, header):
    response = client.get("/api/roles", headers={"Authorization": header})
    assert response.status_code == 401


def test_lowercase_bearer_is_accepted(client):
    response = client.get("/api/roles", headers={"Authorization": f"bearer {KEY}"})
    assert response.status_code == 200


def test_non_uuid_client_key_is_400(client):
    response = client.get(
        "/api/roles", headers={"Authorization": "Bearer not-a-uuid"}
    )
    assert response.status_code == 400


def test_invalid_role_name_is_400(client):
    response = client.post(
        "/api/role/bad!name", headers={"Authorization": f"Bearer {KEY}"}
    )
    assert response.status_code == 400


def test_unhandled_exception_returns_json_envelope(client):
    with patch(
        "auth.services.service.AuthorizationService.get_roles",
        side_effect=RuntimeError("boom"),
    ):
        response = client.get("/api/roles", headers={"Authorization": f"Bearer {KEY}"})
    assert response.status_code == 500
    body = response.get_json()  # was an HTML page before
    assert body["success"] is False
    assert body["code"] == 500


def test_email_user_names_accepted_over_rest(client):
    """The documented REST examples use emails; the Python API accepts them,
    so the REST validation must too (regression: 400 before 1.4.0)."""
    headers = {"Authorization": f"Bearer {KEY}"}
    assert client.post("/api/role/support", headers=headers).status_code == 200
    response = client.post(
        "/api/membership/alice.smith+dev@example.com/support", headers=headers
    )
    assert response.status_code == 200
    assert response.get_json() == {"result": True}
    check = client.get(
        "/api/membership/alice.smith+dev@example.com/support", headers=headers
    )
    assert check.get_json()["data"]["has_permission"] is True


def test_ping_shape_pinned(client):
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.get_json() == {"message": "PONG"}


def test_health_endpoint_shape(client):
    body = client.get("/health").get_json()
    assert body["status"] == "healthy"
    assert "pool_size" in body["database"]
