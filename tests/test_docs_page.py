"""
Tests for the self-describing docs served at `/`.

The page exists so an agent handed only the base URL can call the API
correctly, so these tests pin the two things that would silently break that:
the page must stay reachable without credentials, and the gotchas it documents
must still be the ones the API actually exhibits.
"""

import pytest

from auth.docs_page import render_markdown
from auth.main import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.mark.parametrize("path", ["/", "/docs", "/llms.txt"])
def test_docs_paths_serve_without_authentication(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "RBAC authorization service" in response.get_data(as_text=True)


def test_root_serves_markdown_to_agents(client):
    """curl and HTTP libraries send `*/*` — they get Markdown, not HTML."""
    response = client.get("/", headers={"Accept": "*/*"})
    assert response.mimetype == "text/markdown"
    assert response.get_data(as_text=True).startswith("# auth")


def test_root_serves_html_to_browsers(client):
    response = client.get(
        "/", headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    )
    assert response.mimetype == "text/html"
    body = response.get_data(as_text=True)
    assert body.startswith("<!doctype html>")
    # Markdown is escaped into the <pre>, so tables must not become markup.
    assert "<table" not in body


def test_llms_txt_is_always_markdown(client):
    response = client.get("/llms.txt", headers={"Accept": "text/html"})
    assert response.mimetype == "text/markdown"


def test_documented_version_matches_package():
    from auth import __version__

    assert f"Version {__version__}." in render_markdown()


def test_documents_every_registered_api_route():
    """A new endpoint must not ship undocumented."""
    app = create_app()
    documented = render_markdown()
    api_rules = {
        rule.rule for rule in app.url_map.iter_rules() if rule.rule.startswith("/api/")
    }
    assert api_rules, "expected the API routes to be registered"

    # Strip Flask's converters: /api/role/<role> -> /api/role/
    undocumented = [
        rule for rule in api_rules if rule.split("<")[0].rstrip("/") not in documented
    ]
    assert not undocumented, f"routes missing from the docs page: {sorted(undocumented)}"


def test_writes_to_a_missing_role_return_200_false(client, monkeypatch):
    """The headline gotcha in section 3 — pinned so the docs cannot go stale."""
    import uuid

    headers = {"Authorization": f"Bearer {uuid.uuid4()}"}

    response = client.post("/api/membership/alice/role-that-does-not-exist", headers=headers)
    assert response.status_code == 200
    assert response.get_json() == {"result": False}

    response = client.post("/api/permission/role-that-does-not-exist/deploy", headers=headers)
    assert response.status_code == 200
    assert response.get_json() == {"result": False}


def test_membership_check_answers_with_has_permission_key(client):
    """Section 3 documents this misnomer; fail loudly if it is ever renamed."""
    import uuid

    headers = {"Authorization": f"Bearer {uuid.uuid4()}"}
    response = client.get("/api/membership/alice/engineers", headers=headers)
    assert response.status_code == 200
    assert "has_permission" in response.get_json()["data"]
