import re

import pytest

from auth.main import create_app
from auth.validation import validate_permission_name

CANONICAL = "https://auth.rodmena.com"
RETIRED = ("https://auth.rodmena.app", "https://auth.rodmena.co.uk")
PAGES = ["/", "/docs", "/llms.txt", "/claude"]


@pytest.fixture(scope="module")
def pages():
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    served = {}
    for path in PAGES:
        response = client.get(path, headers={"Accept": "*/*"})
        assert response.status_code == 200, path
        served[path] = response.get_data(as_text=True)
    return served


@pytest.mark.parametrize("path", PAGES)
def test_pages_use_the_canonical_host(pages, path):
    text = pages[path]
    assert CANONICAL in text
    for host in RETIRED:
        assert host not in text


@pytest.mark.parametrize("path", PAGES)
def test_pages_do_not_recommend_a_rejected_permission_name(pages, path):
    assert "doc:123:edit" not in pages[path]


def test_the_documented_scoped_name_is_one_the_api_accepts(pages):
    shown = set(re.findall(r"`(doc[-:]\d+[-:]edit)`", pages["/llms.txt"]))
    assert shown == {"doc-123-edit"}
    assert validate_permission_name("doc-123-edit")
    assert not validate_permission_name("doc:123:edit")


def test_reference_documents_the_migration_command(pages):
    text = pages["/llms.txt"]
    assert "auth-migrate apply" in text
    assert "AUTH_DATABASE_SCHEMA=auth_rbac" in text
