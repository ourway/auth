import json
import os
import subprocess
import sys

import pytest

import auth

FOOTPRINT_SCRIPT = """
import json, sys
import auth, auth.main
served = sorted(m for m in ("requests", "urllib3", "brotli") if m in sys.modules)
from auth import AuthRefused, AuthTransportError, Client, EnhancedAuthClient
from auth.core import Client as CoreClient, EnhancedAuthClient as CoreEnhanced
import auth.client as real
same = {
    "Client": Client is real.Client,
    "EnhancedAuthClient": EnhancedAuthClient is real.EnhancedAuthClient,
    "AuthRefused": AuthRefused is real.AuthRefused,
    "AuthTransportError": AuthTransportError is real.AuthTransportError,
    "core.Client": CoreClient is real.Client,
    "core.EnhancedAuthClient": CoreEnhanced is real.EnhancedAuthClient,
}
after_client = sorted(m for m in ("requests", "urllib3") if m in sys.modules)
print(json.dumps({"served": served, "same": same, "after_client": after_client}))
"""


def _run(tmp_path, script):
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AUTH_") and key != "PGSSLMODE"
    }
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(auth.__file__)))
    env.update(
        PYTHONPATH=package_root,
        AUTH_DATABASE_TYPE="sqlite",
        AUTH_SQLITE_PATH=f"{tmp_path}/footprint.db",
        AUTH_ENABLE_ENCRYPTION="false",
        AUTH_JWT_SECRET_KEY="import-footprint-test-secret-0001",
        AUTH_AUDIT_PEPPER="import-footprint-test-pepper-0001",
        AUTH_ENABLE_RATE_LIMIT="false",
    )
    return subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture(scope="module")
def footprint(tmp_path_factory):
    result = _run(tmp_path_factory.mktemp("footprint"), FOOTPRINT_SCRIPT)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_serving_process_does_not_load_the_http_client_stack(footprint):
    assert footprint["served"] == []


def test_detector_sees_the_client_stack_once_the_client_is_used(footprint):
    assert footprint["after_client"] == ["requests", "urllib3"]


@pytest.mark.parametrize(
    "name",
    [
        "Client",
        "EnhancedAuthClient",
        "AuthRefused",
        "AuthTransportError",
        "core.Client",
        "core.EnhancedAuthClient",
    ],
)
def test_lazy_exports_are_the_client_module_objects(footprint, name):
    assert footprint["same"][name] is True


def test_unknown_attribute_still_raises_attribute_error():
    with pytest.raises(AttributeError, match="no attribute 'NoSuchThing'"):
        auth.NoSuchThing  # noqa: B018


def test_client_names_stay_in_the_public_api():
    for name in ("AuthRefused", "AuthTransportError", "Client", "EnhancedAuthClient"):
        assert name in auth.__all__
