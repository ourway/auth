"""Strict user identity, opt-in phase (SPEC 0008/0010) — HTTP-level.

The gate is tested in BOTH directions everywhere: strict mode blocks keyless
users AND releases them the moment a key is issued (or the mode is disabled),
and a tenant that never opts in behaves exactly like 2.4.1.
"""

import uuid

import pytest

from auth.main import create_app


@pytest.fixture
def app():
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _h(key):
    return {"Authorization": f"Bearer {key}"}


def _seed_rbac(client, key, user="alice"):
    h = _h(key)
    assert client.post("/api/role/engineers", headers=h).get_json()["result"] is True
    assert (
        client.post("/api/permission/engineers/deploy", headers=h).get_json()["result"]
        is True
    )
    assert (
        client.post(f"/api/membership/{user}/engineers", headers=h).get_json()["result"]
        is True
    )


def _has_permission(client, key, user="alice", perm="deploy"):
    return client.get(f"/api/has_permission/{user}/{perm}", headers=_h(key)).get_json()[
        "data"
    ]


def test_settings_default_and_toggle_roundtrip(client):
    key = str(uuid.uuid4())
    h = _h(key)
    assert client.get("/api/settings", headers=h).get_json()["data"] == {
        "strict_users": False
    }
    on = client.put("/api/settings", headers=h, json={"strict_users": True})
    assert on.status_code == 200
    assert on.get_json()["data"] == {"strict_users": True}
    assert client.get("/api/settings", headers=h).get_json()["data"] == {
        "strict_users": True
    }
    # Both directions: it turns off again.
    off = client.put("/api/settings", headers=h, json={"strict_users": False})
    assert off.get_json()["data"] == {"strict_users": False}
    assert client.get("/api/settings", headers=h).get_json()["data"] == {
        "strict_users": False
    }


def test_settings_input_validation(client):
    key = str(uuid.uuid4())
    h = _h(key)
    assert client.put("/api/settings", headers=h).status_code == 400
    assert (
        client.put("/api/settings", headers=h, json={"strict_users": "yes"}).status_code
        == 400
    )
    assert client.put("/api/settings", headers=h, json={}).status_code == 400
    assert client.get("/api/settings").status_code == 401


def test_strict_blocks_and_releases_permission_checks(client):
    key = str(uuid.uuid4())
    h = _h(key)
    _seed_rbac(client, key)

    # GREEN baseline: keyless user answers true while strict is off (2.4.1
    # behavior) — proves the block below is strict mode, not a broken seed.
    assert _has_permission(client, key) == {"has_permission": True}

    client.put("/api/settings", headers=h, json={"strict_users": True})

    blocked = _has_permission(client, key)
    assert blocked == {
        "has_permission": False,
        "reason": "user_not_key_backed",
    }
    # user_permissions and membership check and workflow can_run agree.
    perms = client.get("/api/user_permissions/alice", headers=h).get_json()["data"]
    assert perms["count"] == 0 and perms["reason"] == "user_not_key_backed"
    member = client.get("/api/membership/alice/engineers", headers=h).get_json()["data"]
    assert member == {"has_permission": False, "reason": "user_not_key_backed"}
    wf = client.get(
        "/api/workflow/user/alice/can_run/deploy", headers=h
    ).get_json()["data"]
    assert wf == {"has_permission": False, "reason": "user_not_key_backed"}

    # RELEASE direction 1: issuing a key restores every answer.
    client.post("/api/apikeys/user/alice", headers=h)
    assert _has_permission(client, key) == {"has_permission": True}
    assert (
        client.get("/api/user_permissions/alice", headers=h).get_json()["data"]["count"]
        == 1
    )
    assert client.get("/api/membership/alice/engineers", headers=h).get_json()["data"][
        "has_permission"
    ] is True

    # Revoking the only key blocks again (revocation is now end-to-end).
    key_id = client.get("/api/apikeys/user/alice", headers=h).get_json()["data"][
        "keys"
    ][0]["key_id"]
    client.delete(f"/api/apikeys/user/alice/{key_id}", headers=h)
    assert _has_permission(client, key)["has_permission"] is False

    # RELEASE direction 2: disabling strict mode restores 2.4.1 behavior.
    client.put("/api/settings", headers=h, json={"strict_users": False})
    assert _has_permission(client, key) == {"has_permission": True}


def test_strict_blocks_membership_add_but_never_removal(client):
    key = str(uuid.uuid4())
    h = _h(key)
    _seed_rbac(client, key, user="bob")  # bob is a member while strict is off
    client.put("/api/settings", headers=h, json={"strict_users": True})

    # Adds for keyless users are refused with an unmissable 409 (a 200 here
    # was shown by two consumers to be silently written past).
    add = client.post("/api/membership/carol/engineers", headers=h)
    assert add.status_code == 409
    assert add.get_json() == {"result": False, "reason": "user_not_key_backed"}
    # The documented missing-role no-op keeps its 200-false shape even in
    # strict tenants — only the key-less refusal is a 409.
    ghost_role = client.post("/api/membership/carol/ghosts", headers=h)
    assert ghost_role.status_code == 409  # carol is still key-less: strict wins
    client.post("/api/apikeys/user/dave", headers=h)
    keyed_ghost = client.post("/api/membership/dave/ghosts", headers=h)
    assert keyed_ghost.status_code == 200
    assert keyed_ghost.get_json() == {"result": False}

    # Removal is NEVER strict-gated: revocation must always work.
    rm = client.delete("/api/membership/bob/engineers", headers=h).get_json()
    assert rm == {"result": True}
    client.put("/api/settings", headers=h, json={"strict_users": False})
    assert (
        client.get("/api/membership/bob/engineers", headers=h).get_json()["data"][
            "has_permission"
        ]
        is False
    )

    # Bootstrap order under strict mode: key first, then membership works.
    client.put("/api/settings", headers=h, json={"strict_users": True})
    client.post("/api/apikeys/user/carol", headers=h)
    assert (
        client.post("/api/membership/carol/engineers", headers=h).get_json()["result"]
        is True
    )


def test_strict_mode_is_tenant_scoped(client):
    strict_tenant, normal_tenant = str(uuid.uuid4()), str(uuid.uuid4())
    _seed_rbac(client, strict_tenant)
    _seed_rbac(client, normal_tenant)
    client.put(
        "/api/settings", headers=_h(strict_tenant), json={"strict_users": True}
    )

    assert _has_permission(client, strict_tenant)["has_permission"] is False
    # The other tenant is untouched — byte-identical 2.4.1 behavior.
    assert _has_permission(client, normal_tenant) == {"has_permission": True}


def test_denial_reason_only_appears_when_strict_blocked(client):
    key = str(uuid.uuid4())
    h = _h(key)
    _seed_rbac(client, key)
    client.put("/api/settings", headers=h, json={"strict_users": True})
    client.post("/api/apikeys/user/alice", headers=h)

    # A key-backed user lacking the permission is a plain denial — no reason
    # key, so callers can distinguish denial from strict-block.
    denied = _has_permission(client, key, perm="launch_missiles")
    assert denied == {"has_permission": False}


def test_check_permission_composite_endpoint(client):
    key = str(uuid.uuid4())
    h = _h(key)
    _seed_rbac(client, key)
    secret = client.post("/api/apikeys/user/alice", headers=h).get_json()["data"][
        "api_key"
    ]

    ok = client.post(
        "/api/apikeys/check_permission",
        headers=h,
        json={"api_key": secret, "permission": "deploy"},
    ).get_json()["data"]
    assert ok["valid"] is True
    assert ok["user"] == "alice"
    assert ok["has_permission"] is True

    # Valid key, missing permission: valid stays true, answer is false.
    no = client.post(
        "/api/apikeys/check_permission",
        headers=h,
        json={"api_key": secret, "permission": "launch_missiles"},
    ).get_json()["data"]
    assert no == {
        "valid": True,
        "user": "alice",
        "key_id": no["key_id"],
        "has_permission": False,
    }

    # Works under strict mode too (the key IS the user's backing).
    client.put("/api/settings", headers=h, json={"strict_users": True})
    assert (
        client.post(
            "/api/apikeys/check_permission",
            headers=h,
            json={"api_key": secret, "permission": "deploy"},
        ).get_json()["data"]["has_permission"]
        is True
    )

    # Revoked key: validate-shaped red, no permission evaluation.
    key_id = client.get("/api/apikeys/user/alice", headers=h).get_json()["data"][
        "keys"
    ][0]["key_id"]
    client.delete(f"/api/apikeys/user/alice/{key_id}", headers=h)
    revoked = client.post(
        "/api/apikeys/check_permission",
        headers=h,
        json={"api_key": secret, "permission": "deploy"},
    ).get_json()["data"]
    assert revoked == {"valid": False, "reason": "revoked"}

    # Input validation.
    assert (
        client.post(
            "/api/apikeys/check_permission",
            headers=h,
            json={"api_key": secret, "permission": "bad name!"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/apikeys/check_permission", headers=h, json={"api_key": "nope"}
        ).status_code
        == 400
    )
    assert client.post("/api/apikeys/check_permission", headers=h).status_code == 400


def test_rotation_carries_strict_setting(client):
    key = str(uuid.uuid4())
    h = _h(key)
    _seed_rbac(client, key)
    client.post("/api/apikeys/user/alice", headers=h)
    client.put("/api/settings", headers=h, json={"strict_users": True})

    rotated = client.post("/api/keys/rotate", headers=h).get_json()["data"]
    assert rotated["migrated"]["settings"] == 1
    h_new = _h(rotated["new_key"])
    # Strict survives rotation; the key-backed user still answers true.
    assert client.get("/api/settings", headers=h_new).get_json()["data"] == {
        "strict_users": True
    }
    assert (
        client.get("/api/has_permission/alice/deploy", headers=h_new).get_json()[
            "data"
        ]["has_permission"]
        is True
    )


def test_settings_update_is_audited(client):
    from auth.audit import AuditLog
    from auth.database import SessionLocal

    key = str(uuid.uuid4())
    client.put("/api/settings", headers=_h(key), json={"strict_users": True})
    session = SessionLocal()
    try:
        actions = {row.action for row in session.query(AuditLog).all()}
        assert "UPDATE_SETTINGS" in actions
    finally:
        session.close()


def test_in_process_service_override_param():
    """Library callers pin strict behavior explicitly, DB row ignored."""
    import uuid as _uuid

    from auth.database import SessionLocal
    from auth.main import create_app
    from auth.services.service import AuthorizationService

    create_app()
    tenant = str(_uuid.uuid4())
    db = SessionLocal()
    try:
        svc = AuthorizationService(db, tenant)
        svc.set_strict_users(True)
        assert AuthorizationService(db, tenant).strict_users_enabled() is True
        # Explicit override beats the stored row, both ways.
        assert (
            AuthorizationService(db, tenant, strict_users=False).strict_users_enabled()
            is False
        )
        off = AuthorizationService(db, tenant, strict_users=True)
        svc.set_strict_users(False)
        assert off.strict_users_enabled() is True
    finally:
        db.close()
