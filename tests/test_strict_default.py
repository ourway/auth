"""3.0.0 strict-by-default mechanics (SPEC 0012).

The legacy suites run with AUTH_STRICT_USERS_DEFAULT=false (the grandfathered
reality of every pre-3.0 tenant); these tests cover the 3.0.0 default itself
and the one-shot grandfathering pass that guarantees the flip reaches only
tenants created after it ran.
"""

import uuid
from typing import cast

import pytest
from sqlalchemy import Table, delete, select

from auth.config import get_settings
from auth.database import GRANDFATHER_MARKER, _grandfather_strict_users
from auth.main import create_app
from auth.models.sql import AuthTenantSettings
from auth.services.service import AuthorizationService


@pytest.fixture(autouse=True)
def _app():
    create_app()


def _strict_default(monkeypatch, value: bool):
    monkeypatch.setattr(get_settings(), "strict_users_default", value)


def test_no_row_tenant_follows_server_default(monkeypatch):
    from auth.database import SessionLocal

    tenant = str(uuid.uuid4())
    db = SessionLocal()
    try:
        # Green baseline: with default false (test env), no-row means lax.
        assert AuthorizationService(db, tenant).strict_users_enabled() is False
        # 3.0.0 production shape: default true governs no-row tenants...
        _strict_default(monkeypatch, True)
        assert AuthorizationService(db, tenant).strict_users_enabled() is True
        # ...but an explicit row always wins over the default, both ways.
        svc = AuthorizationService(db, tenant)
        svc.set_strict_users(False)
        assert AuthorizationService(db, tenant).strict_users_enabled() is False
        svc.set_strict_users(True)
        _strict_default(monkeypatch, False)
        assert AuthorizationService(db, tenant).strict_users_enabled() is True
    finally:
        db.close()


def test_new_tenant_is_strict_end_to_end(monkeypatch):
    _strict_default(monkeypatch, True)
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    tenant = str(uuid.uuid4())
    h = {"Authorization": f"Bearer {tenant}"}

    assert client.post("/api/role/ops", headers=h).get_json()["result"] is True
    # Key-less grant refused (409) in the strict new world...
    refused = client.post("/api/membership/zoe/ops", headers=h)
    assert refused.status_code == 409
    # ...key first, then everything works (the release direction).
    client.post("/api/apikeys/user/zoe", headers=h)
    assert client.post("/api/membership/zoe/ops", headers=h).get_json()["result"] is True
    # And the audited opt-out immediately restores lax behavior.
    client.put("/api/settings", headers=h, json={"strict_users": False})
    assert client.post("/api/membership/keyless/ops", headers=h).get_json() == {
        "result": True
    }


def test_grandfather_pass_is_one_shot_and_covers_existing_creators():
    from auth.database import SessionLocal, engine

    settings_t = cast(Table, AuthTenantSettings.__table__)
    db = SessionLocal()
    try:
        # The boot pass has already stamped this test database; remove the
        # marker so the pass can be exercised from scratch.
        db.execute(
            delete(settings_t).where(settings_t.c.creator == GRANDFATHER_MARKER)
        )
        db.commit()

        veteran = str(uuid.uuid4())
        AuthorizationService(db, veteran).add_role("old-guard")
        assert (
            db.execute(
                select(settings_t.c.creator).where(settings_t.c.creator == veteran)
            ).first()
            is None
        )

        _grandfather_strict_users(engine)

        row = db.execute(
            select(settings_t.c.strict_users).where(settings_t.c.creator == veteran)
        ).one()
        assert row.strict_users is False
        assert (
            db.execute(
                select(settings_t.c.id).where(
                    settings_t.c.creator == GRANDFATHER_MARKER
                )
            ).first()
            is not None
        )

        # One-shot: a creator appearing AFTER the marker is NOT grandfathered,
        # even across repeated boots.
        newcomer = str(uuid.uuid4())
        AuthorizationService(db, newcomer).add_role("new-blood")
        _grandfather_strict_users(engine)
        assert (
            db.execute(
                select(settings_t.c.creator).where(settings_t.c.creator == newcomer)
            ).first()
            is None
        )

        # An existing EXPLICIT setting is never clobbered by the pass.
        opted_in = str(uuid.uuid4())
        svc = AuthorizationService(db, opted_in)
        svc.add_role("strict-club")
        svc.set_strict_users(True)
        db.execute(
            delete(settings_t).where(settings_t.c.creator == GRANDFATHER_MARKER)
        )
        db.commit()
        _grandfather_strict_users(engine)
        row = db.execute(
            select(settings_t.c.strict_users).where(settings_t.c.creator == opted_in)
        ).one()
        assert row.strict_users is True
    finally:
        db.close()
