import pytest

from overwatch.config import Config
from overwatch.db import Database
from overwatch.web import create_app


@pytest.fixture
def ctx(tmp_path):
    config = Config(instance_dir=tmp_path)
    app = create_app(config)
    app.config.update(TESTING=True)
    client = app.test_client()
    db = Database(config.database)
    return config, db, client


def register(client, username, password):
    return client.post(
        "/register",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_first_user_is_admin_and_can_reach_monitor(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")
    assert db.get_user("alice")["role"] == "admin"
    login(client, "alice", "pw")
    assert client.get("/monitor").status_code == 200
    assert client.get("/devices").status_code == 200
    assert client.get("/users").status_code == 200


def test_registration_closes_after_first_user(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")
    resp = register(client, "mallory", "pw")
    assert db.get_user("mallory") is None
    assert b"Registration is closed" in resp.data


def test_viewer_cannot_reach_admin_pages(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")  # admin
    from overwatch import auth
    db.add_user("vic", auth.hash_password("pw"), role="viewer")
    login(client, "vic", "pw")
    # viewer may read the dashboard...
    assert client.get("/dashboard").status_code == 200
    # ...but is redirected away from admin write pages
    resp = client.get("/monitor", follow_redirects=True)
    assert b"requires an administrator" in resp.data


def test_login_required_redirect(ctx):
    config, db, client = ctx
    resp = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in" in resp.data


def test_help_is_public(ctx):
    config, db, client = ctx
    resp = client.get("/help")
    assert resp.status_code == 200
    assert b"defensive host-integrity monitor" in resp.data


def test_bad_login_fails(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")
    resp = login(client, "alice", "wrong")
    assert b"Login failed" in resp.data


def test_enroll_requires_key_then_ingests_events(ctx):
    config, db, client = ctx
    # Wrong key rejected.
    assert client.post("/api/enroll", json={"name": "d"},
                       headers={"X-Enroll-Key": "nope"}).status_code == 403
    # Correct key mints a token.
    resp = client.post("/api/enroll", json={"name": "laptop", "platform": "Win"},
                       headers={"X-Enroll-Key": config.enroll_key})
    assert resp.status_code == 201
    token = resp.get_json()["token"]

    # Token ingests events, recorded under the device name.
    ing = client.post(
        "/api/events",
        json={"events": [{"monitor": "file", "target": "C:/x", "action": "modified",
                          "severity": "warning"}]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ing.status_code == 202
    assert ing.get_json()["stored"] == 1
    rows = db.recent_events()
    assert rows[0]["source"] == "laptop"
    assert rows[0]["severity"] == "warning"


def test_ingest_rejects_bad_token(ctx):
    config, db, client = ctx
    resp = client.post("/api/events", json={"events": []},
                       headers={"Authorization": "Bearer 1.bad"})
    assert resp.status_code == 401


def test_healthz_is_public(ctx):
    config, db, client = ctx
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok" and "version" in body


def test_events_csv_export(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")
    login(client, "alice", "pw")
    db.add_event("file", "/x", "modified", severity="warning")
    resp = client.get("/events.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["Content-Type"]
    assert b"modified" in resp.data


def test_events_clear_admin_only(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")  # admin
    db.add_event("file", "/x", "modified")
    login(client, "alice", "pw")
    resp = client.post("/events/clear", follow_redirects=True)
    assert resp.status_code == 200
    assert db.event_counts() == {}


def test_user_creation_issues_identity_certificate(ctx):
    config, db, client = ctx
    register(client, "alice", "pw")  # first user -> admin
    user = db.get_user("alice")
    assert user["pid"] and user["pid"].startswith("OW-000001-")
    import json as _json
    from overwatch import identity
    cert = _json.loads(user["credential"])
    assert cert["subject"] == "alice" and cert["role"] == "admin"
    assert identity.verify_certificate(config.secret_key, cert) is True

    # Admin can view the credential and cross-reference it by PID.
    login(client, "alice", "pw")
    page = client.get(f"/users/{user['id']}/credential")
    assert page.status_code == 200 and b"signature valid" in page.data
    api = client.get(f"/api/identity/{user['pid']}")
    assert api.status_code == 200
    assert api.get_json()["valid"] is True


def test_enroll_stores_fingerprint(ctx):
    config, db, client = ctx
    resp = client.post(
        "/api/enroll",
        json={"name": "lap", "platform": "Win11",
              "fingerprint": {"hostname": "h1", "primary_mac": "00:11:22:33:44:55"}},
        headers={"X-Enroll-Key": config.enroll_key},
    )
    assert resp.status_code == 201
    dev = db.get_device(1)
    assert dev["platform"] == "Win11"
    assert "hostname" in (dev["fingerprint"] or "")
