import re

from overwatch.config import Config
from overwatch.web import create_app


def test_csrf_blocks_then_allows(tmp_path):
    # A non-TESTING app enforces CSRF on browser POSTs.
    app = create_app(Config(instance_dir=tmp_path))
    client = app.test_client()

    # POST with no token is rejected.
    blocked = client.post("/register", data={"username": "a", "password": "b"})
    assert blocked.status_code == 400

    # Fetch the form, read the token, and the same POST now succeeds.
    page = client.get("/register").get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert m, "csrf token field not rendered"
    ok = client.post(
        "/register",
        data={"username": "a", "password": "b", "csrf_token": m.group(1)},
        follow_redirects=True,
    )
    assert ok.status_code == 200
    assert b"can now log in" in ok.data


def test_api_is_csrf_exempt(tmp_path):
    # The device ingest API uses bearer tokens, so it must not require CSRF.
    config = Config(instance_dir=tmp_path)
    app = create_app(config)
    client = app.test_client()
    resp = client.post(
        "/api/enroll",
        json={"name": "d"},
        headers={"X-Enroll-Key": config.enroll_key},
    )
    assert resp.status_code == 201
