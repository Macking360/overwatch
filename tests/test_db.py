from overwatch.db import Database


def make_db(tmp_path):
    db = Database(tmp_path / "ow.db")
    db.init()
    return db


def test_users_and_roles(tmp_path):
    db = make_db(tmp_path)
    assert db.count_users() == 0
    uid = db.add_user("alice", "hash", role="admin")
    assert db.count_users() == 1
    assert db.count_admins() == 1
    assert db.get_user("alice")["id"] == uid
    db.add_user("bob", "hash", role="viewer")
    assert {r["username"] for r in db.list_users()} == {"alice", "bob"}
    db.set_role(uid, "viewer")
    assert db.count_admins() == 0


def test_bad_role_defaults_to_viewer(tmp_path):
    db = make_db(tmp_path)
    db.add_user("x", "h", role="superuser")
    assert db.get_user("x")["role"] == "viewer"


def test_events_source_and_counts(tmp_path):
    db = make_db(tmp_path)
    db.add_event("file", "/tmp/a", "modified", severity="warning")
    db.add_event("process", "p", "started", severity="notice", source="laptop")
    rows = db.recent_events()
    assert rows[0]["source"] == "laptop"
    assert rows[1]["source"] == "local"
    assert db.event_counts()["warning"] == 1
    assert len(db.recent_events(monitor="file")) == 1


def test_baselines(tmp_path):
    db = make_db(tmp_path)
    db.set_baseline("process", "1", "init")
    db.set_baseline("process", "1", "init2")  # upsert
    assert db.get_baseline("process") == {"1": "init2"}
    db.clear_baseline("process")
    assert db.get_baseline("process") == {}


def test_devices(tmp_path):
    db = make_db(tmp_path)
    did = db.add_device("laptop", "tokhash", "Windows 11")
    assert db.get_device(did)["status"] == "active"
    db.touch_device(did)
    assert db.get_device(did)["last_seen"] is not None
    db.set_device_status(did, "revoked")
    assert db.get_device(did)["status"] == "revoked"
    db.delete_device(did)
    assert db.get_device(did) is None
