from overwatch import devices
from overwatch.db import Database


def test_issue_and_verify_token(tmp_path):
    db = Database(tmp_path / "ow.db")
    db.init()
    token = devices.issue_token(db, "laptop", "Windows 11")
    assert "." in token
    device_id = devices.verify_token(db, token)
    assert device_id == 1


def test_verify_rejects_garbage(tmp_path):
    db = Database(tmp_path / "ow.db")
    db.init()
    devices.issue_token(db, "laptop")
    assert devices.verify_token(db, "") is None
    assert devices.verify_token(db, "notoken") is None
    assert devices.verify_token(db, "1.wrongsecret") is None
    assert devices.verify_token(db, "99.whatever") is None


def test_verify_rejects_revoked(tmp_path):
    db = Database(tmp_path / "ow.db")
    db.init()
    token = devices.issue_token(db, "laptop")
    db.set_device_status(1, "revoked")
    assert devices.verify_token(db, token) is None
