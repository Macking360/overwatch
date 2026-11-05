from overwatch import identity


def test_issue_and_verify_roundtrip():
    conn_fp = {"ip": "10.0.0.5", "user_agent": "pytest"}
    pid, cert = identity.issue_certificate("secret", 7, "alice", conn_fp, role="admin")
    assert pid.startswith("OW-000007-")
    assert cert["subject"] == "alice" and cert["role"] == "admin"
    assert cert["connection_fingerprint"] == conn_fp
    assert identity.verify_certificate("secret", cert) is True


def test_pid_aligns_to_fingerprint():
    fp1 = {"ip": "10.0.0.5"}
    fp2 = {"ip": "10.0.0.6"}
    pid1, _ = identity.issue_certificate("s", 1, "u", fp1)
    pid2, _ = identity.issue_certificate("s", 1, "u", fp2)
    # Same user, different connection fingerprint -> different PID suffix.
    assert pid1 != pid2


def test_tampering_breaks_signature():
    pid, cert = identity.issue_certificate("secret", 1, "bob", {"ip": "1.1.1.1"})
    cert["role"] = "admin"  # privilege tamper
    assert identity.verify_certificate("secret", cert) is False


def test_wrong_key_fails():
    pid, cert = identity.issue_certificate("secret", 1, "bob", {"ip": "1.1.1.1"})
    assert identity.verify_certificate("other-secret", cert) is False


def test_verify_handles_garbage():
    assert identity.verify_certificate("s", None) is False
    assert identity.verify_certificate("s", {"no": "signature"}) is False
