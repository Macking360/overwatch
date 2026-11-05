import os

from overwatch import fingerprint
from overwatch.monitors import process_monitor


def test_fingerprint_collect_has_core_fields():
    fp = fingerprint.collect()
    for key in ("hostname", "system", "platform", "machine", "primary_mac"):
        assert key in fp
    assert isinstance(fp["primary_mac"], str)
    assert fp["primary_mac"].count(":") == 5


def test_process_details_self():
    d = process_monitor.details(os.getpid())
    assert d["pid"] == os.getpid()


def test_process_describe_is_string():
    assert isinstance(process_monitor.describe(os.getpid()), str)


def test_process_details_unknown_pid_is_safe():
    d = process_monitor.details(2_000_000_000)
    assert d == {"pid": 2_000_000_000}
