import time

from overwatch.config import Config
from overwatch.db import Database
from overwatch.engine import OverwatchTool
from overwatch.monitors.file_monitor import FileMonitor
from overwatch.net import RemoteForwarder


def _make(tmp_path):
    cfg = Config(instance_dir=tmp_path)
    cfg.poll_interval = 0.2
    db = Database(cfg.database)
    db.init()
    return cfg, db


def test_heartbeat_loop_emits_alive(tmp_path):
    cfg, db = _make(tmp_path)
    eng = OverwatchTool(cfg, db, source="node-a")
    eng.start_heartbeat(0.2)
    try:
        time.sleep(0.7)
    finally:
        eng.stop()
    beats = [e for e in db.recent_events(limit=50)
             if e["monitor"] == "heartbeat" and e["action"] == "alive"]
    assert beats, "expected at least one heartbeat"
    assert beats[0]["source"] == "node-a"
    assert eng.status()["heartbeat"] is False  # stopped


def test_forwarders_receive_event_dict(tmp_path):
    cfg, db = _make(tmp_path)
    got = []
    eng = OverwatchTool(cfg, db, source="node-a", forwarders=[got.append])
    eng.log_activity("file", "/x", "modified", severity="notice")
    assert got and got[0]["source"] == "node-a"
    assert got[0]["action"] == "modified" and got[0]["monitor"] == "file"


def test_file_monitor_live_detects_modify(tmp_path):
    target = tmp_path / "watched.txt"
    target.write_text("a", encoding="utf-8")
    seen = []
    mon = FileMonitor([str(target)], lambda a, t, d: seen.append((a, t)))
    mon.start()
    try:
        time.sleep(0.3)
        target.write_text("b", encoding="utf-8")
        for _ in range(50):
            if seen:
                break
            time.sleep(0.1)
    finally:
        mon.stop()
    assert any(t.endswith("watched.txt") for _, t in seen), f"no event seen: {seen}"


def test_forwarder_buffers_on_failure():
    # Nothing is listening on port 1 -> every post fails and events buffer.
    fwd = RemoteForwarder("http://127.0.0.1:1/", "1.secret", timeout=0.3)
    assert fwd({"a": 1}) is False
    assert fwd.pending == 1
    assert fwd({"b": 2}) is False
    assert fwd.pending == 2
