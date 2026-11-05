from overwatch.monitors import file_monitor, process_monitor, registry_monitor


class FakeEvent:
    def __init__(self, src_path, is_directory=False, dest_path=None):
        self.src_path = src_path
        self.is_directory = is_directory
        self.event_type = "modified"
        if dest_path is not None:
            self.dest_path = dest_path


def test_file_recorder_only_emits_for_watched_paths(tmp_path):
    watched = str(tmp_path / "hosts")
    seen = []
    rec = file_monitor._Recorder({watched}, lambda a, t, d: seen.append((a, t, d)))

    rec.on_modified(FakeEvent(watched))
    rec.on_modified(FakeEvent(str(tmp_path / "other")))  # not watched
    rec.on_created(FakeEvent(watched, is_directory=True))  # directory ignored

    assert seen == [("modified", watched, "")]


def test_file_classify():
    assert file_monitor.classify("deleted") == "warning"
    assert file_monitor.classify("modified") == "notice"
    assert file_monitor.classify("weird") == "info"


def test_process_diff():
    started, stopped = process_monitor.diff({1: "init"}, {1: "init", 2: "bash"})
    assert started == [(2, "bash")]
    assert stopped == []
    started, stopped = process_monitor.diff({1: "init", 9: "x"}, {1: "init"})
    assert stopped == [(9, "x")]


def test_registry_diff():
    added, changed, removed = registry_monitor.diff(
        {"a": "1", "b": "2"}, {"a": "1", "b": "9", "c": "3"}
    )
    assert added == [("c", "3")]
    assert changed == [("b", "2 -> 9")]
    assert removed == []


def test_registry_unsupported_off_windows():
    # On the Linux CI host this is a no-op reader.
    if not registry_monitor.available():
        assert registry_monitor.read_autoruns() == {}
