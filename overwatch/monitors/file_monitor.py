"""File-integrity monitoring via watchdog.

A FileMonitor watches the directory containing one or more target paths and
reports create/modify/move/delete events for those paths through a callback.
The handler logic is deliberately split out so it can be unit-tested without a
live filesystem observer.
"""

from __future__ import annotations

import os
from typing import Callable, Iterable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

# callback(action, target_path, detail)
EventCallback = Callable[[str, str, str], None]

_ACTION_SEVERITY = {
    "created": "notice",
    "modified": "notice",
    "moved": "warning",
    "deleted": "warning",
}


def classify(action: str) -> str:
    """Map a watchdog event type to an OverWatch severity."""
    return _ACTION_SEVERITY.get(action, "info")


class _Recorder(FileSystemEventHandler):
    """Turns filesystem events on watched paths into callback invocations."""

    def __init__(self, watched: set[str], on_event: EventCallback) -> None:
        self._watched = watched
        self._on_event = on_event

    def _emit(self, action: str, path: str, detail: str = "") -> None:
        resolved = os.path.abspath(path)
        if resolved in self._watched:
            self._on_event(action, resolved, detail)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("deleted", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            dest = getattr(event, "dest_path", "")
            self._emit("moved", event.src_path, f"-> {dest}")
            # The destination may also be a watched path.
            if dest:
                self._emit("moved", dest, f"<- {event.src_path}")


class FileMonitor:
    def __init__(self, paths: Iterable[str], on_event: EventCallback) -> None:
        self.paths = [os.path.abspath(p) for p in paths]
        self._watched = set(self.paths)
        self._on_event = on_event
        self._observer: Observer | None = None

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def start(self) -> None:
        if self.running:
            return
        observer = Observer()
        recorder = _Recorder(self._watched, self._on_event)
        # Schedule each distinct parent directory once.
        for directory in sorted({os.path.dirname(p) or "." for p in self.paths}):
            os.makedirs(directory, exist_ok=True)
            observer.schedule(recorder, path=directory, recursive=False)
        observer.start()
        self._observer = observer

    def stop(self, timeout: float = 5.0) -> None:
        if self._observer is None:
            return
        self._observer.stop()
        self._observer.join(timeout=timeout)
        self._observer = None
