"""OverwatchTool — the monitoring engine.

This is the modern, defensive successor to the original ``OverwatchTool`` class.
It owns the three monitors (file / process / registry), records every change to
the activity log and the database, and fans critical events out to the opt-in
alert webhook. It observes only; it never hides or modifies anything on the host.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from .alerts import send_alert
from .config import Config
from .db import Database
from .monitors import file_monitor, process_monitor, registry_monitor


class OverwatchTool:
    def __init__(
        self,
        config: Config,
        db: Database,
        source: str = "local",
        forwarders: Optional[list[Callable[[dict], object]]] = None,
    ) -> None:
        self.config = config
        self.db = db
        # Label applied to every event this engine records (hostname in agent
        # mode, "local" for the central server's own monitors).
        self.source = source or "local"
        # Extra sinks (e.g. a RemoteForwarder) invoked after the local write.
        self.forwarders: list[Callable[[dict], object]] = list(forwarders or [])

        self._file_monitors: list[file_monitor.FileMonitor] = []
        self._watched_paths: set[str] = set()

        self._poll_thread: Optional[threading.Thread] = None
        self._poll_stop = threading.Event()
        self._process_watch = False
        self._registry_watch = False

        # Optional heartbeat loop: periodically emits an "alive" event so the
        # fleet can see a quiet device is still reporting (and drains the
        # forwarder's retry buffer on a steady cadence).
        self._heartbeat_interval = 0.0
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        self._logger = logging.getLogger("overwatch.activity")
        self._lock = threading.Lock()

    # -- status --------------------------------------------------------------

    @property
    def watched_paths(self) -> list[str]:
        return sorted(self._watched_paths)

    def status(self) -> dict[str, object]:
        return {
            "file_paths": self.watched_paths,
            "file_watch": any(m.running for m in self._file_monitors),
            "process_watch": self._process_watch,
            "process_supported": process_monitor.available(),
            "registry_watch": self._registry_watch,
            "registry_supported": registry_monitor.available(),
            "poll_interval": self.config.poll_interval,
            "alerts_enabled": bool(self.config.alert_webhook),
            "heartbeat_interval": self._heartbeat_interval,
            "heartbeat": bool(self._heartbeat_thread and self._heartbeat_thread.is_alive()),
        }

    # -- logging -------------------------------------------------------------

    def log_activity(
        self,
        monitor: str,
        target: str,
        action: str,
        severity: str = "info",
        detail: str = "",
    ) -> None:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp} [{severity}] {self.source} {monitor}: {action} {target} {detail}".rstrip()
        self._logger.info(line)

        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": self.source,
            "monitor": monitor,
            "severity": severity,
            "target": target,
            "action": action,
            "detail": detail,
        }
        try:
            self.db.add_event(
                monitor, target, action, severity=severity, detail=detail,
                source=self.source, ts=event["ts"],
            )
        except Exception:  # noqa: BLE001 - never let logging crash a monitor thread
            self._logger.exception("failed to persist event")

        for forward in self.forwarders:
            try:
                forward(event)
            except Exception:  # noqa: BLE001
                self._logger.exception("event forwarder failed")

        if severity in ("warning", "critical") and self.config.alert_webhook:
            send_alert(self.config.alert_webhook, f"OverWatch: {line}", self.config.alert_timeout)

    # -- file monitoring -----------------------------------------------------

    def watch_file(self, path: str) -> None:
        with self._lock:
            monitor = file_monitor.FileMonitor(
                [path],
                on_event=lambda action, target, detail: self.log_activity(
                    "file", target, action, severity=file_monitor.classify(action), detail=detail
                ),
            )
            monitor.start()
            self._file_monitors.append(monitor)
            self._watched_paths.add(monitor.paths[0])
        self.log_activity("file", monitor.paths[0], "watch_started", severity="notice")

    # -- process + registry polling -----------------------------------------

    def enable_process_watch(self) -> None:
        self._process_watch = True
        self.db.replace_baseline(
            "process", {str(pid): name for pid, name in process_monitor.snapshot().items()}
        )
        self._ensure_poller()
        self.log_activity("process", "all", "watch_started", severity="notice")

    def enable_registry_watch(self) -> None:
        self._registry_watch = True
        self.db.replace_baseline("registry", dict(registry_monitor.read_autoruns()))
        self._ensure_poller()
        supported = registry_monitor.available()
        self.log_activity(
            "registry",
            "autoruns",
            "watch_started" if supported else "watch_unsupported",
            severity="notice" if supported else "info",
            detail="" if supported else "registry monitoring requires Windows",
        )

    # -- heartbeat loop ------------------------------------------------------

    def start_heartbeat(self, interval: float) -> None:
        """Begin (or restart) the heartbeat loop. interval <= 0 disables it."""
        self.stop_heartbeat()
        self._heartbeat_interval = float(interval)
        if interval <= 0:
            return
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="overwatch-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()
        self.log_activity(
            "heartbeat", self.source, "heartbeat_started",
            severity="notice", detail=f"every {interval:g}s",
        )

    def stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=self._heartbeat_interval + 2)
            self._heartbeat_thread = None

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.wait(self._heartbeat_interval):
            self.log_activity(
                "heartbeat", self.source, "alive",
                severity="info", detail=f"interval {self._heartbeat_interval:g}s",
            )

    def _ensure_poller(self) -> None:
        if self._poll_thread and self._poll_thread.is_alive():
            return
        self._poll_stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop, name="overwatch-poller", daemon=True
        )
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._poll_stop.is_set():
            if self._process_watch:
                self._sweep_processes()
            if self._registry_watch and registry_monitor.available():
                self._sweep_registry()
            self._poll_stop.wait(self.config.poll_interval)

    def _sweep_processes(self) -> None:
        baseline = {int(k): v for k, v in self.db.get_baseline("process").items()}
        current = process_monitor.snapshot()
        started, stopped = process_monitor.diff(baseline, current)
        for pid, name in started:
            self.log_activity(
                "process", f"{name} (pid {pid})", "started",
                severity="notice", detail=process_monitor.describe(pid),
            )
        for pid, name in stopped:
            self.log_activity("process", f"{name} (pid {pid})", "exited", severity="info")
        if started or stopped:
            self.db.replace_baseline("process", {str(pid): name for pid, name in current.items()})

    def _sweep_registry(self) -> None:
        baseline = self.db.get_baseline("registry")
        current = registry_monitor.read_autoruns()
        added, changed, removed = registry_monitor.diff(baseline, current)
        for key, detail in added:
            self.log_activity("registry", key, "autorun_added", severity="warning", detail=detail)
        for key, detail in changed:
            self.log_activity("registry", key, "autorun_changed", severity="warning", detail=detail)
        for key, detail in removed:
            self.log_activity("registry", key, "autorun_removed", severity="warning", detail=detail)
        if added or changed or removed:
            self.db.replace_baseline("registry", dict(current))

    # -- lifecycle -----------------------------------------------------------

    def stop(self) -> None:
        self._poll_stop.set()
        if self._poll_thread:
            self._poll_thread.join(timeout=self.config.poll_interval + 2)
            self._poll_thread = None
        self.stop_heartbeat()
        self._process_watch = False
        self._registry_watch = False
        with self._lock:
            for monitor in self._file_monitors:
                monitor.stop()
            self._file_monitors.clear()
            self._watched_paths.clear()
