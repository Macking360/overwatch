"""Command-line entry point for OverWatch.

Usage:
    python -m overwatch run                 # start the web server
    python -m overwatch init                # create the database
    python -m overwatch create-user NAME --role admin
    python -m overwatch status              # print resolved config

Passwords are read from the OVERWATCH_PASSWORD env var or prompted for; they
are never passed on the command line.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform as _platform
import sys
import time

from . import auth
from .config import Config
from .db import ROLES, Database


def _password(explicit: str | None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("OVERWATCH_PASSWORD")
    if env:
        return env
    return getpass.getpass("Password: ")


def cmd_init(config: Config) -> int:
    Database(config.database).init()
    print(f"Initialized database at {config.database}")
    return 0


def cmd_create_user(config: Config, args: argparse.Namespace) -> int:
    db = Database(config.database)
    db.init()
    if db.get_user(args.username) is not None:
        print(f"User {args.username!r} already exists.", file=sys.stderr)
        return 1
    role = args.role if args.role in ROLES else "viewer"
    # First account is forced to admin so the install is never left without one.
    if db.count_users() == 0:
        role = "admin"
    password = _password(args.password)
    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        return 1
    user_id = db.add_user(args.username, auth.hash_password(password), role=role)
    # Issue the identity certificate bound to a local (CLI) connection fingerprint.
    from . import identity
    conn_fp = identity.local_fingerprint("cli")
    pid, cert = identity.issue_certificate(config.secret_key, user_id, args.username, conn_fp, role)
    db.set_user_credential(user_id, pid, json.dumps(cert), json.dumps(conn_fp))
    print(f"Created user {args.username!r} ({role}); identity {pid} issued.")
    return 0


def cmd_status(config: Config) -> int:
    db = Database(config.database)
    db.init()
    print("OverWatch configuration:")
    for key, value in config.as_dict().items():
        print(f"  {key}: {value}")
    print(f"  users: {db.count_users()} ({db.count_admins()} admin)")
    return 0


def cmd_run(config: Config) -> int:
    from .web import create_app

    db = Database(config.database)
    db.init()
    if db.count_users() == 0:
        print(
            "No users yet. Open /register to create the first (admin) account, "
            "or run: python -m overwatch create-user <name> --role admin",
            file=sys.stderr,
        )
    app = create_app(config)
    if config.heartbeat_interval and config.heartbeat_interval > 0:
        app.config["OVERWATCH_ENGINE"].start_heartbeat(config.heartbeat_interval)
    ssl_context = config.ssl_context()
    scheme = "https" if ssl_context else "http"
    print(f"OverWatch listening on {scheme}://{config.host}:{config.port}")
    app.run(host=config.host, port=config.port, debug=False, ssl_context=ssl_context)
    return 0


def _cache_token(config: Config, token: str) -> None:
    path = config.instance_dir / "device_token"
    try:
        path.write_text(token, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass


def _cached_token(config: Config) -> str:
    path = config.instance_dir / "device_token"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


def _tls_from(config: Config, args: argparse.Namespace):
    """Resolve (verify, cert) for requests from CLI flags over config."""
    ca = args.ca_cert or config.ca_cert
    client_cert = args.client_cert or config.client_cert
    client_key = args.client_key or config.client_key
    verify = ca or True
    if client_cert and client_key:
        cert = (client_cert, client_key)
    else:
        cert = client_cert or None
    return verify, cert


def cmd_agent(config: Config, args: argparse.Namespace) -> int:
    from . import fingerprint
    from .engine import OverwatchTool
    from .net import RemoteForwarder, enroll

    server = (args.server or config.agent_server).rstrip("/")
    if not server:
        print("--server is required (or set OVERWATCH_SERVER).", file=sys.stderr)
        return 1

    name = args.name or config.device_name or _platform.node() or "device"
    token = args.device_token or config.agent_token or _cached_token(config)
    verify, cert = _tls_from(config, args)

    if not token:
        if not args.enroll_key:
            print(
                "No device token. Provide --device-token, or --enroll-key to enroll.",
                file=sys.stderr,
            )
            return 1
        print(f"[agent] enrolling '{name}' with {server} ...")
        token = enroll(
            server, args.enroll_key, name, _platform.platform(),
            fingerprint=fingerprint.collect(), verify=verify, cert=cert,
        )
        if not token:
            print("[agent] enrollment failed.", file=sys.stderr)
            return 1
        _cache_token(config, token)
        print("[agent] enrolled; token cached.")

    db = Database(config.database)
    db.init()
    forwarder = RemoteForwarder(
        server, token, timeout=config.alert_timeout + 2, verify=verify, cert=cert
    )
    engine = OverwatchTool(config, db, source=name, forwarders=[forwarder])

    for path in args.watch_file or []:
        engine.watch_file(path)
    if args.watch_process:
        engine.enable_process_watch()
    if args.watch_registry:
        engine.enable_registry_watch()

    if not (args.watch_file or args.watch_process or args.watch_registry):
        print("[agent] nothing to watch; pass --watch-process / --watch-registry / --watch-file.",
              file=sys.stderr)
        engine.stop()
        return 1

    heartbeat = args.heartbeat if args.heartbeat is not None else config.heartbeat_interval
    if heartbeat and heartbeat > 0:
        engine.start_heartbeat(heartbeat)

    tls = "TLS" if str(server).startswith("https") else "http"
    print(f"[agent] '{name}' reporting to {server} ({tls}). Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[agent] stopping ...")
    finally:
        engine.stop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="overwatch", description="OverWatch host-integrity monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database")
    sub.add_parser("status", help="print resolved configuration")
    sub.add_parser("run", help="start the web server")

    cu = sub.add_parser("create-user", help="create a user account")
    cu.add_argument("username")
    cu.add_argument("--role", choices=ROLES, default="viewer")
    cu.add_argument("--password", default=None, help="(discouraged; prefer prompt/env)")

    ag = sub.add_parser("agent", help="run as a BYOD agent, forwarding events to a server")
    ag.add_argument("--server", default="", help="central OverWatch base URL")
    ag.add_argument("--enroll-key", default="", help="shared key to enroll and mint a token")
    ag.add_argument("--device-token", default="", help="pre-issued device token")
    ag.add_argument("--name", default="", help="device name (defaults to hostname)")
    ag.add_argument("--watch-file", action="append", metavar="PATH", help="file path to watch (repeatable)")
    ag.add_argument("--watch-process", action="store_true", help="watch process start/exit")
    ag.add_argument("--watch-registry", action="store_true", help="watch registry autoruns (Windows)")
    ag.add_argument("--heartbeat", type=float, default=None, metavar="SECONDS",
                    help="emit an 'alive' event every N seconds (0 = off)")
    ag.add_argument("--ca-cert", default="", metavar="PATH",
                    help="CA bundle to verify the server (pin your own CA)")
    ag.add_argument("--client-cert", default="", metavar="PATH", help="client cert for mTLS")
    ag.add_argument("--client-key", default="", metavar="PATH", help="client key for mTLS")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config()
    if args.command == "init":
        return cmd_init(config)
    if args.command == "status":
        return cmd_status(config)
    if args.command == "create-user":
        return cmd_create_user(config, args)
    if args.command == "run":
        return cmd_run(config)
    if args.command == "agent":
        return cmd_agent(config, args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
