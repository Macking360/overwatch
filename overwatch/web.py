"""Flask application factory and routes.

Preserves the original OverWatch route shape — index, login, register, logout,
dashboard, monitor — and extends it into a defensive platform: all three
monitors are wired in, authentication is real, and write/administrative actions
are gated to admin accounts via ``admin_required``.
"""

from __future__ import annotations

import csv
import io
import json
import secrets as _secrets
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from . import auth, devices, identity
from .auth import admin_required, current_user, is_admin, login_required
from .config import Config
from .db import ROLES, SEVERITIES, Database
from .engine import OverwatchTool

__version__ = __import__("overwatch").__version__

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
STATIC = Path(__file__).resolve().parent.parent / "static"


def create_app(config: Config | None = None, engine: OverwatchTool | None = None) -> Flask:
    config = config or Config()
    db = Database(config.database)
    db.init()
    engine = engine or OverwatchTool(config, db)

    app = Flask(
        __name__,
        template_folder=str(TEMPLATES),
        static_folder=str(STATIC),
    )
    app.config.update(
        SECRET_KEY=config.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        OVERWATCH_CONFIG=config,
        OVERWATCH_DB=db,
        OVERWATCH_ENGINE=engine,
    )

    def _issue_user_credential(user_id: int, username: str, role: str) -> str:
        """Issue and store a signed identity certificate (PID) bound to the
        fingerprint of the connection this user was created on."""
        conn_fp = identity.connection_fingerprint(request)
        pid, cert = identity.issue_certificate(
            config.secret_key, user_id, username, conn_fp, role
        )
        db.set_user_credential(user_id, pid, json.dumps(cert), json.dumps(conn_fp))
        return pid

    @app.context_processor
    def inject_user():
        user = current_user()
        return {
            "current_user": user,
            "is_admin": is_admin(user),
            "app_version": __version__,
        }

    # -- CSRF protection for browser (session) POSTs ------------------------
    # The device ingest API under /api/ authenticates with bearer tokens and is
    # exempt. Disabled under TESTING so the test client can post directly.

    def _csrf_field() -> Markup:
        return Markup(
            f'<input type="hidden" name="csrf_token" value="{session.get("csrf_token", "")}">'
        )

    app.jinja_env.globals["csrf_field"] = _csrf_field

    @app.before_request
    def _csrf_protect():
        if "csrf_token" not in session:
            session["csrf_token"] = _secrets.token_urlsafe(32)
        if app.testing or request.method != "POST":
            return
        if request.path.startswith("/api/"):
            return
        if request.form.get("csrf_token", "") != session["csrf_token"]:
            abort(400, description="CSRF token missing or invalid.")

    @app.route("/healthz")
    def healthz():
        return jsonify({
            "status": "ok",
            "version": __version__,
            "users": db.count_users(),
            "monitors": engine.status(),
        }), 200

    # -- public --------------------------------------------------------------

    @app.route("/")
    def index():
        if current_user() is not None:
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.route("/help")
    def help_page():
        # Public: the introduction must be readable before sign-in.
        return render_template("help.html", config=config.as_dict())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db.get_user(username)
            if user and auth.verify_password(user["password_hash"], password):
                auth.login_user(user["id"])
                flash("Signed in.", "success")
                return redirect(url_for("dashboard"))
            flash("Login failed. Check your username and password.", "danger")
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        # Registration is only open for first-run bootstrap, or when an operator
        # explicitly enables it. The very first account is always an admin.
        no_users = db.count_users() == 0
        if not no_users and not config.allow_open_registration:
            flash("Registration is closed. Ask an administrator to create your account.", "danger")
            return redirect(url_for("login"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                flash("Username and password are required.", "danger")
            elif db.get_user(username) is not None:
                flash("Username already exists.", "danger")
            else:
                role = "admin" if no_users else "viewer"
                user_id = db.add_user(username, auth.hash_password(password), role=role)
                pid = _issue_user_credential(user_id, username, role)
                flash(
                    f"Account created as {role}. Identity {pid} issued. You can now log in.",
                    "success",
                )
                return redirect(url_for("login"))
        return render_template("register.html", bootstrap=no_users)

    @app.route("/logout")
    @login_required
    def logout():
        auth.logout_user()
        flash("Signed out.", "success")
        return redirect(url_for("index"))

    # -- dashboard + log (read: any signed-in user) --------------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            status=engine.status(),
            counts=db.event_counts(),
            events=db.recent_events(limit=25),
            config=config.as_dict(),
        )

    @app.route("/events")
    @login_required
    def events():
        monitor = request.args.get("monitor") or None
        return render_template(
            "events.html",
            events=db.recent_events(limit=500, monitor=monitor),
            monitor=monitor,
        )

    @app.route("/events.csv")
    @login_required
    def events_csv():
        rows = db.recent_events(limit=100000)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ts", "source", "monitor", "severity", "action", "target", "detail"])
        for r in rows:
            writer.writerow([
                r["ts"], r["source"], r["monitor"], r["severity"],
                r["action"], r["target"], r["detail"],
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=overwatch-events.csv"},
        )

    @app.route("/events/clear", methods=["POST"])
    @admin_required
    def events_clear():
        n = db.clear_events()
        flash(f"Activity log cleared ({n} events removed).", "success")
        return redirect(url_for("events"))

    # -- monitor configuration (write: admin only) --------------------------

    @app.route("/monitor", methods=["GET", "POST"])
    @admin_required
    def monitor():
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "watch_file":
                path = request.form.get("file_path", "").strip()
                if path:
                    engine.watch_file(path)
                    flash(f"Now watching {path}", "success")
                else:
                    flash("Provide a file path to watch.", "danger")
            elif action == "watch_process":
                engine.enable_process_watch()
                flash("Process monitoring enabled.", "success")
            elif action == "watch_registry":
                engine.enable_registry_watch()
                if engine.status()["registry_supported"]:
                    flash("Registry autorun monitoring enabled.", "success")
                else:
                    flash("Registry monitoring is Windows-only; enabled as no-op here.", "info")
            elif action == "stop_all":
                engine.stop()
                flash("All monitoring stopped.", "success")
            else:
                flash("Unknown action.", "danger")
            return redirect(url_for("monitor"))
        return render_template("monitor.html", status=engine.status())

    @app.route("/baseline/<kind>", methods=["POST"])
    @admin_required
    def recapture_baseline(kind: str):
        if kind == "process":
            engine.enable_process_watch()
            flash("Process baseline recaptured.", "success")
        elif kind == "registry":
            engine.enable_registry_watch()
            flash("Registry baseline recaptured.", "success")
        else:
            flash("Unknown baseline.", "danger")
        return redirect(url_for("monitor"))

    # -- user management (admin only) ---------------------------------------

    @app.route("/users")
    @admin_required
    def users():
        return render_template("users.html", users=db.list_users(), roles=ROLES)

    @app.route("/users/create", methods=["POST"])
    @admin_required
    def users_create():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")
        if role not in ROLES:
            role = "viewer"
        if not username or not password:
            flash("Username and password are required.", "danger")
        elif db.get_user(username) is not None:
            flash("Username already exists.", "danger")
        else:
            user_id = db.add_user(username, auth.hash_password(password), role=role)
            pid = _issue_user_credential(user_id, username, role)
            flash(f"Created {username} ({role}) with identity {pid}.", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/role", methods=["POST"])
    @admin_required
    def users_set_role(user_id: int):
        role = request.form.get("role", "viewer")
        target = db.get_user_by_id(user_id)
        if target is None:
            flash("No such user.", "danger")
        elif target["role"] == "admin" and role != "admin" and db.count_admins() <= 1:
            flash("Cannot demote the last administrator.", "danger")
        else:
            db.set_role(user_id, role)
            flash(f"Updated {target['username']} to {role}.", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/password", methods=["POST"])
    @admin_required
    def users_set_password(user_id: int):
        password = request.form.get("password", "")
        target = db.get_user_by_id(user_id)
        if target is None:
            flash("No such user.", "danger")
        elif not password:
            flash("Password cannot be empty.", "danger")
        else:
            db.set_password(user_id, auth.hash_password(password))
            flash(f"Reset password for {target['username']}.", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @admin_required
    def users_delete(user_id: int):
        target = db.get_user_by_id(user_id)
        me = current_user()
        if target is None:
            flash("No such user.", "danger")
        elif me is not None and int(me["id"]) == user_id:
            flash("You cannot delete your own account.", "danger")
        elif target["role"] == "admin" and db.count_admins() <= 1:
            flash("Cannot delete the last administrator.", "danger")
        else:
            db.delete_user(user_id)
            flash(f"Deleted {target['username']}.", "success")
        return redirect(url_for("users"))

    @app.route("/users/<int:user_id>/credential")
    @admin_required
    def user_credential(user_id: int):
        u = db.get_user_by_id(user_id)
        if u is None:
            abort(404)
        cert = json.loads(u["credential"]) if u["credential"] else None
        valid = identity.verify_certificate(config.secret_key, cert) if cert else False
        return render_template(
            "credential.html",
            user=u,
            cert=cert,
            valid=valid,
            cert_json=json.dumps(cert, indent=2) if cert else "",
        )

    @app.route("/api/identity/<pid>")
    @admin_required
    def api_identity(pid: str):
        """Cross-reference an identity by PID (signed certificate lookup)."""
        u = db.get_user_by_pid(pid)
        if u is None or not u["credential"]:
            return jsonify({"error": "unknown pid"}), 404
        cert = json.loads(u["credential"])
        return jsonify({
            "pid": pid,
            "subject": u["username"],
            "role": u["role"],
            "valid": identity.verify_certificate(config.secret_key, cert),
            "certificate": cert,
        })

    # -- BYOD devices (admin console) ---------------------------------------

    @app.route("/devices")
    @admin_required
    def devices_page():
        enroll_cmd = (
            f"python -m overwatch agent --server http://<this-host>:{config.port} "
            f"--enroll-key {config.enroll_key} --name <device-name>"
        )
        return render_template(
            "devices.html",
            devices=db.list_devices(),
            enroll_key=config.enroll_key,
            enroll_cmd=enroll_cmd,
            port=config.port,
            issued_token=request.args.get("token"),
            issued_name=request.args.get("name"),
        )

    @app.route("/devices/create", methods=["POST"])
    @admin_required
    def devices_create():
        name = request.form.get("name", "").strip()
        platform = request.form.get("platform", "").strip()
        if not name:
            flash("Device name is required.", "danger")
            return redirect(url_for("devices_page"))
        token = devices.issue_token(db, name, platform)
        flash(f"Enrolled {name}. Copy the token now — it is shown only once.", "success")
        # The one-time token is passed back via query string for display only.
        return redirect(url_for("devices_page", token=token, name=name))

    @app.route("/devices/<int:device_id>/status", methods=["POST"])
    @admin_required
    def devices_status(device_id: int):
        status = request.form.get("status", "active")
        if status not in ("active", "revoked"):
            status = "revoked"
        if db.get_device(device_id) is None:
            flash("No such device.", "danger")
        else:
            db.set_device_status(device_id, status)
            flash(f"Device {device_id} set to {status}.", "success")
        return redirect(url_for("devices_page"))

    @app.route("/devices/<int:device_id>/delete", methods=["POST"])
    @admin_required
    def devices_delete(device_id: int):
        if db.get_device(device_id) is None:
            flash("No such device.", "danger")
        else:
            db.delete_device(device_id)
            flash(f"Removed device {device_id}.", "success")
        return redirect(url_for("devices_page"))

    # -- network ingest API (device tokens, not user sessions) --------------

    def _bearer() -> str:
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[len("Bearer "):].strip()
        return ""

    @app.route("/api/enroll", methods=["POST"])
    def api_enroll():
        if request.headers.get("X-Enroll-Key", "") != config.enroll_key:
            return jsonify({"error": "invalid enroll key"}), 403
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        platform = str(payload.get("platform", "")).strip()
        fp = payload.get("fingerprint") or {}
        if not name:
            return jsonify({"error": "name required"}), 400
        fp_json = json.dumps(fp)[:8000] if isinstance(fp, dict) else ""
        token = devices.issue_token(db, name, platform, fp_json)
        return jsonify({"token": token}), 201

    @app.route("/api/events", methods=["POST"])
    def api_events():
        device_id = devices.verify_token(db, _bearer())
        if device_id is None:
            return jsonify({"error": "invalid or revoked device token"}), 401
        device = db.get_device(device_id)
        db.touch_device(device_id)
        payload = request.get_json(silent=True) or {}
        incoming = payload.get("events", [])
        if not isinstance(incoming, list):
            return jsonify({"error": "events must be a list"}), 400
        stored = 0
        for ev in incoming[:500]:
            if not isinstance(ev, dict):
                continue
            severity = ev.get("severity", "info")
            if severity not in SEVERITIES:
                severity = "info"
            db.add_event(
                monitor=str(ev.get("monitor", "device"))[:64],
                target=str(ev.get("target", ""))[:1024],
                action=str(ev.get("action", "event"))[:128],
                severity=severity,
                detail=str(ev.get("detail", ""))[:2048],
                source=device["name"],
                ts=str(ev.get("ts")) if ev.get("ts") else None,
            )
            stored += 1
        return jsonify({"stored": stored}), 202

    # -- live JSON for the dashboard (session-authed) -----------------------

    @app.route("/api/status.json")
    @login_required
    def api_status():
        return jsonify({"status": engine.status(), "counts": db.event_counts()})

    @app.route("/api/events.json")
    @login_required
    def api_events_json():
        monitor = request.args.get("monitor") or None
        limit = min(int(request.args.get("limit", 25)), 500)
        rows = db.recent_events(limit=limit, monitor=monitor)
        return jsonify({"events": [dict(r) for r in rows]})

    return app
