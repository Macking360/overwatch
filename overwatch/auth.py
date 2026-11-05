"""Session-based authentication.

Replaces the original hard-coded ``auth_token`` cookie (which authenticated
anyone who could set one static value) with Flask's signed session plus
Werkzeug password hashing. Login state lives in ``session['user_id']`` and is
verified against the database on every protected request.
"""

from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import current_app, flash, g, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    return check_password_hash(password_hash, password)


def login_user(user_id: int) -> None:
    session.clear()
    session["user_id"] = int(user_id)
    session.permanent = False


def logout_user() -> None:
    session.clear()


def current_user():
    """Return the logged-in user row, or None. Cached on ``g`` per request."""
    if "user" in g:
        return g.user
    user_id = session.get("user_id")
    user = None
    if user_id is not None:
        user = current_app.config["OVERWATCH_DB"].get_user_by_id(int(user_id))
        if user is None:
            session.clear()
    g.user = user
    return user


def is_admin(user=None) -> bool:
    user = user if user is not None else current_user()
    return bool(user) and user["role"] == "admin"


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in to continue.", "danger")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view: Callable) -> Callable:
    """Gate write/administrative actions to admin accounts.

    Viewers can read the dashboard and the activity log; only admins may
    configure monitors, manage users, or clear the log.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            flash("Please log in to continue.", "danger")
            return redirect(url_for("login"))
        if not is_admin(user):
            flash("That action requires an administrator account.", "danger")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped
