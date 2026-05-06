from __future__ import annotations

import os
import re

from flask import Flask, abort, flash, g, make_response, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFError, CSRFProtect

from account_service import TransferError, do_transfer, get_balance, get_owned_accounts
from user_service import get_user_with_credentials, logged_in


app = Flask(__name__)

# Flask-WTF signs CSRF tokens with SECRET_KEY. In production this must come
# from a private environment variable; the fallback keeps the class demo easy
# to run locally while still showing the right mechanism.
app.config["SECRET_KEY"] = os.environ.get(
    "BANK_DEMO_SECRET_KEY",
    "dev-only-change-me-before-deploying-this-class-demo",
)

# CSRFProtect rejects unsafe requests, such as POST /transfer, unless the form
# includes a valid per-session token. That blocks cross-site forms from silently
# spending a logged-in user's cookie-authenticated session.
csrf = CSRFProtect(app)

ACCOUNT_RE = re.compile(r"^\d{1,12}$")
MAX_TRANSFER_AMOUNT = 1000


def _login_response():
    # All unauthenticated paths return the same login page, avoiding clues about
    # which protected URL or account number was attempted.
    return render_template("login.html"), 401


def _validate_account_number(value: str | None, field_name: str) -> str:
    # Account numbers are constrained to digits before they reach the service.
    # Bound SQL parameters still prevent injection, but validation gives users a
    # clean 400 instead of letting weird input flow deeper into the app.
    if not value or not ACCOUNT_RE.fullmatch(value):
        abort(400, f"{field_name} must be 1 to 12 digits")
    return value


def _validate_amount(value: str | None) -> int:
    # int() can raise ValueError; catching it prevents malformed input from
    # becoming a 500. The bounds stop negative transfers and oversized demo
    # transfers before the database update begins.
    try:
        amount = int(value or "")
    except ValueError:
        abort(400, "Amount must be a whole number")
    if amount <= 0:
        abort(400, "Amount must be positive")
    if amount > MAX_TRANSFER_AMOUNT:
        abort(400, f"Amount may not exceed {MAX_TRANSFER_AMOUNT}")
    return amount


@app.route("/", methods=["GET"])
def home():
    if logged_in():
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    # Generic validation and generic errors defend against user enumeration:
    # the page never says whether the email or password was the failing part.
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    user = get_user_with_credentials(email, password)
    if not user:
        return render_template("login.html", error="Unrecognized email or wrong password."), 401

    response = make_response(redirect(url_for("dashboard")))
    # JWTs are stored in an HttpOnly cookie so injected JavaScript cannot read
    # them. SameSite=Lax reduces cross-site cookie sending; CSRF tokens still
    # protect state-changing POSTs because SameSite is not a complete defense.
    response.set_cookie(
        "auth_token",
        user["token"],
        httponly=True,
        secure=os.environ.get("FLASK_ENV") == "production",
        samesite="Lax",
        max_age=60 * 60,
    )
    return response, 303


@app.route("/logout", methods=["POST"])
def logout():
    # Logout changes auth state, so it is POST-only and CSRF-protected instead
    # of being a state-changing GET link.
    response = make_response(redirect(url_for("home")))
    response.delete_cookie("auth_token")
    return response, 303


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not logged_in():
        return _login_response()
    return render_template("dashboard.html", email=g.user, accounts=get_owned_accounts(g.user))


@app.route("/details", methods=["GET"])
def details():
    if not logged_in():
        return _login_response()
    account_number = _validate_account_number(request.args.get("account"), "Account")
    balance = get_balance(account_number, g.user)
    if balance is None:
        # A missing or not-owned account gets the same 404, so users cannot use
        # this endpoint to distinguish "exists but belongs to someone else."
        abort(404, "Account not found")
    return render_template(
        "details.html",
        user=g.user,
        account_number=account_number,
        balance=balance,
    )


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not logged_in():
        return _login_response()

    accounts = get_owned_accounts(g.user)
    if request.method == "GET":
        return render_template("transfer.html", accounts=accounts)

    source = _validate_account_number(request.form.get("from"), "Source account")
    target = _validate_account_number(request.form.get("to"), "Target account")
    amount = _validate_amount(request.form.get("amount"))

    try:
        do_transfer(source=source, target=target, amount=amount, owner=g.user)
    except TransferError as error:
        # Known validation failures are shown as friendly messages. We keep the
        # text broad enough that it does not leak whether a target account exists.
        flash(str(error), "error")
        return render_template("transfer.html", accounts=accounts), 400

    flash("Transfer completed.", "success")
    return redirect(url_for("dashboard")), 303


@app.errorhandler(400)
def bad_request(error):
    # Consistent error pages make validation failures understandable without
    # dumping stack traces or internal implementation details.
    return render_template("error.html", title="Bad Request", message=error.description), 400


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", title="Not Found", message=error.description), 404


@app.errorhandler(CSRFError)
def csrf_error(error):
    # Flask-WTF raises this before the route executes, so forged POSTs never
    # reach transfer logic.
    return render_template("error.html", title="Bad Request", message="The CSRF token is missing or invalid."), 400
