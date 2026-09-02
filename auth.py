"""
auth.py

User registration/login/logout using Flask-Login for session management and
werkzeug's password hashing (scrypt-based, built into Flask's dependencies --
no extra crypto library needed).
"""

import re

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

import database

auth_bp = Blueprint("auth", __name__)
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to use the scanner."

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class User(UserMixin):
    """Thin wrapper adapting our DB user dict to what Flask-Login expects."""

    def __init__(self, row):
        self.id = str(row["id"])
        self.username = row["username"]
        self.email = row["email"]


@login_manager.user_loader
def load_user(user_id):
    row = database.get_user_by_id(int(user_id))
    return User(row) if row else None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if database.get_user_by_username(username):
            errors.append("That username is already taken.")
        if database.get_user_by_email(email):
            errors.append("An account with that email already exists.")

        if errors:
            for e in errors:
                flash(e)
            return render_template("register.html", username=username, email=email)

        password_hash = generate_password_hash(password)
        user_id = database.create_user(username, email, password_hash)
        login_user(User({"id": user_id, "username": username, "email": email}))
        flash("Account created — welcome!")
        return redirect(url_for("index"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = database.get_user_by_username(username)
        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row))
            flash(f"Welcome back, {row['username']}!")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))

        flash("Invalid username or password.")
        return render_template("login.html", username=username)

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've been logged out.")
    return redirect(url_for("auth.login"))
