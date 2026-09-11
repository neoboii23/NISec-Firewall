"""Isolated vulnerable Flask target; a separate WAF can sit in front of it."""
from __future__ import annotations

import logging
import os
import secrets
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, send_from_directory, session, url_for
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from models import Comment, Item, Upload, User, db

ALLOWED_EXTENSIONS = {"txt", "png", "jpg", "jpeg", "pdf"}
ALLOWED_MIME_TYPES = {"text/plain", "image/png", "image/jpeg", "application/pdf"}

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

for folder in (app.config["UPLOAD_FOLDER"], app.config["LAB_FILES_FOLDER"], app.config["LOG_FOLDER"]):
    Path(folder).mkdir(parents=True, exist_ok=True)
(Path(app.config["LAB_FILES_FOLDER"]) / "readme.txt").write_text("Dedicated laboratory download area.\n", encoding="utf-8")

request_logger = logging.getLogger("origine.requests")
request_logger.setLevel(logging.INFO)
if not request_logger.handlers:
    log_handler = logging.FileHandler(Path(app.config["LOG_FOLDER"]) / "app.log", encoding="utf-8")
    log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    request_logger.addHandler(log_handler)


@app.before_request
def load_current_user():
    g.user = db.session.get(User, session.get("user_id")) if session.get("user_id") else None


@app.after_request
def log_request(response):
    username = g.user.username if getattr(g, "user", None) else "anonymous"
    request_logger.info("ip=%s method=%s path=%s status=%s agent=%r username=%s", request.remote_addr, request.method, request.path, response.status_code, request.user_agent.string[:180], username)
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user or not g.user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def home():
    return render_template("home.html", items=Item.query.order_by(Item.id).limit(3).all())


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password, confirm = request.form.get("password", ""), request.form.get("confirm_password", "")
        if not all((username, email, password, confirm)):
            flash("Please complete every required field.", "error")
        elif "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            flash("That username or email address is already registered.", "error")
        else:
            db.session.add(User(username=username, email=email, password=generate_password_hash(password)))
            db.session.commit()
            flash("Registration successful. Please sign in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("home"))
    if request.method == "POST":
        identity, password = request.form.get("identity", "").strip(), request.form.get("password", "")
        user = User.query.filter((User.username == identity) | (User.email == identity.lower())).first()
        if user and check_password_hash(user.password, password):
            session.clear()
            session["user_id"] = user.id
            flash(f"Welcome back, {user.username}.", "success")
            response = redirect(request.args.get("next") or url_for("home"))
            response.headers["X-Lab-Auth-Result"] = "success"
            return response
        flash("Invalid username/email or password.", "error")
        return render_template("login.html"), 200, {"X-Lab-Auth-Result": "failure"}
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/search")
def search():
    keyword, items, error = request.args.get("q", "").strip(), [], None
    if keyword:
        if app.config["VULNERABLE_MODE"]:
            # INTENTIONALLY VULNERABLE: an isolated SQL-injection lab endpoint.
            try:
                items = db.session.execute(text(f"SELECT * FROM item WHERE name LIKE '%{keyword}%' OR category LIKE '%{keyword}%'")).mappings().all()
            except Exception as exc:
                error = str(exc)
        else:
            items = Item.query.filter((Item.name.ilike(f"%{keyword}%")) | (Item.category.ilike(f"%{keyword}%"))).all()
    return render_template("search.html", keyword=keyword, items=items, error=error)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        full_name, bio, password = request.form.get("full_name", "").strip(), request.form.get("bio", "").strip(), request.form.get("password", "")
        duplicate = User.query.filter(User.email == email, User.id != g.user.id).first()
        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
        elif duplicate:
            flash("That email address is already in use.", "error")
        else:
            g.user.email, g.user.full_name, g.user.bio = email, full_name, bio
            if password:
                g.user.password = generate_password_hash(password)
            db.session.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("edit_profile.html")


@app.route("/comment", methods=["GET", "POST"])
@login_required
def comment():
    items = Item.query.order_by(Item.name).all()
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        item = db.session.get(Item, request.form.get("item_id", type=int))
        if not body or not item:
            flash("Choose a bag and enter a comment.", "error")
        else:
            db.session.add(Comment(body=body, author=g.user, item=item))
            db.session.commit()
            flash("Your comment has been posted.", "success")
            return redirect(url_for("comment"))
    return render_template("comment.html", items=items, comments=Comment.query.order_by(Comment.created_at.desc()).limit(30).all())


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Select a file to upload.", "error")
        elif not app.config["VULNERABLE_MODE"] and (not allowed_file(uploaded.filename) or uploaded.mimetype not in ALLOWED_MIME_TYPES):
            flash("Only TXT, PNG, JPG, JPEG, and PDF files with a matching MIME type are accepted.", "error")
        else:
            # INTENTIONALLY VULNERABLE only in VULNERABLE_MODE: filename/MIME validation is bypassed.
            original = uploaded.filename
            stored = original if app.config["VULNERABLE_MODE"] else f"{secrets.token_hex(8)}_{secure_filename(original)}"
            uploaded.save(Path(app.config["UPLOAD_FOLDER"]) / stored)
            db.session.add(Upload(original_filename=original, stored_filename=stored, content_type=uploaded.mimetype or "unknown", owner=g.user))
            db.session.commit()
            flash("File uploaded successfully.", "success")
            return redirect(url_for("upload"))
    return render_template("upload.html", uploads=Upload.query.filter_by(user_id=g.user.id).order_by(Upload.uploaded_at.desc()).all())


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    if app.config["VULNERABLE_MODE"]:
        # INTENTIONALLY VULNERABLE: isolated path-traversal test point.
        return send_file(os.path.join(app.config["LAB_FILES_FOLDER"], filename), as_attachment=True)
    return send_from_directory(app.config["LAB_FILES_FOLDER"], filename, as_attachment=True)


@app.route("/admin")
@admin_required
def admin():
    stats = {"users": User.query.count(), "items": Item.query.count(), "comments": Comment.query.count(), "uploads": Upload.query.count()}
    return render_template("admin.html", stats=stats, recent_users=User.query.order_by(User.created_at.desc()).limit(5).all(), recent_comments=Comment.query.order_by(Comment.created_at.desc()).limit(5).all())


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view that page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The page you requested could not be found."), 404


@app.errorhandler(413)
def too_large(_error):
    flash("That file is larger than the 2 MB limit.", "error")
    return redirect(url_for("upload"))


@app.errorhandler(500)
def server_error(_error):
    db.session.rollback()
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    from seed import seed_database
    seed_database()
    app.run(host=app.config["HOST"], port=app.config["PORT"], debug=False)
