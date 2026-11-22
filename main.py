import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from werkzeug.utils import secure_filename
from database import init_db, get_db_connection, create_secure_backup, CSV_PATH, BACKUP_DIR
from security import get_or_create_secret_key, generate_csrf_token, verify_csrf_token, verify_audit_logs, log_audit
from auth import authenticate_user, create_user, change_user_password, admin_set_password, delete_user, login_required, role_required
from inventory import get_dashboard_stats, get_all_items, add_item, update_stock, update_price, delete_item

app = Flask(__name__)
app.secret_key = get_or_create_secret_key()

# Secure Session Cookie Settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800  # 30 minutes auto-timeout
)

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

DEFAULT_SETTINGS = {
    "profile_name": "Mohammad Faisal",
    "profile_email": "admin@inventory.com",
    "system_title": "Super Shop Inventory Management",
    "address": "Chittagong, Bangladesh",
    "contact": "+880123456789",
    "low_stock_limit": 10,
    "currency": "BDT",
    "language": "en",
    "logo_url": "/logo.jpeg",
    "avatar_url": ""
}


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                merged = DEFAULT_SETTINGS.copy()
                merged.update(saved)
                return merged
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def persist_settings(data):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


settings_data = load_settings()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "gif", "webp"}


@app.before_request
def csrf_protect():
    if "csrf_token" not in session:
        session["csrf_token"] = generate_csrf_token()
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not verify_csrf_token(session.get("csrf_token", ""), token):
            abort(403, description="CSRF Token Validation Failed!")


@app.after_request
def apply_security_headers(response):
    """Adds enterprise HTTP security headers (XSS, Clickjacking, MIME-sniffing protection)."""
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' data:; img-src 'self' blob: data:;"
    return response


@app.context_processor
def inject_globals():
    now = datetime.now()
    return {
        "current_user": session.get("user"),
        "csrf_token": session.get("csrf_token"),
        "current_date": now.strftime("%d-%m-%Y"),
        "current_time": now.strftime("%H:%M:%S"),
        "logo_url": settings_data.get("logo_url", "/logo.jpeg"),
        "system_title": settings_data.get("system_title", "Super Shop Inventory Management"),
        "profile_name": settings_data.get("profile_name", ""),
        "avatar_url": settings_data.get("avatar_url", ""),
        "currency": settings_data.get("currency", "BDT"),
        "low_stock_limit": settings_data.get("low_stock_limit", 10)
    }


@app.route("/logo.jpeg")
def serve_logo():
    custom_logo = settings_data.get("logo_url", "/logo.jpeg")
    if custom_logo.startswith("/static/"):
        custom_path = os.path.join(app.root_path, custom_logo.lstrip("/"))
        if os.path.exists(custom_path):
            return send_file(custom_path)
    default_path = os.path.join(app.root_path, "static", "logo.jpeg")
    if os.path.exists(default_path):
        return send_file(default_path, mimetype="image/jpeg")
    abort(404)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok, msg, user_data = authenticate_user(username, password, request.remote_addr)
        if ok:
            session.clear()
            session["user"] = user_data
            session["csrf_token"] = generate_csrf_token()
            session.permanent = True
            return redirect(url_for("dashboard"))
        flash(msg, "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "user" in session:
        log_audit(session["user"]["username"], "LOGOUT", "User logged out", request.remote_addr)
    session.clear()
    flash("Logged out securely.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", stats=stats, active_page="dashboard")


@app.route("/inventory")
@login_required
def inventory_list():
    search = request.args.get("q", "")
    items = get_all_items(search)
    return render_template("inventory.html", items=items, search=search, active_page="inventory")


@app.route("/add-item", methods=["GET", "POST"])
@role_required("admin", "manager")
def add_item_route():
    if request.method == "POST":
        try:
            name = request.form.get("name", "")
            category = request.form.get("category", "")
            qty = int(request.form.get("qty", 0))
            price = float(request.form.get("price", 0))
            min_stock = int(request.form.get("min_stock", settings_data["low_stock_limit"]))
            ok, msg = add_item(session["user"]["username"], name, category, qty, price, min_stock, request.remote_addr)
            flash(msg, "success" if ok else "error")
            if ok:
                return redirect(url_for("inventory_list"))
        except ValueError:
            flash("Invalid numeric input.", "error")
    return render_template("add_item.html", active_page="add_item")


@app.route("/stock", methods=["GET", "POST"])
@role_required("admin", "manager")
def stock_route():
    if request.method == "POST":
        try:
            item_id = int(request.form.get("item_id"))
            action_type = request.form.get("action_type")
            amount = int(request.form.get("amount"))
            ok, msg = update_stock(session["user"]["username"], item_id, action_type, amount, request.remote_addr)
            flash(msg, "success" if ok else "error")
        except ValueError:
            flash("Invalid quantity input.", "error")
    items = get_all_items()
    return render_template("stock.html", items=items, active_page="stock")


@app.route("/low-stock")
@login_required
def low_stock_route():
    low_limit = settings_data["low_stock_limit"]
    filtered_items = [i for i in get_all_items() if i["qty"] <= low_limit]
    return render_template("low_stock.html", items=filtered_items, active_page="low_stock")


@app.route("/price-delete", methods=["GET", "POST"])
@role_required("admin", "manager", "accounts_manager")
def price_delete_route():
    if request.method == "POST":
        action = request.form.get("action")
        item_id = int(request.form.get("item_id"))
        if action == "update_price":
            try:
                new_price = float(request.form.get("new_price"))
                ok, msg = update_price(session["user"]["username"], item_id, new_price, request.remote_addr)
                flash(msg, "success" if ok else "error")
            except ValueError:
                flash("Invalid price value.", "error")
        elif action == "delete":
            if session["user"]["role"] != "admin":
                flash("Only Admin can delete items!", "error")
            else:
                ok, msg = delete_item(session["user"]["username"], item_id, request.remote_addr)
                flash(msg, "success" if ok else "error")
    items = get_all_items()
    return render_template("price_delete.html", items=items, active_page="price_delete")


@app.route("/users", methods=["GET", "POST"])
@role_required("admin")
def users_route():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            uname = request.form.get("username", "").strip()
            pw = request.form.get("password", "")
            role = request.form.get("role", "viewer")
            ok, msg = create_user(session["user"]["username"], uname, pw, role, request.remote_addr)
            flash(msg, "success" if ok else "error")
        elif action == "update_role":
            uid = int(request.form.get("user_id"))
            new_role = request.form.get("new_role", "viewer")
            if new_role in ["admin", "manager", "accounts_manager", "viewer"]:
                conn = get_db_connection()
                target = conn.execute("SELECT username FROM users WHERE id = ?", (uid,)).fetchone()
                if target and target["username"] != session["user"]["username"]:
                    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, uid))
                    conn.commit()
                    log_audit(session["user"]["username"], "UPDATE_ROLE", f"Changed {target['username']} role to {new_role}", request.remote_addr)
                    flash(f"Role updated to {new_role.replace('_', ' ').upper()} for {target['username']}.", "success")
                else:
                    flash("Cannot change your own active role!", "error")
                conn.close()
        elif action == "set_password":
            uid = int(request.form.get("user_id"))
            ok, msg = admin_set_password(session["user"]["username"], uid, request.form.get("new_password", ""), request.remote_addr)
            flash(msg, "success" if ok else "error")
        elif action == "delete":
            uid = int(request.form.get("user_id"))
            ok, msg = delete_user(session["user"]["username"], uid, request.remote_addr)
            flash(msg, "success" if ok else "error")

    conn = get_db_connection()
    users = [dict(u) for u in conn.execute("SELECT id, username, role, failed_attempts, locked_until, created_at, (password_hash = '') AS no_password FROM users").fetchall()]
    conn.close()
    return render_template("users.html", users=users, active_page="users")


@app.route("/backup", methods=["GET", "POST"])
@role_required("admin")
def backup_route():
    if request.method == "POST":
        fname = create_secure_backup(session["user"]["username"], request.remote_addr)
        flash(f"Encrypted-checksum SQLite backup created: {fname}", "success")
    backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith(".db")], reverse=True) if os.path.exists(BACKUP_DIR) else []
    return render_template("backup.html", backups=backups, active_page="backup")


@app.route("/audit-log")
@role_required("admin")
def audit_log_route():
    logs = verify_audit_logs()
    return render_template("audit_log.html", logs=logs, active_page="audit_log")


@app.route("/report")
@login_required
def report_route():
    stats = get_dashboard_stats()
    items = get_all_items()
    return render_template("report.html", stats=stats, items=items, active_page="report")


@app.route("/download-csv")
@login_required
def download_csv():
    log_audit(session["user"]["username"], "EXPORT_CSV", "Downloaded inventory.csv", request.remote_addr)
    return send_file(CSV_PATH, as_attachment=True)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password_route():
    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        ok, msg = change_user_password(session["user"]["username"], old_pw, new_pw, request.remote_addr)
        flash(msg, "success" if ok else "error")
    return render_template("password.html", active_page="password")


@app.route("/settings")
@login_required
def settings_route():
    return render_template("settings.html", active_page="settings", **settings_data)


@app.route("/save_settings", methods=["POST"])
@login_required
def save_settings():
    global settings_data
    try:
        settings_data["profile_name"] = request.form.get("full_name", settings_data["profile_name"]).strip()
        settings_data["profile_email"] = request.form.get("email", settings_data["profile_email"]).strip()
        settings_data["system_title"] = request.form.get("system_title", settings_data["system_title"]).strip()
        settings_data["address"] = request.form.get("address", settings_data["address"]).strip()
        settings_data["contact"] = request.form.get("contact", settings_data["contact"]).strip()
        settings_data["low_stock_limit"] = int(request.form.get("low_stock_limit", settings_data["low_stock_limit"]))
        settings_data["currency"] = request.form.get("currency", settings_data["currency"])
        settings_data["language"] = request.form.get("language", settings_data["language"])

        upload_dir = os.path.join(app.root_path, "static")
        os.makedirs(upload_dir, exist_ok=True)

        avatar_file = request.files.get("avatar")
        if avatar_file and avatar_file.filename != "":
            if allowed_file(avatar_file.filename):
                filename = secure_filename(avatar_file.filename)
                avatar_filename = f"avatar_{filename}"
                avatar_file.save(os.path.join(upload_dir, avatar_filename))
                settings_data["avatar_url"] = f"/static/{avatar_filename}"
            else:
                flash("Invalid format for Avatar Image! Only PNG, JPG, JPEG, GIF, WEBP allowed.", "error")
                return redirect(url_for("settings_route"))

        logo_file = request.files.get("app_logo")
        if logo_file and logo_file.filename != "":
            if allowed_file(logo_file.filename):
                filename = secure_filename(logo_file.filename)
                logo_filename = f"logo_{filename}"
                logo_file.save(os.path.join(upload_dir, logo_filename))
                settings_data["logo_url"] = f"/static/{logo_filename}"
            else:
                flash("Invalid format for Logo Image! Only PNG, JPG, JPEG, GIF, WEBP allowed.", "error")
                return redirect(url_for("settings_route"))

        persist_settings(settings_data)
        log_audit(session["user"]["username"], "SETTINGS_UPDATE", "Updated application/profile settings", request.remote_addr)
        flash("Settings updated and saved successfully!", "success")

    except ValueError:
        flash("Invalid numeric input for Low Stock Limit.", "error")
    except Exception as e:
        flash(f"Error updating settings: {str(e)}", "error")

    return redirect(url_for("settings_route"))


if __name__ == "__main__":
    init_db()
    if "COLAB_RELEASE_TAG" in os.environ or "COLAB_GPU" in os.environ:
        from google.colab.output import eval_js
        print("=" * 60)
        print("Google Colab Detected! Open this URL in your browser:")
        print(eval_js("google.colab.kernel.proxyPort(5000)"))
        print("Default Admin Login -> Username: admin | Password: Admin@1234")
        print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)