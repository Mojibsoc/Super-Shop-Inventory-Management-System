import os
import re
import hashlib
import hmac
from datetime import datetime, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash, request
from database import get_db_connection
from security import log_audit, hash_password, verify_password


def is_strong_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, "Strong password."


def authenticate_user(username: str, password: str, ip_address: str = "127.0.0.1"):
    username = (username or "").strip()
    if not username or not password:
        return False, "Username and password are required.", None

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        conn.close()
        log_audit(username, "LOGIN_FAILED", "Unknown username attempt", ip_address)
        return False, "Invalid username or password.", None

    now = datetime.now()
    if user["locked_until"]:
        try:
            lock_dt = datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S")
            if now < lock_dt:
                conn.close()
                return False, f"Account locked until {user['locked_until']} due to failed attempts.", None
        except ValueError:
            pass

    if verify_password(password, user["password_hash"]):
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        conn.commit()
        conn.close()
        log_audit(user["username"], "LOGIN_SUCCESS", "User logged in", ip_address)
        return True, "Login successful.", {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
        }

    failed = (user["failed_attempts"] or 0) + 1
    locked_until_str = None
    msg = "Invalid username or password."
    if failed >= 5:
        lock_time = now + timedelta(minutes=15)
        locked_until_str = lock_time.strftime("%Y-%m-%d %H:%M:%S")
        msg = f"Too many failed attempts. Account locked until {locked_until_str}."

    conn.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (failed, locked_until_str, user["id"]),
    )
    conn.commit()
    conn.close()
    log_audit(username, "LOGIN_FAILED", f"Failed attempt #{failed}", ip_address)
    return False, msg, None


def create_user(actor_username: str, username: str, password: str, role: str, ip_address: str = "127.0.0.1"):
    username = (username or "").strip()
    role = (role or "viewer").strip()

    if not username or not re.match(r"^[A-Za-z0-9_.-]{3,32}$", username):
        return False, "Username must be 3-32 characters (letters, numbers, _, ., -)."

    if role not in ["admin", "manager", "accounts_manager", "viewer"]:
        return False, "Invalid role selected."

    ok, pw_msg = is_strong_password(password)
    if not ok:
        return False, pw_msg

    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        return False, "Username already exists."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pw_hash = hash_password(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, pw_hash, role, now_str),
    )
    conn.commit()
    conn.close()

    log_audit(actor_username, "CREATE_USER", f"Created user '{username}' with role '{role}'", ip_address)
    return True, f"User '{username}' created with role '{role.replace('_', ' ').upper()}'."


def change_user_password(username: str, old_password: str, new_password: str, ip_address: str = "127.0.0.1"):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not verify_password(old_password, user["password_hash"]):
        conn.close()
        return False, "Current password is incorrect."

    ok, pw_msg = is_strong_password(new_password)
    if not ok:
        conn.close()
        return False, pw_msg

    new_hash = hash_password(new_password)
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
    conn.commit()
    conn.close()

    log_audit(username, "CHANGE_PASSWORD", "Password changed successfully", ip_address)
    return True, "Password updated successfully."


def admin_set_password(actor_username: str, user_id: int, new_password: str, ip_address: str = "127.0.0.1"):
    """Admin gives a user a brand-new password (used after passwords were deleted/reset)."""
    ok, pw_msg = is_strong_password(new_password)
    if not ok:
        return False, pw_msg
    conn = get_db_connection()
    target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        return False, "User not found."
    conn.execute(
        "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (hash_password(new_password), user_id),
    )
    conn.commit()
    conn.close()
    log_audit(actor_username, "SET_PASSWORD", f"New password set for '{target['username']}'", ip_address)
    return True, f"New password set for '{target['username']}'."


def delete_user(actor_username: str, user_id: int, ip_address: str = "127.0.0.1"):
    conn = get_db_connection()
    target = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not target:
        conn.close()
        return False, "User not found."

    if target["username"] == actor_username:
        conn.close()
        return False, "You cannot delete your own active account."

    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

    log_audit(actor_username, "DELETE_USER", f"Deleted user '{target['username']}'", ip_address)
    return True, f"User '{target['username']}' deleted."


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            user_role = session.get("user", {}).get("role")
            if user_role not in allowed_roles:
                flash("Access denied: insufficient permissions for your role.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator