"""Delete ALL passwords so new ones can be given.
  python reset_all_passwords.py
- admin   -> temporary password  Admin1234  (log in, then set a strong one)
- others  -> password DELETED (login blocked until admin sets a new password
             from the Users page: type a new password and press 'Set').
Run from any folder. Also clears every account lock."""
from database import init_db, get_db_connection
from security import hash_password

init_db()
conn = get_db_connection()
conn.execute("UPDATE users SET password_hash = '', failed_attempts = 0, locked_until = NULL")
conn.execute("UPDATE users SET password_hash = ? WHERE username = 'admin'", (hash_password("Admin1234"),))
conn.commit()
n = conn.execute("SELECT COUNT(*) FROM users WHERE password_hash = ''").fetchone()[0]
conn.close()
print(f"Done. admin password = Admin1234 (temporary). {n} other account(s) have no password; set them from the Users page.")
