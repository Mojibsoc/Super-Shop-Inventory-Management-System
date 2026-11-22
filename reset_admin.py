"""Reset the admin login. Usage:  python reset_admin.py            -> admin / Admin1234
                                  python reset_admin.py NewPass@1  -> admin / NewPass@1
Also clears any account lock. Works from any folder."""
import sys
from database import init_db, get_db_connection
from security import hash_password

pw = sys.argv[1] if len(sys.argv) > 1 else "Admin1234"
init_db()
conn = get_db_connection()
conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL")
row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
if row:
    conn.execute("UPDATE users SET password_hash = ?, role = 'admin' WHERE username = 'admin'", (hash_password(pw),))
else:
    from datetime import datetime
    conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES ('admin', ?, 'admin', ?)",
                 (hash_password(pw), datetime.now().strftime("%Y-%m-%d %H:%M")))
conn.commit()
conn.close()
print(f"Done. Login -> username: admin | password: {pw}")
