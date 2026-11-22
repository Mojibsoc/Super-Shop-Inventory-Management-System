# Super Shop Inventory Management (Enterprise Security & SQLite Edition)

A secure, Role-Based Access Control (RBAC) Inventory Management System built with **Python, Flask, SQLite3**, and cryptographic security controls.

## Security Architecture
1. **SQLite3 Relational Database (`data/inventory.db`)**: Uses parameterized queries (`?`) with `PRAGMA foreign_keys = ON` and `WAL` mode to eliminate SQL Injection and race conditions, while auto-syncing sanitized snapshots to `data/inventory.csv` and `data/users.json`.
2. **PBKDF2-HMAC-SHA256 Password Hashing (`security.py`)**: 260,000 iterations with 16-byte cryptographic salt and constant-time verification (`hmac.compare_digest`).
3. **Brute-Force Protection (`auth.py`)**: Locks accounts automatically for 5 minutes after 5 failed login attempts.
4. **Role-Based Access Control (RBAC)**:
   - `admin`: Full access (Users, Backups, Audit Logs, Delete Items).
   - `manager`: Add items, Stock In/Out, Update Prices.
   - `viewer`: Read-only access to Dashboard, Inventory, Low Stock, and Reports.
5. **Tamper-Evident HMAC Audit Logging (`data/audit.log`)**: Every log line is signed with an HMAC-SHA256 signature; any manual editing of `audit.log` is flagged as `TAMPERED` in the dashboard.
6. **CSRF & HTTP Security Headers**: Built-in CSRF tokens on all POST forms, HTTP-only session cookies, CSP, and XSS/Clickjacking headers.

## How to Run in Google Colab
1. Upload `Super_Shop_Management_Secure.zip` to Google Colab.
2. Run the following in a Colab cell:
```python
!unzip -q Super_Shop_Management_Secure.zip
%cd Super_Shop_Management
!python main.py
```
3. Click the generated Colab proxy URL shown in the output.
4. **Default Admin Login**:
   - **Username:** `admin`
   - **Password:** `Admin@1234`
