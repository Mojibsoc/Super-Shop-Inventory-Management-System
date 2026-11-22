from datetime import datetime
from database import get_db_connection, sync_flat_files
from security import sanitize_input, log_audit

def get_dashboard_stats() -> dict:
    conn = get_db_connection()
    total_items = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    total_units = conn.execute("SELECT COALESCE(SUM(qty), 0) FROM items").fetchone()[0]
    stock_value = conn.execute("SELECT COALESCE(SUM(qty * price), 0.0) FROM items").fetchone()[0]
    low_stock_count = conn.execute("SELECT COUNT(*) FROM items WHERE qty < min_stock").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    low_stock_items = conn.execute("SELECT * FROM items WHERE qty < min_stock ORDER BY qty ASC").fetchall()
    conn.close()
    return {
        "total_items": total_items,
        "total_units": total_units,
        "stock_value": f"{stock_value:,.2f}",
        "low_stock": low_stock_count,
        "total_users": total_users,
        "low_stock_items": [dict(r) for r in low_stock_items]
    }

def get_all_items(search: str = "") -> list[dict]:
    conn = get_db_connection()
    if search:
        q = f"%{sanitize_input(search, 50)}%"
        rows = conn.execute(
            "SELECT * FROM items WHERE name LIKE ? OR category LIKE ? ORDER BY id ASC", (q, q)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM items ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_item(actor: str, name: str, category: str, qty: int, price: float, min_stock: int, ip: str = "127.0.0.1") -> tuple[bool, str]:
    clean_name = sanitize_input(name, 80)
    clean_cat = sanitize_input(category, 50)
    if not clean_name or not clean_cat:
        return False, "Item name and category are required."
    if qty < 0 or price < 0 or min_stock < 0:
        return False, "Quantity, price, and minimum stock cannot be negative."

    conn = get_db_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn.execute(
        "INSERT INTO items (name, category, qty, price, min_stock, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (clean_name, clean_cat, qty, round(price, 2), min_stock, now)
    )
    conn.commit()
    conn.close()
    sync_flat_files()
    log_audit(actor, "ITEM_ADDED", f"Added '{clean_name}' (Qty: {qty}, Price: {price})", ip)
    return True, f"Item '{clean_name}' added successfully."

def update_stock(actor: str, item_id: int, action_type: str, amount: int, ip: str = "127.0.0.1") -> tuple[bool, str]:
    if amount <= 0:
        return False, "Amount must be greater than zero."
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        return False, "Item not found."

    new_qty = item["qty"] + amount if action_type == "in" else item["qty"] - amount
    if new_qty < 0:
        conn.close()
        return False, f"Insufficient stock! Available: {item['qty']}"

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn.execute("UPDATE items SET qty = ?, updated_at = ? WHERE id = ?", (new_qty, now, item_id))
    conn.commit()
    conn.close()
    sync_flat_files()
    log_audit(actor, f"STOCK_{action_type.upper()}", f"Item '{item['name']}' ({item['qty']} -> {new_qty})", ip)
    return True, f"Stock updated for '{item['name']}' (New Qty: {new_qty})."

def update_price(actor: str, item_id: int, new_price: float, ip: str = "127.0.0.1") -> tuple[bool, str]:
    if new_price < 0:
        return False, "Price cannot be negative."
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        return False, "Item not found."

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn.execute("UPDATE items SET price = ?, updated_at = ? WHERE id = ?", (round(new_price, 2), now, item_id))
    conn.commit()
    conn.close()
    sync_flat_files()
    log_audit(actor, "PRICE_UPDATED", f"Item '{item['name']}' price: {item['price']} -> {new_price}", ip)
    return True, f"Price updated for '{item['name']}'."

def delete_item(actor: str, item_id: int, ip: str = "127.0.0.1") -> tuple[bool, str]:
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not item:
        conn.close()
        return False, "Item not found."
    conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    sync_flat_files()
    log_audit(actor, "ITEM_DELETED", f"Deleted '{item['name']}' (ID: {item_id})", ip)
    return True, f"Item '{item['name']}' deleted."
