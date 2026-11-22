import os
import csv
import json
import sqlite3
import shutil
import hashlib
from datetime import datetime
from security import hash_password, log_audit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "inventory.db")
CSV_PATH = os.path.join(DATA_DIR, "inventory.csv")
USERS_JSON_PATH = os.path.join(DATA_DIR, "users.json")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")

def get_db_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table with RBAC, failed_attempts, and locked_until for brute-force protection
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'manager', 'accounts_manager', 'viewer')),
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )
    """)

    # Inventory items table with strict constraints
    cur.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            qty INTEGER NOT NULL CHECK(qty >= 0),
            price REAL NOT NULL CHECK(price >= 0),
            min_stock INTEGER NOT NULL DEFAULT 10 CHECK(min_stock >= 0),
            updated_at TEXT NOT NULL
        )
    """)

    # Seed default strong Admin if empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        # Default strong password: Admin@1234
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", hash_password("Admin@1234"), "admin", now)
        )
        log_audit("SYSTEM", "INIT_ADMIN", "Default secure admin created (User: admin)")

    # Seed initial items matching the dashboard layout if empty
    cur.execute("SELECT COUNT(*) FROM items")
    if cur.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        sample_items = [
            ('Basmati Rice 25kg', 'Grocery', 20, 15.5, 10, now),
            ('Rice 5kg', 'Grocery', 4, 32.5, 10, now),
            ('Miniket Rice 25kg', 'Grocery', 34, 49.5, 10, now),
            ('Nazirshail Rice 25kg', 'Grocery', 3, 66.5, 10, now),
            ('Atap Rice 5kg', 'Grocery', 48, 83.5, 10, now),
            ('Brown Rice 1kg', 'Grocery', 55, 100.5, 10, now),
            ('Wheat Flour 2kg', 'Grocery', 62, 117.5, 10, now),
            ('Atta 5kg', 'Grocery', 69, 134.5, 10, now),
            ('Maida 1kg', 'Grocery', 76, 151.5, 10, now),
            ('Suji 1kg', 'Grocery', 83, 168.5, 10, now),
            ('Salt 1kg', 'Grocery', 200, 185.5, 10, now),
            ('Iodized Salt 1kg', 'Grocery', 97, 202.5, 10, now),
            ('Sugar 1kg', 'Grocery', 23, 219.5, 10, now),
            ('Brown Sugar 1kg', 'Grocery', 30, 236.5, 10, now),
            ('Mustard Oil 1L', 'Grocery', 37, 253.5, 10, now),
            ('Soybean Oil 5L', 'Grocery', 44, 270.5, 10, now),
            ('Sunflower Oil 1L', 'Grocery', 51, 287.5, 10, now),
            ('Olive Oil 500ml', 'Grocery', 58, 304.5, 10, now),
            ('Ghee 500g', 'Grocery', 65, 321.5, 10, now),
            ('Butter 200g', 'Grocery', 72, 338.5, 10, now),
            ('Lentils 1kg', 'Grocery', 79, 355.5, 10, now),
            ('Red Lentils 1kg', 'Grocery', 86, 372.5, 10, now),
            ('Chickpeas 1kg', 'Grocery', 93, 389.5, 10, now),
            ('Green Gram 1kg', 'Grocery', 100, 406.5, 10, now),
            ('Black Gram 1kg', 'Grocery', 26, 423.5, 10, now),
            ('Peas 1kg', 'Grocery', 33, 440.5, 10, now),
            ('Kidney Beans 1kg', 'Grocery', 40, 457.5, 10, now),
            ('White Beans 1kg', 'Grocery', 47, 474.5, 10, now),
            ('Peanut 500g', 'Grocery', 54, 491.5, 10, now),
            ('Cashew Nuts 250g', 'Grocery', 61, 18.5, 10, now),
            ('Almonds 250g', 'Grocery', 68, 35.5, 10, now),
            ('Raisins 250g', 'Grocery', 75, 52.5, 10, now),
            ('Dates 500g', 'Grocery', 82, 69.5, 10, now),
            ('Pistachio 250g', 'Grocery', 89, 86.5, 10, now),
            ('Walnuts 250g', 'Grocery', 96, 103.5, 10, now),
            ('Potato 5kg', 'Grocery', 22, 120.5, 10, now),
            ('Onion 2kg', 'Fruits & Vegetables', 29, 137.5, 10, now),
            ('Garlic 500g', 'Fruits & Vegetables', 36, 154.5, 10, now),
            ('Ginger 500g', 'Fruits & Vegetables', 43, 171.5, 10, now),
            ('Green Chili 250g', 'Fruits & Vegetables', 50, 188.5, 10, now),
            ('Tomato 1kg', 'Fruits & Vegetables', 57, 205.5, 10, now),
            ('Carrot 1kg', 'Fruits & Vegetables', 64, 222.5, 10, now),
            ('Cucumber 1kg', 'Fruits & Vegetables', 71, 239.5, 10, now),
            ('Eggplant 1kg', 'Fruits & Vegetables', 78, 256.5, 10, now),
            ('Cauliflower 1pc', 'Fruits & Vegetables', 85, 273.5, 10, now),
            ('Cabbage 1pc', 'Fruits & Vegetables', 92, 290.5, 10, now),
            ('Pumpkin 1kg', 'Fruits & Vegetables', 99, 307.5, 10, now),
            ('Spinach 500g', 'Fruits & Vegetables', 25, 324.5, 10, now),
            ('Lettuce 1pc', 'Fruits & Vegetables', 32, 341.5, 10, now),
            ('Capsicum 500g', 'Fruits & Vegetables', 39, 358.5, 10, now),
            ('Lemon 500g', 'Fruits & Vegetables', 46, 375.5, 10, now),
            ('Coriander 100g', 'Fruits & Vegetables', 53, 392.5, 10, now),
            ('Mint Leaves 100g', 'Fruits & Vegetables', 60, 409.5, 10, now),
            ('Radish 1kg', 'Fruits & Vegetables', 67, 426.5, 10, now),
            ('Beans 500g', 'Fruits & Vegetables', 74, 443.5, 10, now),
            ('Okra 500g', 'Fruits & Vegetables', 81, 460.5, 10, now),
            ('Bitter Gourd 500g', 'Fruits & Vegetables', 88, 477.5, 10, now),
            ('Bottle Gourd 1pc', 'Fruits & Vegetables', 95, 494.5, 10, now),
            ('Sweet Potato 1kg', 'Fruits & Vegetables', 21, 21.5, 10, now),
            ('Beetroot 500g', 'Fruits & Vegetables', 28, 38.5, 10, now),
            ('Apple 1kg', 'Fruits & Vegetables', 35, 55.5, 10, now),
            ('Banana 1 Dozen', 'Fruits & Vegetables', 42, 72.5, 10, now),
            ('Orange 1kg', 'Fruits & Vegetables', 49, 89.5, 10, now),
            ('Mango 1kg', 'Fruits & Vegetables', 56, 106.5, 10, now),
            ('Papaya 1pc', 'Fruits & Vegetables', 63, 123.5, 10, now),
            ('Pineapple 1pc', 'Fruits & Vegetables', 70, 140.5, 10, now),
            ('Guava 1kg', 'Fruits & Vegetables', 77, 157.5, 10, now),
            ('Grapes 500g', 'Fruits & Vegetables', 84, 174.5, 10, now),
            ('Watermelon 1pc', 'Fruits & Vegetables', 91, 191.5, 10, now),
            ('Pomegranate 1kg', 'Fruits & Vegetables', 98, 208.5, 10, now),
            ('Coconut 1pc', 'Fruits & Vegetables', 24, 225.5, 10, now),
            ('Dates 1kg', 'Fruits & Vegetables', 31, 242.5, 10, now),
            ('Jackfruit 1pc', 'Fruits & Vegetables', 38, 259.5, 10, now),
            ('Strawberry 250g', 'Fruits & Vegetables', 45, 276.5, 10, now),
            ('Milk 1L', 'Fruits & Vegetables', 52, 293.5, 10, now),
            ('Powder Milk 500g', 'Dairy & Eggs', 59, 310.5, 10, now),
            ('Condensed Milk 400g', 'Dairy & Eggs', 66, 327.5, 10, now),
            ('Yogurt 500g', 'Dairy & Eggs', 73, 344.5, 10, now),
            ('Sweet Yogurt 500g', 'Dairy & Eggs', 80, 361.5, 10, now),
            ('Cheese 200g', 'Dairy & Eggs', 87, 378.5, 10, now),
            ('Paneer 200g', 'Dairy & Eggs', 94, 395.5, 10, now),
            ('Cream 200ml', 'Dairy & Eggs', 20, 412.5, 10, now),
            ('Eggs 12pcs', 'Dairy & Eggs', 27, 429.5, 10, now),
            ('Chicken 1kg', 'Dairy & Eggs', 34, 446.5, 10, now),
            ('Beef 1kg', 'Dairy & Eggs', 41, 463.5, 10, now),
            ('Mutton 1kg', 'Dairy & Eggs', 48, 480.5, 10, now),
            ('Fish 1kg', 'Dairy & Eggs', 55, 497.5, 10, now),
            ('Prawn 500g', 'Meat & Fish', 62, 24.5, 10, now),
            ('Hilsa Fish 1kg', 'Meat & Fish', 69, 41.5, 10, now),
            ('Rohu Fish 1kg', 'Meat & Fish', 76, 58.5, 10, now),
            ('Tilapia Fish 1kg', 'Meat & Fish', 83, 75.5, 10, now),
            ('Canned Tuna 185g', 'Meat & Fish', 90, 92.5, 10, now),
            ('Frozen Chicken 1kg', 'Meat & Fish', 97, 109.5, 10, now),
            ('Chicken Nuggets 500g', 'Meat & Fish', 23, 126.5, 10, now),
            ('Fish Fingers 500g', 'Meat & Fish', 30, 143.5, 10, now),
            ('Bread 400g', 'Meat & Fish', 37, 160.5, 10, now),
            ('Brown Bread 400g', 'Meat & Fish', 44, 177.5, 10, now),
            ('Burger Bun 4pcs', 'Bakery', 51, 194.5, 10, now),
            ('Cake 500g', 'Bakery', 58, 211.5, 10, now),
            ('Biscuits 200g', 'Bakery', 65, 228.5, 10, now),
            ('Cookies 200g', 'Bakery', 72, 245.5, 10, now),
            ('Toast 200g', 'Bakery', 79, 262.5, 10, now),
            ('Oats 500g', 'Bakery', 86, 279.5, 10, now),
            ('Cornflakes 500g', 'Bakery', 93, 296.5, 10, now),
            ('Chira 500g', 'Bakery', 100, 313.5, 10, now),
            ('Muri 500g', 'Bakery', 26, 330.5, 10, now),
            ('Popcorn 200g', 'Bakery', 33, 347.5, 10, now),
            ('Noodles 8pcs', 'Bakery', 40, 364.5, 10, now),
            ('Instant Soup 50g', 'Bakery', 47, 381.5, 10, now),
            ('Pasta 500g', 'Bakery', 54, 398.5, 10, now),
            ('Macaroni 500g', 'Grocery', 61, 415.5, 10, now),
            ('Spaghetti 500g', 'Grocery', 68, 432.5, 10, now),
            ('Vermicelli 200g', 'Grocery', 75, 449.5, 10, now),
            ('Tomato Sauce 500g', 'Grocery', 82, 466.5, 10, now),
            ('Chili Sauce 250g', 'Grocery', 89, 483.5, 10, now),
            ('Soy Sauce 250ml', 'Grocery', 96, 500.5, 10, now),
            ('Vinegar 500ml', 'Grocery', 22, 27.5, 10, now),
            ('Mayonnaise 250g', 'Grocery', 29, 44.5, 10, now),
            ('Mustard Paste 200g', 'Grocery', 36, 61.5, 10, now),
            ('Tomato Paste 200g', 'Grocery', 43, 78.5, 10, now),
            ('Ketchup 500g', 'Grocery', 50, 95.5, 10, now),
            ('Hot Sauce 150ml', 'Grocery', 57, 112.5, 10, now),
            ('Black Pepper 100g', 'Grocery', 64, 129.5, 10, now),
            ('White Pepper 50g', 'Grocery', 71, 146.5, 10, now),
            ('Turmeric Powder 200g', 'Grocery', 78, 163.5, 10, now),
            ('Chili Powder 200g', 'Grocery', 85, 180.5, 10, now),
            ('Coriander Powder 200g', 'Grocery', 92, 197.5, 10, now),
            ('Cumin Powder 100g', 'Grocery', 99, 214.5, 10, now),
            ('Cinnamon 50g', 'Grocery', 25, 231.5, 10, now),
            ('Cardamom 50g', 'Grocery', 32, 248.5, 10, now),
            ('Cloves 50g', 'Grocery', 39, 265.5, 10, now),
            ('Bay Leaves 25g', 'Grocery', 46, 282.5, 10, now),
            ('Curry Powder 100g', 'Grocery', 53, 299.5, 10, now),
            ('Biryani Masala 100g', 'Grocery', 60, 316.5, 10, now),
            ('Garam Masala 100g', 'Grocery', 67, 333.5, 10, now),
            ('Chaat Masala 100g', 'Grocery', 74, 350.5, 10, now),
            ('Meat Masala 100g', 'Grocery', 81, 367.5, 10, now),
            ('Fish Masala 100g', 'Grocery', 88, 384.5, 10, now),
            ('Chicken Masala 100g', 'Grocery', 95, 401.5, 10, now),
            ('Tea 200g', 'Grocery', 21, 418.5, 10, now),
            ('Green Tea 100g', 'Grocery', 28, 435.5, 10, now),
            ('Coffee 100g', 'Grocery', 35, 452.5, 10, now),
            ('Instant Coffee 100g', 'Grocery', 42, 469.5, 10, now),
            ('Chocolate Drink 500g', 'Grocery', 49, 486.5, 10, now),
            ('Fruit Juice 1L', 'Grocery', 56, 503.5, 10, now),
            ('Mango Juice 1L', 'Grocery', 63, 30.5, 10, now),
            ('Orange Juice 1L', 'Grocery', 70, 47.5, 10, now),
            ('Soft Drink 2L', 'Grocery', 77, 64.5, 10, now),
            ('Mineral Water 1L', 'Grocery', 84, 81.5, 10, now),
            ('Coconut Water 500ml', 'Grocery', 91, 98.5, 10, now),
            ('Energy Drink 250ml', 'Snacks & Drinks', 98, 115.5, 10, now),
            ('Honey 500g', 'Snacks & Drinks', 24, 132.5, 10, now),
            ('Jam 500g', 'Snacks & Drinks', 31, 149.5, 10, now),
            ('Peanut Butter 340g', 'Snacks & Drinks', 38, 166.5, 10, now),
            ('Chocolate Spread 350g', 'Snacks & Drinks', 45, 183.5, 10, now),
            ('Dark Chocolate 100g', 'Snacks & Drinks', 52, 200.5, 10, now),
            ('Milk Chocolate 100g', 'Snacks & Drinks', 59, 217.5, 10, now),
            ('Candy 100g', 'Snacks & Drinks', 66, 234.5, 10, now),
            ('Lollipop 10pcs', 'Snacks & Drinks', 73, 251.5, 10, now),
            ('Ice Cream 1L', 'Snacks & Drinks', 80, 268.5, 10, now),
            ('Potato Chips 150g', 'Snacks & Drinks', 87, 285.5, 10, now),
            ('Nachos 150g', 'Snacks & Drinks', 94, 302.5, 10, now),
            ('Popcorn 100g', 'Snacks & Drinks', 20, 319.5, 10, now),
            ('Crackers 200g', 'Snacks & Drinks', 27, 336.5, 10, now),
            ('Rice Crackers 150g', 'Snacks & Drinks', 34, 353.5, 10, now),
            ('Coconut Biscuit 200g', 'Snacks & Drinks', 41, 370.5, 10, now),
            ('Wafer 100g', 'Snacks & Drinks', 48, 387.5, 10, now),
            ('Chutney 250g', 'Snacks & Drinks', 55, 404.5, 10, now),
            ('Pickle 400g', 'Snacks & Drinks', 62, 421.5, 10, now),
            ('Olives 250g', 'Snacks & Drinks', 69, 438.5, 10, now),
            ('Mushroom 200g', 'Snacks & Drinks', 76, 455.5, 10, now),
            ('Sweet Corn 400g', 'Snacks & Drinks', 83, 472.5, 10, now),
            ('Green Peas 400g', 'Snacks & Drinks', 90, 489.5, 10, now),
            ('Canned Beans 400g', 'Snacks & Drinks', 97, 16.5, 10, now),
            ('Canned Pineapple 400g', 'Snacks & Drinks', 23, 33.5, 10, now),
            ('Baking Powder 100g', 'Grocery', 30, 50.5, 10, now),
            ('Baking Soda 100g', 'Grocery', 37, 67.5, 10, now),
            ('Yeast 50g', 'Grocery', 44, 84.5, 10, now),
            ('Corn Flour 500g', 'Grocery', 51, 101.5, 10, now),
            ('Custard Powder 100g', 'Grocery', 58, 118.5, 10, now),
            ('Gelatin 50g', 'Grocery', 65, 135.5, 10, now),
            ('Cocoa Powder 100g', 'Grocery', 72, 152.5, 10, now),
            ('Vanilla Essence 30ml', 'Grocery', 79, 169.5, 10, now),
            ('Food Color 25g', 'Grocery', 86, 186.5, 10, now),
            ('Pudding Mix 100g', 'Grocery', 93, 203.5, 10, now),
            ('Puffed Rice 500g', 'Grocery', 100, 220.5, 10, now),
            ('Flattened Rice 500g', 'Grocery', 26, 237.5, 10, now),
            ('Semolina 500g', 'Grocery', 33, 254.5, 10, now),
            ('Barley 500g', 'Grocery', 40, 271.5, 10, now),
            ('Quinoa 500g', 'Grocery', 47, 288.5, 10, now),
            ('Chia Seeds 200g', 'Grocery', 54, 305.5, 10, now),
            ('Flax Seeds 200g', 'Grocery', 61, 322.5, 10, now),
            ('Sesame Seeds 200g', 'Grocery', 68, 339.5, 10, now),
            ('Pumpkin Seeds 200g', 'Grocery', 75, 356.5, 10, now),
            ('Sunflower Seeds 200g', 'Grocery', 82, 373.5, 10, now),
            ('Dried Coconut 200g', 'Grocery', 89, 390.5, 10, now),
            ('Desiccated Coconut 200g', 'Grocery', 96, 407.5, 10, now),
            ('Tamarind 250g', 'Grocery', 22, 424.5, 10, now),
            ('Jaggery 500g', 'Grocery', 29, 441.5, 10, now),
            ('Molasses 500g', 'Grocery', 36, 458.5, 10, now),
            ('Lemon Juice 250ml', 'Grocery', 43, 475.5, 10, now),
            ('Rose Water 250ml', 'Grocery', 50, 492.5, 10, now),
            ('Kewra Water 250ml', 'Grocery', 57, 19.5, 10, now),
        ]
        cur.executemany(
            "INSERT INTO items (name, category, qty, price, min_stock, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            sample_items
        )
        log_audit("SYSTEM", "INIT_DATA", "Initial inventory items seeded into SQLite database")

    conn.commit()
    conn.close()
    sync_flat_files()

def sync_flat_files():
    """Exports sanitized snapshots to data/inventory.csv and data/users.json (WITHOUT password hashes)."""
    conn = get_db_connection()
    items = conn.execute("SELECT id, name, category, qty, price, min_stock, updated_at FROM items ORDER BY id").fetchall()
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Name", "Category", "Qty", "Price", "Min", "Updated"])
        for r in items:
            writer.writerow([r["id"], r["name"], r["category"], r["qty"], r["price"], r["min_stock"], r["updated_at"]])

    users = conn.execute("SELECT id, username, role, failed_attempts, locked_until, created_at FROM users ORDER BY id").fetchall()
    users_list = [dict(u) for u in users]
    with open(USERS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(users_list, f, indent=4)
    conn.close()

def create_secure_backup(username: str, ip: str = "127.0.0.1") -> str:
    """Creates a timestamped SQLite backup along with a SHA-256 checksum file."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"inventory_backup_{ts}.db")
    shutil.copy2(DB_PATH, backup_file)

    # Calculate SHA-256 hash for integrity verification
    sha256 = hashlib.sha256()
    with open(backup_file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    checksum = sha256.hexdigest()

    with open(f"{backup_file}.sha256", "w", encoding="utf-8") as f:
        f.write(f"{checksum}  {os.path.basename(backup_file)}\n")

    log_audit(username, "BACKUP_CREATED", f"File: {os.path.basename(backup_file)} | SHA256: {checksum[:16]}...", ip)
    return os.path.basename(backup_file)
