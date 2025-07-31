import sqlite3
import hashlib
import os
from datetime import datetime

# ✅ Step 1: Initialize DB and Table
def initialize_database():
    if not os.path.exists("users.db"):
        print("🆕 Creating users.db...")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized and ready.")

# ✅ Step 2: Hash Password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ✅ Step 3: Register New User
def register():
    username = input("Choose a username: ").strip()
    password = input("Choose a password: ").strip()

    if len(username) < 3 or len(password) < 6:
        print("❌ Username must be ≥3 characters, password ≥6 characters.")
        return

    hashed_pw = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
                       (username, hashed_pw, created_at))
        conn.commit()
        print("✅ User registered successfully.")
    except sqlite3.IntegrityError:
        print("❌ Username already exists.")
    except Exception as e:
        print("❌ Error during registration:", e)
    finally:
        conn.close()

# ✅ Step 4: Login
def login():
    username = input("Enter your username: ").strip()
    password = input("Enter your password: ").strip()

    hashed_pw = hash_password(password)

    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_pw))
        result = cursor.fetchone()
        if result:
            print("✅ Login successful!")
        else:
            print("❌ Invalid credentials.")
    except Exception as e:
        print("❌ Error during login:", e)
    finally:
        conn.close()

# ✅ Step 5: View Users (for verification/testing only)
def view_users():
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, created_at FROM users")
        rows = cursor.fetchall()
        print("\n📦 Registered Users:")
        for row in rows:
            print(f"  ID: {row[0]} | Username: {row[1]} | Registered: {row[2]}")
    except Exception as e:
        print("❌ Error fetching users:", e)
    finally:
        conn.close()

# ✅ MAIN MENU
def main():
    initialize_database()

    while True:
        print("\n====== MENU ======")
        print("1. Register")
        print("2. Login")
        print("3. View Registered Users (test)")
        print("4. Exit")

        choice = input("Enter choice (1/2/3/4): ").strip()

        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            view_users()
        elif choice == "4":
            print("👋 Exiting...")
            break
        else:
            print("show menu.")

if __name__ == "__main__":
    main()
    