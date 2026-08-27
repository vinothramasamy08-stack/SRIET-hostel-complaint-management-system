import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hostel.db")

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Students Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Single Management Admin Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Complaints Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            category TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            rectification TEXT,
            proof TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Enforce SINGLE Management Admin Account (Remove any extra admins)
    cursor.execute("DELETE FROM admins WHERE username != 'admin'")

    # Seed Single Super Admin if not exists
    admin_exists = cursor.execute("SELECT 1 FROM admins WHERE username = 'admin'").fetchone()
    if not admin_exists:
        hashed_admin_pw = generate_password_hash('admin123')
        cursor.execute("""
            INSERT INTO admins (username, password)
            VALUES (?, ?)
        """, ('admin', hashed_admin_pw))

    # Seed Demo Student if not exists
    student_exists = cursor.execute("SELECT 1 FROM students WHERE student_id = ?", ('STU001',)).fetchone()
    if not student_exists:
        hashed_stu_pw = generate_password_hash('12345')
        cursor.execute("""
            INSERT INTO students (student_id, name, password)
            VALUES (?, ?, ?)
        """, ('STU001', 'Demo Student', hashed_stu_pw))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized with strict single-admin enforcement.")
