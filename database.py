
import sqlite3
import os


# Database file location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "instance",
    "records.db"
)


# ==================================================
# 1. DATABASE CONNECTION
# ==================================================

def get_db_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# ==================================================
# 2. DATABASE INITIALIZATION
# ==================================================

def initialize_database():

    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

    connection = get_db_connection()

    # USERS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        )
    """)

    # Add security columns to an existing users table
    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    }

    if "failed_attempts" not in existing_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0
        """)

    if "locked_until" not in existing_columns:
        connection.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until TEXT
        """)

    # SESSIONS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # RECORDS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()
