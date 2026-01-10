import sqlite3
import os
import json
from datetime import datetime

# Import Turso's drop-in replacement if available
try:
    import libsql as turso
    HAS_TURSO = True
except ImportError:
    HAS_TURSO = False

DB_NAME = "zk_vault_v2.db"

def get_db_connection():
    url = os.environ.get("TURSO_DATABASE_URL")
    token = os.environ.get("TURSO_AUTH_TOKEN")
    
    if url and HAS_TURSO:
        # Turso Cloud (libsql)
        conn = turso.connect(url, auth_token=token)
        return conn
    else:
        # Local SQLite
        conn = sqlite3.connect(DB_NAME)
        return conn

def to_dict(cursor, row):
    """Helper to convert a DB row to a dictionary."""
    if row is None:
        return None
    return {column[0]: row[i] for i, column in enumerate(cursor.description)}

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # User table: Stores auth info (hashed) and the encrypted vault blob
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    auth_hash TEXT NOT NULL, 
                    salt TEXT NOT NULL,
                    encrypted_blob TEXT,
                    security_score INTEGER DEFAULT 0,
                    pwned_count INTEGER DEFAULT 0,
                    item_count INTEGER DEFAULT 0,
                    note_count INTEGER DEFAULT 0,
                    file_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # Migrate if needed
    try:
        # Standard SQLite check
        c.execute("ALTER TABLE users ADD COLUMN item_count INTEGER DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN note_count INTEGER DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN file_count INTEGER DEFAULT 0")
    except (sqlite3.OperationalError, ValueError, Exception) as e:
        # Ignore duplicate column errors (common in both SQLite and Turso)
        pass 
        
    conn.commit()
    conn.close()

def create_user(username, auth_hash, salt, encrypted_blob):
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, auth_hash, salt, encrypted_blob) VALUES (?, ?, ?, ?)',
                     (username, auth_hash, salt, encrypted_blob))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user(username):
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    user = to_dict(c, row)
    conn.close()
    return user

def update_vault(username, encrypted_blob, security_score=0, pwned_count=0, item_count=0, note_count=0, file_count=0):
    conn = get_db_connection()
    conn.execute('''UPDATE users 
                  SET encrypted_blob = ?, security_score = ?, pwned_count = ?, 
                      item_count = ?, note_count = ?, file_count = ? 
                  WHERE username = ?''', 
                 (encrypted_blob, security_score, pwned_count, item_count, note_count, file_count, username))
    conn.commit()
    conn.close()

def get_all_users_admin():
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute('SELECT username, encrypted_blob, security_score, pwned_count, item_count, note_count, file_count, created_at FROM users').fetchall()
    users = [to_dict(c, r) for r in rows]
    conn.close()
    return users
