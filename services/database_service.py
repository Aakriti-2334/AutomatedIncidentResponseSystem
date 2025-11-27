import sqlite3
import time
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE_NAME = 'incident_response.db'

def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Create blocked_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY
        )
    ''')

    # Create alerted_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerted_ips (
            ip TEXT PRIMARY KEY,
            unblock_time REAL
        )
    ''')

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Create ip_reputation table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            reputation_score INTEGER NOT NULL,
            last_seen REAL NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print(f"✅ Database '{DATABASE_NAME}' initialized successfully.")

def get_ip_reputation(ip):
    """Retrieve the reputation for a given IP."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT reputation_score, last_seen FROM ip_reputation WHERE ip = ?", (ip,))
    reputation = cursor.fetchone()
    conn.close()
    return reputation

def update_ip_reputation(ip, score):
    """Create or update the reputation score for an IP."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    current_time = time.time()
    cursor.execute(
        "INSERT OR REPLACE INTO ip_reputation (ip, reputation_score, last_seen) VALUES (?, ?, ?)",
        (ip, score, current_time)
    )
    conn.commit()
    conn.close()

def get_all_reputations():
    """Retrieve all IP reputations for decay calculation."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT ip, reputation_score, last_seen FROM ip_reputation")
    reputations = cursor.fetchall()
    conn.close()
    return reputations

def create_user(username, password):
    """Create a new user with a hashed password."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, generate_password_hash(password)))
        conn.commit()
        print(f"✅ User '{username}' created successfully.")
        return True
    except sqlite3.IntegrityError:
        print(f"❌ User '{username}' already exists.")
        return False
    finally:
        conn.close()

def get_user_by_username(username):
    """Retrieve a user by username."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    """Retrieve a user by ID."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_blocked_ip(ip):
    """Add an IP to the blocked_ips table."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # IP already exists
        return False
    finally:
        conn.close()

def remove_blocked_ip(ip):
    """Remove an IP from the blocked_ips table."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

def get_blocked_ips():
    """Retrieve all blocked IPs."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM blocked_ips")
    ips = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ips

def add_alerted_ip(ip, unblock_time):
    """Add an IP to the alerted_ips table with an unblock time."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO alerted_ips (ip, unblock_time) VALUES (?, ?)", (ip, unblock_time))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # IP already exists, update unblock time
        cursor.execute("UPDATE alerted_ips SET unblock_time = ? WHERE ip = ?", (unblock_time, ip))
        conn.commit()
        return True
    finally:
        conn.close()

def remove_alerted_ip(ip):
    """Remove an IP from the alerted_ips table."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerted_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    return cursor.rowcount > 0

def get_alerted_ips():
    """Retrieve all alerted IPs with their unblock times."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT ip, unblock_time FROM alerted_ips")
    alerts = [{"ip": row[0], "unblock_time": row[1]} for row in cursor.fetchall()]
    conn.close()
    return alerts

def is_ip_blocked(ip):
    """Check if an IP is currently permanently blocked."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def is_ip_alerted(ip):
    """Check if an IP is currently alerted (temporarily blocked)."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT unblock_time FROM alerted_ips WHERE ip = ?", (ip,))
    result = cursor.fetchone()
    conn.close()
    if result:
        unblock_time = result[0]
        return time.time() < unblock_time
    return False

def clear_blocked_ips():
    """Remove all IPs from the blocked_ips table."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()
    print("✅ All permanently blocked IPs have been cleared.")

def clear_alerted_ips():
    """Remove all IPs from the alerted_ips table."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM alerted_ips")
    conn.commit()
    conn.close()
    print("✅ All temporarily blocked IPs (alerts) have been cleared.")