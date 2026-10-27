"""
Database connection, schema migration, and seeding manager.
Uses SQLite for self-contained, reproducible academic testing.
"""

import sqlite3
import hashlib
from typing import Generator
from contextlib import contextmanager
from ..config import DATABASE_PATH

def hash_password(password: str) -> str:
    """Simulate SHA-256 password hashing for realistic authentication."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def get_connection() -> sqlite3.Connection:
    """Create a connection with row dict access enabled."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database transactions."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    """Initialize schema and seed sample data."""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                email TEXT NOT NULL,
                full_name TEXT NOT NULL,
                account_balance REAL NOT NULL DEFAULT 0.0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 2. Products / Inventory Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sku TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price REAL NOT NULL,
                stock_quantity INTEGER NOT NULL,
                description TEXT NOT NULL
            );
        """)

        # 3. Transactions Table (for financial data exposure demos)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reference_code TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        """)

        # 4. Security Audit Logs Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                endpoint TEXT NOT NULL,
                mode TEXT NOT NULL,
                raw_input TEXT NOT NULL,
                executed_query TEXT NOT NULL,
                execution_time_ms REAL NOT NULL,
                status TEXT NOT NULL,
                anomaly_detected INTEGER DEFAULT 0,
                details TEXT
            );
        """)
        
        # Seed users if table is empty
        cursor.execute("SELECT COUNT(*) FROM users;")
        if cursor.fetchone()[0] == 0:
            seed_data(conn)

def seed_data(conn: sqlite3.Connection) -> None:
    """Populate realistic test data for authentication and search tests."""
    cursor = conn.cursor()
    
    users = [
        (1, "admin", hash_password("SuperSecretAdminPass!"), "admin", "admin@securesphere.corp", "Chief Security Officer", 1250000.0, 1),
        (2, "john_doe", hash_password("Password123!"), "user", "john.doe@email.com", "John Doe", 4500.50, 1),
        (3, "alice_smith", hash_password("AlicePass2026#"), "manager", "alice.smith@securesphere.corp", "Alice Smith", 89400.00, 1),
        (4, "bob_martin", hash_password("BobSecret99"), "user", "bob.martin@email.com", "Bob Martin", 1200.75, 1),
        (5, "sec_auditor", hash_password("Auditor$ecure#2026"), "auditor", "auditor@securesphere.corp", "Security Compliance Auditor", 65000.00, 1)
    ]
    cursor.executemany("""
        INSERT INTO users (id, username, password_hash, role, email, full_name, account_balance, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, users)

    products = [
        ("SEC-FW-01", "NextGen Enterprise Firewall", "Network Security", 4999.00, 15, "Multi-gigabit deep packet inspection and intrusion defense appliance."),
        ("SEC-HSM-02", "Hardware Security Module (HSM)", "Cryptography", 12500.00, 6, "FIPS 140-2 Level 3 validated tamper-evident key storage module."),
        ("SEC-WAF-03", "Cloud Web Application Firewall", "Application Security", 1299.00, 50, "Layer 7 inspection engine protecting against OWASP Top 10 web injection vectors."),
        ("SEC-EDR-04", "Endpoint Threat Detection Suite", "Endpoint Security", 349.00, 250, "Continuous behavioral anomaly detection and threat hunting agent."),
        ("NET-RTR-05", "Encrypted Core Gateway Router", "Infrastructure", 3200.00, 20, "Zero-trust transit router with hardware IPsec and WireGuard offloading.")
    ]
    cursor.executemany("""
        INSERT INTO products (sku, name, category, price, stock_quantity, description)
        VALUES (?, ?, ?, ?, ?, ?);
    """, products)

    transactions = [
        (1, "TXN-90211", 50000.00, "COMPLETED"),
        (2, "TXN-90212", 249.99, "COMPLETED"),
        (2, "TXN-90213", 1200.00, "COMPLETED"),
        (3, "TXN-90214", 15400.00, "COMPLETED"),
        (4, "TXN-90215", 35.50, "COMPLETED")
    ]
    cursor.executemany("""
        INSERT INTO transactions (user_id, reference_code, amount, status)
        VALUES (?, ?, ?, ?);
    """, transactions)

def reset_db() -> None:
    """Drop and recreate all tables for a fresh state."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS audit_logs;")
        cursor.execute("DROP TABLE IF EXISTS transactions;")
        cursor.execute("DROP TABLE IF EXISTS products;")
        cursor.execute("DROP TABLE IF EXISTS users;")
    init_db()
