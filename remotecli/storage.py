import sqlite3
import time
from typing import Optional, List, Tuple
from .config import DB_PATH, ensure_app_dirs
from .security import encrypt_dict, decrypt_dict, hash_password

def _conn():
    ensure_app_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'auditor', 'readonly'))
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('ssh','winrm')),
        data BLOB NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        actor TEXT NOT NULL,
        target TEXT NOT NULL,
        channel TEXT NOT NULL CHECK (channel IN ('ssh','winrm')),
        command TEXT NOT NULL,
        exit_code INTEGER,
        stdout TEXT,
        stderr TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT UNIQUE NOT NULL,
        hostname TEXT,
        os TEXT,
        last_seen INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT NOT NULL,
        os TEXT NOT NULL CHECK (os IN ('windows','linux')),
        content TEXT NOT NULL,
        signed INTEGER NOT NULL DEFAULT 0,
        signature TEXT,
        key_id TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        category TEXT NOT NULL,
        compliant INTEGER NOT NULL,
        severity TEXT,
        details TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        device_id TEXT,
        level TEXT NOT NULL,
        message TEXT NOT NULL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS policy_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_id TEXT UNIQUE NOT NULL,
        secret BLOB NOT NULL,
        active INTEGER NOT NULL DEFAULT 0,
        created_ts INTEGER NOT NULL
    )
    """)
    # Migrate older policies table to add columns if missing
    try:
        cur.execute("ALTER TABLE policies ADD COLUMN signature TEXT")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE policies ADD COLUMN key_id TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()

def add_user(username: str, password: str, role: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, hash_password(password), role))
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row

def list_users() -> List[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_credential(name: str, cred_type: str, data: dict):
    blob = encrypt_dict(data)
    conn = _conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO credentials (name, type, data) VALUES (?,?,?)",
                (name, cred_type, blob))
    conn.commit()
    conn.close()

def get_credential(name: str) -> Optional[Tuple[str, dict]]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT type, data FROM credentials WHERE name = ?", (name,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return row["type"], decrypt_dict(row["data"])

def list_credentials() -> List[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT name, type FROM credentials ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    return rows

def delete_credential(name: str) -> bool:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM credentials WHERE name = ?", (name,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def add_command(actor: str, target: str, channel: str, command: str,
                exit_code: int, stdout: str, stderr: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO commands (ts, actor, target, channel, command, exit_code, stdout, stderr)
        VALUES (?,?,?,?,?,?,?,?)
    """, (int(time.time()), actor, target, channel, command, exit_code, stdout, stderr))
    conn.commit()
    conn.close()

def list_commands(limit: int = 50, actor: Optional[str] = None) -> List[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    if actor:
        cur.execute("""
            SELECT ts, actor, target, channel, command, exit_code
            FROM commands WHERE actor = ?
            ORDER BY ts DESC LIMIT ?
        """, (actor, limit))
    else:
        cur.execute("""
            SELECT ts, actor, target, channel, command, exit_code
            FROM commands ORDER BY ts DESC LIMIT ?
        """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def clear_commands(actor: Optional[str] = None) -> int:
    conn = _conn()
    cur = conn.cursor()
    if actor:
        cur.execute("DELETE FROM commands WHERE actor = ?", (actor,))
    else:
        cur.execute("DELETE FROM commands")
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted

def upsert_device(device_id: str, hostname: str, os: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO devices (device_id, hostname, os, last_seen)
        VALUES (?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname, os=excluded.os, last_seen=excluded.last_seen
    """, (device_id, hostname, os, int(time.time())))
    conn.commit()
    conn.close()

def add_policy(version: str, os: str, content: str, signed: bool = False, signature: Optional[str] = None, key_id: Optional[str] = None):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO policies (version, os, content, signed, signature, key_id) VALUES (?,?,?,?,?,?)
    """, (version, os, content, 1 if signed else 0, signature, key_id))
    conn.commit()
    conn.close()

def get_latest_policy(os: str) -> Optional[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM policies WHERE os = ? ORDER BY id DESC LIMIT 1
    """, (os,))
    row = cur.fetchone()
    conn.close()
    return row

def add_finding(device_id: str, rule_id: str, category: str, compliant: bool, severity: str, details: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO findings (ts, device_id, rule_id, category, compliant, severity, details)
        VALUES (?,?,?,?,?,?,?)
    """, (int(time.time()), device_id, rule_id, category, 1 if compliant else 0, severity, details))
    conn.commit()
    conn.close()

def list_findings(device_id: Optional[str] = None, limit: int = 100) -> List[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    if device_id:
        cur.execute("""
            SELECT * FROM findings WHERE device_id = ? ORDER BY ts DESC LIMIT ?
        """, (device_id, limit))
    else:
        cur.execute("""
            SELECT * FROM findings ORDER BY ts DESC LIMIT ?
        """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def add_alert(level: str, message: str, device_id: Optional[str] = None):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (ts, device_id, level, message) VALUES (?,?,?,?)
    """, (int(time.time()), device_id, level, message))
    conn.commit()
    conn.close()

def add_policy_key(key_id: str, secret: bytes, active: bool = False):
    blob = encrypt_dict({"secret": base64.b64encode(secret).decode("utf-8")})
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO policy_keys (key_id, secret, active, created_ts) VALUES (?,?,?,?)
    """, (key_id, blob, 1 if active else 0, int(time.time())))
    conn.commit()
    conn.close()

def list_policy_keys() -> List[sqlite3.Row]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT key_id, active, created_ts FROM policy_keys ORDER BY created_ts DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def set_active_policy_key(key_id: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("UPDATE policy_keys SET active = 0")
    cur.execute("UPDATE policy_keys SET active = 1 WHERE key_id = ?", (key_id,))
    conn.commit()
    conn.close()

def get_active_policy_key() -> Optional[Tuple[str, bytes]]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT key_id, secret FROM policy_keys WHERE active = 1 LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    data = decrypt_dict(row["secret"])
    secret_b64 = data["secret"]
    return row["key_id"], base64.b64decode(secret_b64.encode("utf-8"))

def get_policy_key_secret(key_id: str) -> Optional[bytes]:
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT secret FROM policy_keys WHERE key_id = ?", (key_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    data = decrypt_dict(row["secret"])
    secret_b64 = data["secret"]
    return base64.b64decode(secret_b64.encode("utf-8"))