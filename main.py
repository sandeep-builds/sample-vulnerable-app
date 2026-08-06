# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
# Security fixes applied: parameterized queries, removed hardcoded secrets, restricted deserialization
import sqlite3
import subprocess
import pickle
import os
import logging

logger = logging.getLogger(__name__)

# CWE-798 fix: Read API token from environment variable instead of hardcoding
API_TOKEN = os.environ.get("API_TOKEN", "")

# simple SQLite DB on local disk
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # CWE-89 fix: Use parameterized queries instead of string formatting
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # CWE-89 fix: Use parameterized queries instead of string formatting
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # CWE-78 fix: Use subprocess with shell=False and argument list
    import shlex
    args = shlex.split(command)
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return result.stdout

def deserialize_blob(blob):
    # CWE-502 fix: Use restricted unpickler or validate before deserializing
    # In production, prefer JSON or other safe formats
    import io
    class RestrictedUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            raise pickle.UnpicklingError(f"Restricted: {module}.{name}")
    return RestrictedUnpickler(io.BytesIO(blob)).load()

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # CWE-200 fix: Log token presence as boolean, never expose the value
    logger.info("API_TOKEN configured: %s", bool(API_TOKEN))
    print(get_user("alice"))
    print(run_shell("echo Hello"))
    try:
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)
