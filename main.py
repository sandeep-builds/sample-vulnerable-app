# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import logging

logger = logging.getLogger(__name__)

# Use environment variable instead of hardcoded token (CWE-200 fix)
API_TOKEN = os.environ.get("API_TOKEN", "")

# simple SQLite DB on local disk
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed: Use parameterized queries to prevent SQL injection (CWE-89)
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed: Use parameterized queries to prevent SQL injection (CWE-89)
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # insecure deserialization of untrusted data
    return pickle.loads(blob)

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Fixed: Use logger instead of print to avoid sensitive information leak (CWE-200)
    logger.info("Application started with configured API token")
    print(get_user("alice"))
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        logger.error("Deserialization error: %s", e)
