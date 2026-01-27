# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # FIX: Import ast for safe literal evaluation
import hashlib

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# Hardcoded AWS Secret (Issue 5 - NEW)
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Insecure hashing using MD5 (Issue 6 - NEW)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    
    # SQL injection vulnerability via string formatting (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, hashed_password)
    cur.execute(sql)
    conn.commit()

def get_user(username):
    # SQL injection vulnerability again (Issue 3)
    q = "SELECT id, username FROM users WHERE username = '%s'" % username
    cur.execute(q)
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def read_user_file(filename):
    # Path traversal vulnerability (Issue 7 - NEW)
    # Allows reading arbitrary files like /etc/passwd if unsanitized
    base_path = "/var/www/uploads/"
    full_path = os.path.join(base_path, filename)
    with open(full_path, 'r') as f:
        return f.read()

def deserialize_blob(blob):
    # FIX: Replaced insecure pickle.loads() with safe ast.literal_eval()
    # This prevents arbitrary code execution from untrusted input
    # Only safe Python literals (strings, numbers, tuples, lists, dicts, booleans, None) can be evaluated
    try:
        return ast.literal_eval(blob.decode('utf-8') if isinstance(blob, bytes) else blob)
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Invalid input: cannot safely deserialize data - {e}")

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)
