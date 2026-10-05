"""
Controlled Educational Code Samples for Secure Coding Review Tool
CodeAlpha Security Audit Task 3
"""

SAMPLE_VULNERABLE_1 = '''"""
Educational Sample: Vulnerable Python Script
Demonstrating common application security weaknesses (CWEs).
"""
import os
import hashlib
import random
import subprocess

# 1. Hard-coded secret key (CWE-798)
API_SECRET = "super_secret_hardcoded_api_key_12345"
app_password = "AdminSuperSecretPass123!"

def process_data(user_query, user_filename, untrusted_code):
    # 2. Unsafe eval (CWE-95)
    result = eval(untrusted_code)

    # 3. SQL Injection string construction (CWE-89)
    sql_query = f"SELECT * FROM users WHERE username = '{user_query}'"

    # 4. Unsafe Subprocess with shell=True (CWE-78)
    cmd = "cat " + user_filename
    subprocess.run(cmd, shell=True)

    # 5. Weak Hashing with MD5 (CWE-327)
    password_hash = hashlib.md5(app_password.encode()).hexdigest()

    # 6. Insecure Randomness (CWE-330)
    session_token = str(random.randint(100000, 999999))

    # 7. Unsafe File / Path Handling (CWE-22)
    with open("/tmp/uploads/" + user_filename, "r") as f:
        file_data = f.read()

    # 8. Broad Exception Handling (CWE-396)
    try:
        critical_operation()
    except Exception:
        pass

    return result, sql_query, password_hash, session_token

def main():
    print("Running vulnerable script sample...")

if __name__ == "__main__":
    # 9. Debug mode enabled (CWE-215)
    debug = True
'''

SAMPLE_SECURE_1 = '''"""
Educational Sample: Remediated Secure Python Script
Demonstrating secure coding best practices addressing all CWEs.
"""
import os
import ast
import sqlite3
import secrets
import logging
import subprocess
from werkzeug.security import generate_password_hash

# 1. Environment Variable Secrets Management (Remediation CWE-798)
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
API_SECRET = os.environ.get("API_SECRET", secrets.token_hex(32))

def process_data(user_query, user_filename, untrusted_code):
    # 2. Safe Literal Parsing instead of eval (Remediation CWE-95)
    try:
        result = ast.literal_eval(untrusted_code)
    except (ValueError, SyntaxError) as err:
        logging.warning(f"Invalid input literal: {err}")
        result = None

    # 3. Parameterized SQL Queries (Remediation CWE-89)
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_query,))

    # 4. Safe Subprocess without Shell (Remediation CWE-78)
    safe_filename = os.path.basename(user_filename)
    subprocess.run(["cat", safe_filename], shell=False, check=True)

    # 5. Strong Password Hashing with PBKDF2/SHA256 (Remediation CWE-327)
    password_hash = generate_password_hash("UserPassword123!", method="pbkdf2:sha256")

    # 6. Cryptographically Secure Token Generation (Remediation CWE-330)
    session_token = secrets.token_hex(32)

    # 7. Safe Path Sanitization & Canonical Path Checks (Remediation CWE-22)
    safe_name = os.path.basename(user_filename)
    safe_path = os.path.abspath(os.path.join("/tmp/uploads", safe_name))
    if safe_path.startswith("/tmp/uploads/"):
        with open(safe_path, "r", encoding="utf-8") as f:
            file_data = f.read()

    # 8. Specific Exception Handling & Logging (Remediation CWE-396)
    try:
        critical_operation()
    except FileNotFoundError as fnf_err:
        logging.error(f"File missing: {fnf_err}")
    except ValueError as val_err:
        logging.error(f"Validation error: {val_err}")

    return result, password_hash, session_token

if __name__ == "__main__":
    # 9. Debug mode disabled in production (Remediation CWE-215)
    debug = False
'''

EDUCATIONAL_SAMPLES = {
    "vulnerable_1": {
        "name": "Controlled Educational Sample: Vulnerable Python Script",
        "description": "Intentionally vulnerable script containing Hard-coded Secrets, eval(), SQLi, shell=True, MD5, and Debug Mode.",
        "code": SAMPLE_VULNERABLE_1
    },
    "secure_1": {
        "name": "Controlled Educational Sample: Remediated Secure Script",
        "description": "Secure remediated counterpart utilizing Environment Variables, Parameterized Queries, PBKDF2, and secrets module.",
        "code": SAMPLE_SECURE_1
    }
}
