"""
Unit tests for Python Static Security Analysis Engine
CodeAlpha Security Audit Task 3: Secure Coding Review
"""

import unittest
from analyzer import StaticAnalyzer

class TestStaticAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = StaticAnalyzer()

    def test_hardcoded_secret_detection(self):
        code = '''
app_secret = "super_secret_api_key_12345"
hardcoded_key = "super_secret_stripe_api_key_99999"
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Secret" in cat for cat in categories))

    def test_unsafe_eval_detection(self):
        code = '''
user_input = "__import__('os').system('dir')"
eval(user_input)
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        severities = [f["severity"] for f in result["findings"]]
        self.assertIn("Unsafe Dynamic Code Execution (eval/exec)", categories)
        self.assertIn("CRITICAL", severities)

    def test_unsafe_subprocess_detection(self):
        code = '''
import subprocess
cmd = "ls -la " + user_arg
subprocess.run(cmd, shell=True)
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Subprocess" in cat or "Shell" in cat for cat in categories))

    def test_sql_injection_detection(self):
        code = '''
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("SQL" in cat for cat in categories))

    def test_debug_mode_detection(self):
        code = '''
from flask import Flask
app = Flask(__name__)
app.run(debug=True, port=5000)
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Debug" in cat for cat in categories))

    def test_weak_hashing_detection(self):
        code = '''
import hashlib
pwd_hash = hashlib.md5("password".encode()).hexdigest()
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Hashing" in cat or "Weak" in cat for cat in categories))

    def test_insecure_randomness_detection(self):
        code = '''
import random
token = random.randint(1000, 9999)
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Random" in cat for cat in categories))

    def test_unsafe_path_handling_detection(self):
        code = '''
user_file = request.args.get("file")
with open("/var/data/" + user_file, "r") as f:
    content = f.read()
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Path" in cat or "File" in cat for cat in categories))

    def test_broad_exception_handling_detection(self):
        code = '''
try:
    do_something()
except Exception as e:
    pass
'''
        result = self.analyzer.analyze_code(code)
        categories = [f["category"] for f in result["findings"]]
        self.assertTrue(any("Exception" in cat for cat in categories))

    def test_clean_secure_code_produces_no_critical_or_high_findings(self):
        code = '''
import os
import secrets
import sqlite3
import subprocess
from werkzeug.security import generate_password_hash

secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
hashed = generate_password_hash("secure_password_123")

conn = sqlite3.connect("test.db")
cursor = conn.cursor()
cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
subprocess.run(["ls", "-l"], shell=False)
'''
        result = self.analyzer.analyze_code(code)
        high_critical = [f for f in result["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(len(high_critical), 0)

if __name__ == '__main__':
    unittest.main()
