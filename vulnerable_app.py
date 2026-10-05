"""
SecureVault - Vulnerable Application Version
CodeAlpha Security Audit Task 3: Secure Coding Review

WARNING: This module contains INTENTIONALLY VULNERABLE code for educational
and security auditing purposes only. Do not use this in production.
"""

import sqlite3
import hashlib
from flask import Flask, request, render_template, redirect, url_for, session, flash

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret Key (CWE-798 / Bandit B105)
app.secret_key = "super_secret_hardcoded_key_12345_do_not_share"

DB_FILE = "vulnerable_securevault.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database with vulnerable schema and seed data."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    
    # Create User Notes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Seed default user if not exists using WEAK MD5 hashing
    # VULNERABILITY 2: Weak Cryptographic Hashing (MD5) (CWE-327 / Bandit B303, B324)
    default_pass = hashlib.md5("admin123".encode()).hexdigest()
    try:
        cursor.execute(f"INSERT INTO users (username, password, email, role) VALUES ('admin', '{default_pass}', 'admin@securevault.local', 'admin')")
        cursor.execute(f"INSERT INTO users (username, password, email, role) VALUES ('alice', '{hashlib.md5('password123'.encode()).hexdigest()}', 'alice@securevault.local', 'user')")
        cursor.execute("INSERT INTO user_notes (username, title, content) VALUES ('admin', 'System Master Key Backup', 'Vault Master Passcode: SV-99482-SEC')")
        cursor.execute("INSERT INTO user_notes (username, title, content) VALUES ('alice', 'Personal Notes', 'Remember to audit API keys before release.')")
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


@app.context_processor
def inject_app_mode():
    """Pass application mode metadata to templates."""
    return {
        'app_mode': 'VULNERABLE',
        'app_port': 5000,
        'other_port': 5001,
        'other_mode_label': 'Remediated Secure Version'
    }


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABILITY 2: Weak Password Digest Calculation (MD5 without Salt)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # VULNERABILITY 3: Unsafe SQL Query Construction (SQL Injection) (CWE-89 / Bandit B608)
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
            print(f"[VULNERABLE LOG] Executing Query: {query}")
            
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                session['username'] = user['username']
                session['role'] = user['role']
                flash("Login successful! Welcome back.", "success")
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username or password credentials."
        except Exception as e:
            # VULNERABILITY 4: Information Disclosure via Raw Exception Messages (CWE-209)
            error = f"Database Exception Caught: {str(e)} | Query: {query}"
            
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        # VULNERABILITY 5: Missing Input Validation & Format Sanitization (CWE-20)
        # Accepts empty strings, SQL characters, control characters, scripts without validation
        
        # Weak MD5 hash
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # VULNERABILITY 3: Unsafe SQL Query Construction (SQL Injection)
            query = f"INSERT INTO users (username, password, email, role) VALUES ('{username}', '{hashed_password}', '{email}', 'user')"
            print(f"[VULNERABLE LOG] Executing Registration: {query}")
            
            cursor.execute(query)
            conn.commit()
            conn.close()
            
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            # VULNERABILITY 4: Information Disclosure
            error = f"Registration Error Detail: {str(e)}"
            
    return render_template('register.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Authentication required. Please log in.", "warning")
        return redirect(url_for('login'))
        
    username = session['username']
    search_query = request.args.get('search', '')
    
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABILITY 3: SQL Injection in Search filter
    if search_query:
        query = f"SELECT * FROM user_notes WHERE username = '{username}' AND (title LIKE '%{search_query}%' OR content LIKE '%{search_query}%')"
    else:
        query = f"SELECT * FROM user_notes WHERE username = '{username}'"
        
    try:
        cursor.execute(query)
        notes = cursor.fetchall()
    except Exception as e:
        notes = []
        flash(f"SQL Execution Error: {str(e)}", "danger")
    finally:
        conn.close()
        
    return render_template('dashboard.html', username=username, role=session.get('role', 'user'), notes=notes, search_query=search_query)


@app.route('/add_note', methods=['POST'])
def add_note():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    username = session['username']
    title = request.form.get('title', '')
    content = request.form.get('content', '')
    
    # VULNERABILITY 6: Stored XSS / Unescaped Input Storage (CWE-79)
    # Content is stored raw into database without HTML escaping or sanitization
    
    conn = get_db()
    cursor = conn.cursor()
    query = f"INSERT INTO user_notes (username, title, content) VALUES ('{username}', '{title}', '{content}')"
    try:
        cursor.execute(query)
        conn.commit()
        flash("Vault note added successfully.", "success")
    except Exception as e:
        flash(f"Failed to add note: {str(e)}", "danger")
    finally:
        conn.close()
        
    return redirect(url_for('dashboard'))


@app.route('/audit')
def audit():
    return render_template('audit.html')


@app.route('/findings')
def findings():
    return render_template('findings.html')


@app.route('/recommendations')
def recommendations():
    return render_template('recommendations.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    print("=============================================================")
    print(" [!] RUNNING VULNERABLE APP VERSION (FOR SECURITY AUDIT)")
    print(" [!] URL: http://127.0.0.1:5000")
    print(" [!] VULNERABILITIES ACTIVE: Hardcoded Keys, Weak MD5, SQLi, Debug Mode")
    print("=============================================================")
    # VULNERABILITY 7: Flask Debug Mode Enabled in Production (CWE-215 / Bandit B201)
    app.run(debug=True, port=5000, host="0.0.0.0")
