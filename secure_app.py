"""
SecureVault - Remediated Secure Application Version
CodeAlpha Security Audit Task 3: Secure Coding Review

This module implements secure coding best practices fixing all identified
vulnerabilities from vulnerable_app.py.
"""

import os
import re
import secrets
import sqlite3
import logging
from datetime import timedelta
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, render_template, redirect, url_for, session, flash

# Configure Server-side Logging for security events & internal errors
logging.basicConfig(
    filename='secure_app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

app = Flask(__name__)

# REMEDIATION 1: Environment Variable for Secrets & Cryptographic Random Fallback
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
app.config['STRIPE_API_KEY'] = STRIPE_API_KEY

# REMEDIATION 2: Secure Session Cookie Configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,  # Set to True in production HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

DB_FILE = "secure_securevault.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database with secure schema and hashed seed data."""
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
    
    # Seed default users using SECURE PBKDF2/SHA256 Password Hashing
    # REMEDIATION 3: Strong Password Hashing with Werkzeug
    admin_pass = generate_password_hash("admin123", method="scrypt" if hasattr(generate_password_hash, "__doc__") else "pbkdf2:sha256")
    alice_pass = generate_password_hash("password123", method="scrypt" if hasattr(generate_password_hash, "__doc__") else "pbkdf2:sha256")
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            ("admin", admin_pass, "admin@securevault.local", "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            ("alice", alice_pass, "alice@securevault.local", "user")
        )
        cursor.execute(
            "INSERT INTO user_notes (username, title, content) VALUES (?, ?, ?)",
            ("admin", "System Security Policy", "Encrypted Vault initialized with PBKDF2/SHA256 Hashing and Parameterized Queries.")
        )
        cursor.execute(
            "INSERT INTO user_notes (username, title, content) VALUES (?, ?, ?)",
            ("alice", "Compliance Checklist", "Security Audit complete. All findings verified and remediated.")
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


@app.context_processor
def inject_app_mode():
    """Pass application mode metadata to templates."""
    return {
        'app_mode': 'SECURE',
        'app_port': 5001,
        'other_port': 5000,
        'other_mode_label': 'Vulnerable Version'
    }


def validate_username(username):
    """Validate username format (alphanumeric and underscores, 3-30 chars)."""
    return bool(re.match(r'^[a-zA-Z0-9_]{3,30}$', username))


def validate_email(email):
    """Validate basic email format."""
    return bool(re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email))


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # REMEDIATION 4: Input Validation
        if not username or not password:
            error = "Please provide both username and password."
            return render_template('login.html', error=error)
            
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # REMEDIATION 5: Parameterized Query (Prevents SQL Injection CWE-89)
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()
            
            # REMEDIATION 3: Constant-time Hash Verification with Werkzeug
            if user and check_password_hash(user['password'], password):
                session.clear()  # Prevent Session Fixation
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = True
                
                logging.info(f"Successful login for user: {username}")
                flash("Login successful! Secure session established.", "success")
                return redirect(url_for('dashboard'))
            else:
                logging.warning(f"Failed login attempt for username: {username}")
                # REMEDIATION 6: Safe Generic Error Message (Prevents User Enumeration CWE-209)
                error = "Invalid username or password credentials."
        except Exception as ex:
            logging.error(f"Internal Login Error: {str(ex)}")
            # REMEDIATION 6: Safe Generic Error Message
            error = "An internal authentication error occurred. Please try again later."
            
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        
        # REMEDIATION 4: Strict Input Validation & Length Checks
        if not validate_username(username):
            error = "Username must be 3-30 characters long and contain only letters, numbers, and underscores."
            return render_template('register.html', error=error)
            
        if not validate_email(email):
            error = "Please enter a valid email address."
            return render_template('register.html', error=error)
            
        if len(password) < 8:
            error = "Password must be at least 8 characters long."
            return render_template('register.html', error=error)
            
        # REMEDIATION 3: Strong PBKDF2/SHA256 Hashing
        hashed_password = generate_password_hash(password)
        
        try:
            conn = get_db()
            cursor = conn.cursor()
            
            # REMEDIATION 5: Parameterized Query
            cursor.execute(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                (username, hashed_password, email, 'user')
            )
            conn.commit()
            conn.close()
            
            logging.info(f"New user registered: {username}")
            flash("Registration successful! Please log in with your credentials.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username already registered. Please choose another."
        except Exception as ex:
            logging.error(f"Registration DB Error: {str(ex)}")
            error = "An internal error occurred during registration. Please try again."
            
    return render_template('register.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Authentication required. Please log in.", "warning")
        return redirect(url_for('login'))
        
    username = session['username']
    search_query = request.args.get('search', '').strip()
    
    conn = get_db()
    cursor = conn.cursor()
    
    # REMEDIATION 5: Parameterized Query for search filter
    if search_query:
        query = "SELECT * FROM user_notes WHERE username = ? AND (title LIKE ? OR content LIKE ?)"
        pattern = f"%{search_query}%"
        cursor.execute(query, (username, pattern, pattern))
    else:
        query = "SELECT * FROM user_notes WHERE username = ?"
        cursor.execute(query, (username,))
        
    notes = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', username=username, role=session.get('role', 'user'), notes=notes, search_query=search_query)


@app.route('/add_note', methods=['POST'])
def add_note():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    username = session['username']
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    
    if not title or not content:
        flash("Note title and content cannot be empty.", "warning")
        return redirect(url_for('dashboard'))
        
    # REMEDIATION 7: Input HTML Escaping & Sanitization (Prevents XSS CWE-79)
    safe_title = str(escape(title))
    safe_content = str(escape(content))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # REMEDIATION 5: Parameterized Query
    try:
        cursor.execute(
            "INSERT INTO user_notes (username, title, content) VALUES (?, ?, ?)",
            (username, safe_title, safe_content)
        )
        conn.commit()
        flash("Vault note securely stored.", "success")
    except Exception as ex:
        logging.error(f"Note Addition Error: {str(ex)}")
        flash("Failed to store note due to an internal error.", "danger")
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
    flash("Secure session ended successfully.", "info")
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    print("=============================================================")
    print(" [SECURE] RUNNING REMEDIATED SECURE APP VERSION")
    print(" [SECURE] URL: http://127.0.0.1:5001")
    print(" [SECURE] SECURITY CONTROLS: Parameterized SQL, PBKDF2/SHA256, XSS Sanitize")
    print("=============================================================")
    # REMEDIATION 8: Flask Debug Mode Disabled (CWE-215 / Bandit B201)
    app.run(debug=False, port=5001, host="127.0.0.1")

