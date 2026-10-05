"""
CodeShield - Secure Coding Review & Application Security Analysis Tool
CodeAlpha Security Audit Task 3

Primary Application Entrypoint
"""

import os
import re
import uuid
import sqlite3
import logging
from datetime import datetime
from markupsafe import escape
from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, jsonify, Response
)

from analyzer import StaticAnalyzer
from report_generator import ReportGenerator
from sample_codes import EDUCATIONAL_SAMPLES, SAMPLE_VULNERABLE_1, SAMPLE_SECURE_1

# Configure Server-side Logging
logging.basicConfig(
    filename='app_security_audit.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB upload limit

# Load environment variables from .env if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Safely read Stripe API key from environment variable
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
app.config['STRIPE_API_KEY'] = STRIPE_API_KEY

DB_FILE = "secure_securevault.db"

# In-memory scan cache to avoid Flask 4KB cookie session size limits
SCAN_CACHE = {}


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes local database for storing security review notes safely."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("SELECT COUNT(*) as cnt FROM security_notes")
    if cursor.fetchone()['cnt'] == 0:
        cursor.execute(
            "INSERT INTO security_notes (title, content) VALUES (?, ?)",
            (
                "Security Review Notes",
                "Security review performed using static analysis and manual inspection techniques. Findings are potential security issues and should be manually verified before production deployment."
            )
        )
    conn.commit()
    conn.close()


def _get_current_scan():
    scan_id = session.get('scan_id')
    if scan_id and scan_id in SCAN_CACHE:
        return SCAN_CACHE[scan_id]
    return {}


@app.context_processor
def inject_global_data():
    """Provides common session scan results to all templates."""
    current_scan = _get_current_scan()
    results = current_scan.get('scan_results', {})
    metrics = results.get('metrics', {
        'total_findings': 0, 'critical_count': 0, 'high_count': 0,
        'medium_count': 0, 'low_count': 0, 'info_count': 0, 'lines_analyzed': 0
    })
    return {
        'metrics': metrics,
        'findings': results.get('findings', []),
        'bandit': results.get('bandit', {}),
        'bandit_status': results.get('bandit', {}).get('status', 'Built-in static analysis active.')
    }


@app.route('/')
def index():
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_notes ORDER BY id DESC")
    notes = cursor.fetchall()
    conn.close()
    return render_template('dashboard.html', active_page='dashboard', notes=notes)


@app.route('/code_review')
def code_review():
    current_scan = _get_current_scan()
    current_code = current_scan.get('source_code', SAMPLE_VULNERABLE_1)
    return render_template('code_review.html', active_page='review', current_code=current_code)


@app.route('/analyze', methods=['POST'])
def analyze():
    source_code = ""
    filename = "submitted_code.py"

    # 1. Check if loading pre-set educational sample
    sample_key = request.form.get('sample_key', '').strip()
    if sample_key:
        if sample_key in EDUCATIONAL_SAMPLES:
            source_code = EDUCATIONAL_SAMPLES[sample_key]['code']
            filename = f"{sample_key}.py"
        elif sample_key == "vulnerable_app" and os.path.exists("vulnerable_app.py"):
            with open("vulnerable_app.py", "r", encoding="utf-8") as f:
                source_code = f.read()
            filename = "vulnerable_app.py"
        elif sample_key == "secure_app" and os.path.exists("secure_app.py"):
            with open("secure_app.py", "r", encoding="utf-8") as f:
                source_code = f.read()
            filename = "secure_app.py"

    # 2. Check for uploaded file
    if not source_code and 'code_file' in request.files:
        file = request.files['code_file']
        if file and file.filename != '':
            if not file.filename.endswith('.py'):
                flash("Security Error: Only Python (.py) source files are allowed for analysis.", "danger")
                return redirect(url_for('code_review'))
            filename = file.filename
            source_code = file.read().decode('utf-8', errors='replace')

    # 3. Check for pasted text
    if not source_code:
        source_code = request.form.get('source_code', '').strip()

    if not source_code:
        flash("Please paste Python source code or upload a valid .py file to run security review.", "warning")
        return redirect(url_for('code_review'))

    # Perform Static Security Analysis (AST + Rules + Bandit)
    analyzer = StaticAnalyzer()
    scan_results = analyzer.analyze_code(source_code, filename=filename)

    # Store in SCAN_CACHE using UUID in session
    scan_id = str(uuid.uuid4())
    SCAN_CACHE[scan_id] = {
        'source_code': source_code,
        'filename': filename,
        'scan_results': scan_results
    }
    session['scan_id'] = scan_id

    flash(f"Analysis Complete! Identified {scan_results['metrics']['total_findings']} potential security findings in {filename}.", "success")
    return redirect(url_for('findings'))


@app.route('/findings')
def findings():
    return render_template('findings.html', active_page='findings')


@app.route('/comparison')
def comparison():
    return render_template('comparison.html', active_page='comparison')


@app.route('/recommendations')
def recommendations():
    return render_template('recommendations.html', active_page='recommendations')


@app.route('/reports')
def reports():
    current_scan = _get_current_scan()
    last_results = current_scan.get('scan_results', {})
    if not last_results:
        analyzer = StaticAnalyzer()
        last_results = analyzer.analyze_code(SAMPLE_VULNERABLE_1, filename="vulnerable_sample_1.py")
        scan_id = str(uuid.uuid4())
        SCAN_CACHE[scan_id] = {
            'source_code': SAMPLE_VULNERABLE_1,
            'filename': 'vulnerable_sample_1.py',
            'scan_results': last_results
        }
        session['scan_id'] = scan_id

    report_markdown = ReportGenerator.generate_markdown(last_results)
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return render_template('reports.html', active_page='reports', report_markdown=report_markdown, report_time=report_time)


@app.route('/download_report')
def download_report():
    fmt = request.args.get('format', 'md').lower()
    current_scan = _get_current_scan()
    last_results = current_scan.get('scan_results', {})
    if not last_results:
        analyzer = StaticAnalyzer()
        last_results = analyzer.analyze_code(SAMPLE_VULNERABLE_1, filename="vulnerable_sample_1.py")

    filename = f"security_review_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if fmt == 'json':
        content = ReportGenerator.generate_json(last_results)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-disposition": f"attachment; filename={filename}.json"}
        )
    else:
        content = ReportGenerator.generate_markdown(last_results)
        return Response(
            content,
            mimetype="text/markdown",
            headers={"Content-disposition": f"attachment; filename={filename}.md"}
        )


@app.route('/notes')
def notes():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_notes ORDER BY id DESC")
    all_notes = cursor.fetchall()
    conn.close()
    return render_template('notes.html', active_page='notes', notes=all_notes)


@app.route('/add_secure_note', methods=['POST'])
def add_secure_note():
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()

    if not title or not content:
        flash("Note title and content cannot be empty.", "warning")
        return redirect(url_for('notes'))

    safe_title = str(escape(title))
    safe_content = str(escape(content))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO security_notes (title, content) VALUES (?, ?)", (safe_title, safe_content))
    conn.commit()
    conn.close()

    flash("Security Note saved successfully.", "success")
    return redirect(url_for('notes'))


@app.route('/about')
def about():
    return render_template('about.html', active_page='about')


@app.route('/api/sample')
def api_sample():
    key = request.args.get('key', 'vulnerable_1')
    if key == "vulnerable_app" and os.path.exists("vulnerable_app.py"):
        with open("vulnerable_app.py", "r", encoding="utf-8") as f:
            return jsonify({"code": f.read()})
    elif key == "secure_app" and os.path.exists("secure_app.py"):
        with open("secure_app.py", "r", encoding="utf-8") as f:
            return jsonify({"code": f.read()})
    elif key in EDUCATIONAL_SAMPLES:
        return jsonify({"code": EDUCATIONAL_SAMPLES[key]['code']})
    return jsonify({"code": SAMPLE_VULNERABLE_1})


if __name__ == '__main__':
    init_db()
    print("=============================================================")
    print(" [SECURE] RUNNING CODESHIELD SECURE CODING REVIEW APP")
    print(" [SECURE] URL: http://127.0.0.1:5000")
    print(" [SECURE] ENGINE: AST Static Analyzer & Bandit AST Scanner")
    print("=============================================================")
    app.run(debug=False, port=5000, host="127.0.0.1")
