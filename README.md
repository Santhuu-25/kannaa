# Secure Coding Review & Vulnerability Analysis Tool

**CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review**

An interactive, educational Python-based Secure Coding Review and Application Security Analysis application built to perform static code security reviews (SAST), analyze source code for common security weaknesses (CWEs), display transparent rule-based findings with line numbers and remediations, integrate Bandit AST scanning, and generate downloadable audit reports.

---

## 🎯 Purpose & Scope

The **Secure Coding Review & Vulnerability Analysis Tool** allows software developers, security analysts, and auditors to submit Python source code (via text input, file upload, or controlled educational samples) and receive structured security findings, line-by-line code snippets, severity ratings, security impact analysis, recommended remediations, and verification advice.

> **Safety Notice:** The application parses Python source code into Abstract Syntax Trees (AST) and token structures out-of-band. Submitted source code is **never executed or evaluated**.

---

## ✨ Features

- **Code Input Options:**
  - Interactive Python source code paste editor
  - Direct `.py` file upload validation (type & size limits)
  - Built-in controlled educational samples (Vulnerable & Remediated)
  - Pre-loaded target codebases (`vulnerable_app.py` & `secure_app.py`)

- **Rule-Based Python AST Static Analysis Engine:**
  - Hard-coded Secrets & API Keys (`CWE-798`)
  - Unsafe `eval()` / `exec()` Dynamic Code Execution (`CWE-95`)
  - Unsafe `subprocess` with `shell=True` / Command Injection (`CWE-78`)
  - SQL Injection String Construction (`CWE-89`)
  - Flask Debug Mode Enabled in Production (`CWE-215`)
  - Weak Password Hashing MD5 / SHA-1 (`CWE-327`)
  - Insecure Pseudo-Randomness (`CWE-330`)
  - Path Traversal & Unsafe File Open Handling (`CWE-22`)
  - Broad Exception Handling Swallowing Errors (`CWE-396`)

- **Bandit AST Scanner Integration:**
  - Automatically runs `bandit` AST security scanner if available in environment.
  - Parses JSON output and presents Bandit findings alongside built-in rules.
  - Gracefully falls back to built-in AST static analysis if Bandit is unavailable.

- **Severity Classification & Transparent Metrics:**
  - Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
  - Metrics Dashboard with interactive severity filters (`All`, `Critical`, `High`, `Medium`, `Low`, `Info`)

- **Side-by-Side Code Comparison:**
  - Visual side-by-side comparison of **Vulnerable Code** vs **Remediated Secure Code** with explanations of why the remediated code is safer.

- **Security Review Report Generation:**
  - Generate comprehensive audit reports including metrics, finding breakdowns, remediation steps, verification guidance, and limitations.
  - Export and download reports in **Markdown (.md)** or **JSON (.json)** formats.

- **Persistent Security Notes Manager:**
  - Local database-backed note storage pre-populated with audit disclosure statements.
  - HTML-escaped output preventing XSS.

- **Modern UI & Theme Customization:**
  - Clean light mode background by default with optional Dark Mode toggle.
  - Responsive blue/indigo security dashboard layout.

---

## 🏗️ Architecture & How Analysis Works

```
                        +----------------------------------+
                        |      User Python Source Code     |
                        +----------------------------------+
                                         |
                                         v
                         +--------------------------------+
                         |   Flask Web Application App    |
                         +--------------------------------+
                                         |
                       +-----------------------------------+
                       |    StaticAnalyzer Engine          |
                       +-----------------------------------+
                       /                                   \
                      /                                     \
    +----------------------------------+   +----------------------------------+
    |   Python AST Security Visitor    |   |     Bandit Subprocess Runner     |
    |   - ast.parse()                  |   |     - bandit -f json           |
    |   - ast.NodeVisitor checks       |   |     - Safe temp file scan      |
    +----------------------------------+   +----------------------------------+
                      \                                     /
                       \                                   /
                         +--------------------------------+
                         |  Normalized Findings & Metrics |
                         +--------------------------------+
                                         |
                     +----------------------------------------+
                     | UI Dashboard / Report Generator (.MD)  |
                     +----------------------------------------+
```

1. **AST Parsing:** Python source code is parsed into Abstract Syntax Trees using Python's standard `ast` module.
2. **Node Traversal:** Custom `ast.NodeVisitor` classes inspect function calls (`eval`, `subprocess.run`, `open`), assignments (`secret_key`, `debug`), and exception handlers (`except Exception:`).
3. **Regex Pattern Matching:** Complements AST parsing to detect high-entropy credential strings and specific API keys (e.g. Stripe `sk_live_`, Google `AIzaSy`).
4. **Result Aggregation:** Normalizes finding IDs, severities, line numbers, snippets, explanations, remediations, and verification advice.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+ (Python 3.14 compatible)
- `pip` or `py -m pip`

### Step 1: Clone or Navigate to Project Directory
```bash
cd c:/Users/LENOVO/OneDrive/Desktop/task2/CodeAlpha_Task3_Secure_Coding_Review
```

### Step 2: Install Dependencies
```bash
py -m pip install -r requirements.txt
```
*(Dependencies: Flask, Werkzeug, Bandit, python-dotenv)*

---

## ⚙️ Running the Application

To start the Secure Coding Review Web Application, run:

```bash
py app.py
```

Output:
```
=============================================================
 [🛡️] RUNNING CODESHIELD SECURE CODING REVIEW & ANALYSIS APP
 [🛡️] URL: http://127.0.0.1:5000
 [🛡️] ENGINE: AST Static Analyzer & Bandit AST Scanner
=============================================================
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 🧪 Running Unit & Integration Tests

The project includes 22 automated unit and integration tests covering all static analysis rules and Web application routes without executing submitted code.

To run the static analyzer test suite:
```bash
py -m unittest test_analyzer.py
```

To run the Web application route integration test suite:
```bash
py -m unittest test_app_routes.py
```

To run all tests together:
```bash
py -m unittest discover -p "test_*.py"
```

---

## 📝 Example Findings & Remediation Methodology

| Finding ID | Category | Severity | Vulnerable Snippet Example | Recommended Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-EVAL-001** | Dynamic Code Execution | `CRITICAL` | `eval(user_input)` | Use `ast.literal_eval(user_input)` for literal strings. |
| **SEC-SQLI-001** | SQL Injection | `HIGH` | `f"SELECT * FROM u WHERE id='{id}'"` | Use parameterized query: `cursor.execute("SELECT * FROM u WHERE id=?", (id,))`. |
| **SEC-SECRET-001** | Hard-coded Secret | `HIGH` | `STRIPE_API_KEY = "your_stripe_secret_key_here"` | Store in environment variables: `os.getenv("STRIPE_API_KEY")`. |
| **SEC-SHELL-001** | Subprocess Command Injection | `HIGH` | `subprocess.run(cmd, shell=True)` | Pass list arguments with `shell=False`: `subprocess.run(["cmd", arg])`. |
| **SEC-HASH-001** | Weak Password Hashing | `HIGH` | `hashlib.md5(password).hexdigest()` | Use key-stretching hashes: `generate_password_hash(password)`. |
| **SEC-DEBUG-001** | Debug Mode Enabled | `MEDIUM` | `app.run(debug=True)` | Set `debug=False` in production. |

---

## 📄 Report Generation

Click **"Generate Report"** in the navigation bar to preview or download the Security Review Report in **Markdown (.md)** or **JSON (.json)** formats.

The report includes:
- Project Name & Timestamp
- Lines of Code Analyzed & File Stats
- Executive Summary Metrics Table
- Detailed Vulnerability Catalog with Line Numbers & Code Snippets
- Remediation Guidance & Verification Steps
- Tool/Methodology Statement & Security Limitations

---

## ⚠️ Security Limitations

1. **Static Analysis Boundaries:** Static code analysis identifies security weaknesses based on code structure and patterns. Findings are clearly labeled as *"Potential vulnerability / security issue detected by static analysis."*
2. **False Positives/Negatives:** Static analysis cannot prove exploitability or analyze complex runtime environment variables without manual inspection.
3. **No Execution Guarantee:** This tool does not execute user code, ensuring safe audit operations.

---

## ⚖️ Ethical & Educational Use Statement

This application was developed as part of **CodeAlpha Task 3 — Secure Coding Review**. It is intended strictly for defensive educational purposes, developer secure-coding reviews, and application security auditing coursework.
