"""
Secure Coding Review - Static Security Analysis Engine
CodeAlpha Security Audit Task 3: Secure Coding Review & Vulnerability Analysis

This module implements a rule-based AST and pattern-matching static analyzer for Python source code.
It detects security weaknesses without executing submitted code.
"""

import ast
import re
import os
import sys
import tempfile
import json
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

@dataclass
class Finding:
    finding_id: str
    category: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str      # HIGH, MEDIUM, LOW
    line_number: int
    code_snippet: str
    explanation: str
    security_impact: str
    remediation: str
    verification: str
    cwe: str = "N/A"
    rule_id: str = "CUSTOM"
    secure_example: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StaticAnalyzer:
    """Python AST and Pattern-based Static Code Security Analyzer."""

    def __init__(self):
        self.findings: List[Finding] = []
        self._finding_counter = 0

    def _next_id(self, category_code: str) -> str:
        self._finding_counter += 1
        return f"SEC-{category_code}-{self._finding_counter:03d}"

    def analyze_code(self, source_code: str, filename: str = "submitted_code.py") -> Dict[str, Any]:
        self.findings = []
        self._finding_counter = 0
        lines = source_code.splitlines()

        # 1. Parse AST
        try:
            tree = ast.parse(source_code, filename=filename)
            self._analyze_ast(tree, lines)
        except SyntaxError as se:
            self.findings.append(Finding(
                finding_id=self._next_id("SYNTAX"),
                category="Syntax Error",
                severity="INFO",
                confidence="HIGH",
                line_number=se.lineno or 1,
                code_snippet=lines[se.lineno - 1] if se.lineno and se.lineno <= len(lines) else "",
                explanation=f"Syntax error prevented full AST analysis: {se.msg}",
                security_impact="Syntactically invalid Python code cannot be executed.",
                remediation="Fix Python syntax errors before running static security analysis.",
                verification="Re-run analysis after code compiles without syntax errors."
            ))

        # 2. Regex-based pattern matching (supplements AST for comments/raw strings)
        self._analyze_regex(lines)

        # Sort findings by severity and line number
        self.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), -f.line_number), reverse=True)

        # Remove duplicate findings on the same line for the same category
        deduped = []
        seen = set()
        for f in self.findings:
            key = (f.line_number, f.category)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        self.findings = deduped

        # Calculate metrics
        metrics = {
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in self.findings if f.severity == "HIGH"),
            "medium_count": sum(1 for f in self.findings if f.severity == "MEDIUM"),
            "low_count": sum(1 for f in self.findings if f.severity == "LOW"),
            "info_count": sum(1 for f in self.findings if f.severity == "INFO"),
            "filename": filename,
            "lines_analyzed": len(lines)
        }

        # 3. Try running Bandit if available
        bandit_result = self._run_bandit(source_code)

        return {
            "metrics": metrics,
            "findings": [f.to_dict() for f in self.findings],
            "bandit": bandit_result
        }

    def _analyze_ast(self, tree: ast.AST, lines: List[str]):
        visitor = SecurityASTVisitor(self, lines)
        visitor.visit(tree)

    def _analyze_regex(self, lines: List[str]):
        secret_patterns = [
            (r'(?i)(api[_-]?key|secret|token|password|passwd|auth[_-]?key)\s*=\s*["\']([^"\'\s]{6,})["\']', "Hard-coded Secret / Credential", "HIGH", "CWE-798"),
            (r'["\']sk_live_[0-9a-zA-Z]{10,}["\']', "Hard-coded API Key (Stripe)", "CRITICAL", "CWE-798"),
            (r'["\']AIzaSy[0-9A-Za-z-_]{20,}["\']', "Hard-coded API Key (Google)", "CRITICAL", "CWE-798"),
            (r'["\']ghp_[0-9a-zA-Z]{20,}["\']', "Hard-coded Personal Access Token (GitHub)", "CRITICAL", "CWE-798"),
        ]

        for i, line in enumerate(lines, 1):
            sline = line.strip()
            if sline.startswith("#"):
                continue

            for pattern, cat, sev, cwe in secret_patterns:
                match = re.search(pattern, sline)
                if match:
                    if not any(f.line_number == i and "Secret" in f.category for f in self.findings):
                        self.findings.append(Finding(
                            finding_id=self._next_id("SEC"),
                            category=cat,
                            severity=sev,
                            confidence="HIGH",
                            line_number=i,
                            code_snippet=sline,
                            explanation=f"Hard-coded secret or credential detected in source code line {i}.",
                            security_impact="Exposing hard-coded credentials in version control allows unauthorized access, credential theft, and session hijacking.",
                            remediation="Move secrets to environment variables (`os.environ.get('SECRET_KEY')`) or use a secure secret manager.",
                            verification="Run static analyzer again and verify no plaintext secret string assignments exist.",
                            cwe=cwe,
                            rule_id="RULE-SECRET-01",
                            secure_example="import os\nsecret_key = os.environ.get('API_KEY')"
                        ))

    def _run_bandit(self, source_code: str) -> Dict[str, Any]:
        """Runs Bandit against submitted code if Bandit is installed in environment."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as tmp:
                tmp.write(source_code)
                tmp_path = tmp.name

            try:
                result = subprocess.run(
                    [sys.executable, "-m", "bandit", "-f", "json", tmp_path],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.stdout:
                    data = json.loads(result.stdout)
                    bandit_findings = []
                    for item in data.get("results", []):
                        bandit_findings.append({
                            "test_id": item.get("test_id"),
                            "test_name": item.get("test_name"),
                            "issue_text": item.get("issue_text"),
                            "issue_severity": item.get("issue_severity"),
                            "issue_confidence": item.get("issue_confidence"),
                            "line_number": item.get("line_number"),
                            "code": item.get("code", "").strip(),
                            "more_info": item.get("more_info")
                        })
                    return {
                        "available": True,
                        "status": "Bandit AST analysis complete.",
                        "count": len(bandit_findings),
                        "results": bandit_findings
                    }
            except Exception as e:
                return {
                    "available": False,
                    "status": f"Bandit execution error: {str(e)}. Built-in static analysis active.",
                    "results": []
                }
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        except Exception as ex:
            return {
                "available": False,
                "status": "Built-in static analysis active.",
                "results": []
            }
        return {
            "available": False,
            "status": "Built-in static analysis active.",
            "results": []
        }


class SecurityASTVisitor(ast.NodeVisitor):
    """AST Node Visitor for detecting Python security anti-patterns."""

    def __init__(self, analyzer: StaticAnalyzer, lines: List[str]):
        self.analyzer = analyzer
        self.lines = lines

    def _get_snippet(self, node: ast.AST) -> str:
        line_no = getattr(node, "lineno", 1)
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func_name = ""
        lineno = getattr(node, "lineno", 1)
        snippet = self._get_snippet(node)

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"

        # B. Unsafe eval() / exec()
        if func_name in ("eval", "exec"):
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("EVAL"),
                category="Unsafe Dynamic Code Execution (eval/exec)",
                severity="CRITICAL",
                confidence="HIGH",
                line_number=lineno,
                code_snippet=snippet,
                explanation=f"Use of dangerous dynamic execution function `{func_name}()` detected.",
                security_impact="If untrusted input is passed to eval() or exec(), an attacker can achieve arbitrary Remote Code Execution (RCE) on the server.",
                remediation="Avoid `eval()` or `exec()` for untrusted input. Use `ast.literal_eval()` for safe string parsing of basic Python literals.",
                verification="Run static analyzer again and confirm no raw eval() or exec() calls remain.",
                cwe="CWE-95",
                rule_id="RULE-EVAL-01",
                secure_example="import ast\ndata = ast.literal_eval(user_input_string)"
            ))

        # C. Unsafe subprocess / shell=True / os.system
        if func_name in ("os.system", "os.popen"):
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("SHELL"),
                category="Unsafe OS Command Execution",
                severity="HIGH",
                confidence="HIGH",
                line_number=lineno,
                code_snippet=snippet,
                explanation=f"Use of raw command execution `{func_name}()` passes input directly to system shell.",
                security_impact="Command Injection vulnerability (CWE-78). Attackers can append shell metacharacters (`;`, `&&`, `|`) to execute system commands.",
                remediation="Use `subprocess.run(['command', 'arg1'], shell=False)` with arguments passed as a list, avoiding system shell invocation.",
                verification="Verify that command execution uses subprocess with list arguments and shell=False.",
                cwe="CWE-78",
                rule_id="RULE-SHELL-01",
                secure_example="import subprocess\nsubprocess.run(['ls', '-l', target_dir], check=True)"
            ))

        if "subprocess" in func_name or func_name in ("Popen", "call", "run", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.analyzer.findings.append(Finding(
                        finding_id=self.analyzer._next_id("SHELL"),
                        category="Unsafe Subprocess with shell=True",
                        severity="HIGH",
                        confidence="HIGH",
                        line_number=lineno,
                        code_snippet=snippet,
                        explanation="Subprocess call uses `shell=True`, executing commands through shell interpreter.",
                        security_impact="Invoking shell=True enables shell expansion and metacharacter parsing, risking Command Injection if command arguments contain unsanitized input.",
                        remediation="Set `shell=False` (default) and pass command and arguments as a sequence of strings: `subprocess.run(['cmd', arg1, arg2])`.",
                        verification="Re-analyze code and confirm `shell=True` argument is removed.",
                        cwe="CWE-78",
                        rule_id="RULE-SHELL-02",
                        secure_example="subprocess.run(['ping', '-c', '1', hostname], shell=False)"
                    ))

        # D. SQL Injection-prone query execution directly in Call
        if func_name in ("execute", "executemany", "cursor.execute", "db.execute"):
            if node.args:
                first_arg = node.args[0]
                is_unsafe_sql = False
                reason = ""

                if isinstance(first_arg, ast.JoinedStr):
                    is_unsafe_sql = True
                    reason = "SQL query constructed using Python f-string interpolation directly inside execute()."
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    is_unsafe_sql = True
                    reason = "SQL query constructed using string concatenation or % formatting directly inside execute()."
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    is_unsafe_sql = True
                    reason = "SQL query constructed using `.format()` string method directly inside execute()."

                if is_unsafe_sql:
                    self.analyzer.findings.append(Finding(
                        finding_id=self.analyzer._next_id("SQLI"),
                        category="SQL Injection (SQLi) Vulnerability",
                        severity="HIGH",
                        confidence="HIGH",
                        line_number=lineno,
                        code_snippet=snippet,
                        explanation=f"{reason} Dynamic SQL query construction allows injection.",
                        security_impact="SQL Injection (CWE-89) allows attackers to bypass authentication, dump database tables, tamper with records, or delete data.",
                        remediation="Use parameterized queries with placeholders (`?` or `%s` depending on DB driver). Pass query parameters as a tuple/list parameter.",
                        verification="Run analyzer and confirm query string contains placeholders without inline variable interpolation.",
                        cwe="CWE-89",
                        rule_id="RULE-SQLI-01",
                        secure_example="cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_pass))"
                    ))

        # H. Unsafe File/Path Handling (open() with dynamic concatenation)
        if func_name == "open":
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
                    self.analyzer.findings.append(Finding(
                        finding_id=self.analyzer._next_id("PATH"),
                        category="Unsafe File/Path Handling",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        line_number=lineno,
                        code_snippet=snippet,
                        explanation="File `open()` call uses dynamic string concatenation or unvalidated path construction.",
                        security_impact="Path Traversal (CWE-22) allow attackers using `../` sequences to read or overwrite arbitrary files on the system.",
                        remediation="Validate user-supplied filenames, sanitize inputs using `os.path.basename()`, or verify canonical paths using `os.path.abspath()` within an allowed directory.",
                        verification="Ensure file paths are validated against allowed base directory using `os.path.abspath()`.",
                        cwe="CWE-22",
                        rule_id="RULE-PATH-01",
                        secure_example="safe_name = os.path.basename(filename)\nwith open(os.path.join('/safe/dir', safe_name), 'r') as f:\n    content = f.read()"
                    ))

        # F. Weak Hashing (MD5 / SHA1)
        if func_name in ("hashlib.md5", "md5", "hashlib.sha1", "sha1"):
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("HASH"),
                category="Weak Cryptographic Hashing Algorithm",
                severity="HIGH",
                confidence="HIGH",
                line_number=lineno,
                code_snippet=snippet,
                explanation=f"Use of weak hash function `{func_name}()` detected.",
                security_impact="MD5 and SHA-1 are cryptographically vulnerable to collision and pre-image attacks. Fast hash algorithms are unsafe for password storage because rainbow tables and GPUs can crack them instantly.",
                remediation="Use password hashing algorithms designed for credential storage such as Argon2, bcrypt, scrypt, or PBKDF2 with SHA-256 (e.g. `werkzeug.security.generate_password_hash`).",
                verification="Re-analyze code and verify `hashlib.md5` and `hashlib.sha1` are replaced by secure password hashing functions.",
                cwe="CWE-327",
                rule_id="RULE-HASH-01",
                secure_example="from werkzeug.security import generate_password_hash\nhashed = generate_password_hash(password, method='pbkdf2:sha256')"
            ))

        # G. Insecure Randomness
        if func_name in ("random.random", "random.randint", "random.choice", "random.randrange", "random.randbytes"):
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("RAND"),
                category="Insecure Pseudo-Random Number Generator",
                severity="LOW",
                confidence="MEDIUM",
                line_number=lineno,
                code_snippet=snippet,
                explanation=f"Standard `random` module function `{func_name}()` is not cryptographically secure.",
                security_impact="Standard pseudo-random number generators (PRNGs) like Mersenne Twister are deterministic and predictable. If used for tokens, session IDs, or password reset keys, attackers can predict future outputs.",
                remediation="Use the `secrets` module (`secrets.token_hex()`, `secrets.token_urlsafe()`, `secrets.choice()`) for security-sensitive tokens and secrets.",
                verification="Ensure `secrets` module is used for security tokens instead of `random`.",
                cwe="CWE-330",
                rule_id="RULE-RAND-01",
                secure_example="import secrets\ntoken = secrets.token_hex(32)"
            ))

        # E. Debug mode detection (app.run(debug=True))
        if func_name in ("app.run", "run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.analyzer.findings.append(Finding(
                        finding_id=self.analyzer._next_id("DEBUG"),
                        category="Flask Debug Mode Enabled",
                        severity="MEDIUM",
                        confidence="HIGH",
                        line_number=lineno,
                        code_snippet=snippet,
                        explanation="Flask application configured to run with `debug=True`.",
                        security_impact="Running Flask in debug mode enables the Werkzeug interactive web debugger on unhandled exceptions, allowing remote arbitrary code execution.",
                        remediation="Disable debug mode in production: `app.run(debug=False, host='127.0.0.1')` or manage debug flag via environment variable.",
                        verification="Verify `debug=False` or environment check is configured.",
                        cwe="CWE-215",
                        rule_id="RULE-DEBUG-01",
                        secure_example="app.run(debug=False, host='127.0.0.1', port=5000)"
                    ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        lineno = getattr(node, "lineno", 1)
        snippet = self._get_snippet(node)

        # D. SQL Injection detection during variable assignment (e.g. query = f"SELECT ...")
        is_sql_query = False
        sql_keywords = ("select ", "insert ", "update ", "delete ", "drop ", "alter ", "create ", "where ")
        
        def contains_sql_str(s: str) -> bool:
            return any(kw in s.lower() for kw in sql_keywords)

        if isinstance(node.value, ast.JoinedStr):
            for val in node.value.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str) and contains_sql_str(val.value):
                    is_sql_query = True
                    break
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
            is_sql_query = contains_sql_str(snippet)
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "format":
            is_sql_query = contains_sql_str(snippet)

        if is_sql_query:
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("SQLI"),
                category="SQL Injection (SQLi) Vulnerability",
                severity="HIGH",
                confidence="HIGH",
                line_number=lineno,
                code_snippet=snippet,
                explanation="SQL query string constructed using unsafe string concatenation or variable interpolation.",
                security_impact="Constructing SQL queries dynamically using user input allows attackers to manipulate query logic (CWE-89), bypass authentication, or exfiltrate database records.",
                remediation="Construct query templates using parameter placeholders (`?` or `%s`) and pass variables to query execution separately.",
                verification="Run static analyzer to confirm query assignments use static string templates without variable interpolation.",
                cwe="CWE-89",
                rule_id="RULE-SQLI-02",
                secure_example="query = 'SELECT * FROM users WHERE username = ?'\ncursor.execute(query, (username,))"
            ))

        # Check variable assignment for hardcoded secret / key / token names
        for target in node.targets:
            var_name = ""
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr

            # E. Debug mode assignment
            if var_name.lower() in ("debug", "flask_debug") and isinstance(node.value, ast.Constant) and node.value.value is True:
                self.analyzer.findings.append(Finding(
                    finding_id=self.analyzer._next_id("DEBUG"),
                    category="Debug Mode Assignment Enabled",
                    severity="MEDIUM",
                    confidence="HIGH",
                    line_number=lineno,
                    code_snippet=snippet,
                    explanation=f"Debug flag `{var_name}` explicitly assigned `True`.",
                    security_impact="Enabling debug options in production exposes detailed error stack traces and interactive debugging consoles to attackers.",
                    remediation="Set debug variables to `False` in production or read from env vars: `os.environ.get('FLASK_DEBUG', '0') == '1'`.",
                    verification="Re-run static analysis to confirm debug mode assignment is disabled.",
                    cwe="CWE-215",
                    rule_id="RULE-DEBUG-02",
                    secure_example="app.config['DEBUG'] = os.environ.get('FLASK_DEBUG') == '1'"
                ))

            # A. Hardcoded Secret Assignments
            secret_keywords = ["secret", "key", "token", "password", "passwd", "auth", "credential", "private"]
            if any(k in var_name.lower() for k in secret_keywords):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) >= 4 and not val.startswith("os.environ"):
                        if not any(f.line_number == lineno and "Secret" in f.category for f in self.analyzer.findings):
                            self.analyzer.findings.append(Finding(
                                finding_id=self.analyzer._next_id("SECRET"),
                                category="Hard-coded Secret / Credential",
                                severity="HIGH",
                                confidence="HIGH",
                                line_number=lineno,
                                code_snippet=snippet,
                                explanation=f"Literal secret string assigned to variable `{var_name}`.",
                                security_impact="Hardcoding secrets in source code leads to credential leaks via version control systems and repository access.",
                                remediation="Retrieve secrets dynamically from environment variables or external secret vaults.",
                                verification="Run analyzer and confirm no literal strings are assigned to secret variable names.",
                                cwe="CWE-798",
                                rule_id="RULE-SECRET-02",
                                secure_example="app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))"
                            ))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        lineno = getattr(node, "lineno", 1)
        snippet = self._get_snippet(node)

        # I. Broad Exception Handling
        is_broad = False
        exc_name = "bare except:"
        if node.type is None:
            is_broad = True
        elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
            is_broad = True
            exc_name = f"except {node.type.id}:"

        if is_broad:
            self.analyzer.findings.append(Finding(
                finding_id=self.analyzer._next_id("EXCEPT"),
                category="Overly Broad Exception Handling",
                severity="LOW",
                confidence="MEDIUM",
                line_number=lineno,
                code_snippet=snippet,
                explanation=f"Overly broad exception catch clause (`{exc_name}`) detected.",
                security_impact="Catching generic `Exception` or bare `except:` can catch unintended critical failures (e.g. SystemExit, MemoryError, KeyboardInterrupt, or security check errors), hiding flaws and making debugging difficult.",
                remediation="Catch specific, expected exception types (e.g. `except (ValueError, KeyError):`). Log exceptions or re-raise if unhandled.",
                verification="Verify that try/except blocks handle specific exception classes.",
                cwe="CWE-396",
                rule_id="RULE-EXCEPT-01",
                secure_example="try:\n    perform_action()\nexcept (FileNotFoundError, ValueError) as err:\n    logger.error(f'Expected error: {err}')"
            ))

        self.generic_visit(node)
