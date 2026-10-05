"""
Integration Tests for Flask Web Application Routes
CodeAlpha Task 3: Secure Coding Review
"""

import unittest
from app import app, init_db

class TestAppRoutes(unittest.TestCase):

    def setUp(self):
        init_db()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()

    def test_dashboard_route(self):
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Application Security Audit Dashboard", response.data)

    def test_code_review_route(self):
        response = self.client.get('/code_review')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Python Source Code Security Scanner", response.data)

    def test_analyze_post_route(self):
        code = 'app_key = "super_secret_api_key_12345"\neval("print(1)")'
        response = self.client.post('/analyze', data={'source_code': code}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Audit Findings Catalog", response.data)

    def test_findings_route(self):
        response = self.client.get('/findings')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Findings Catalog", response.data)

    def test_comparison_route(self):
        response = self.client.get('/comparison')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Vulnerable Code vs Remediated Secure Code", response.data)

    def test_recommendations_route(self):
        response = self.client.get('/recommendations')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Secure Coding Guidelines", response.data)

    def test_reports_route(self):
        response = self.client.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Audit Report Generator", response.data)

    def test_download_report_md_route(self):
        response = self.client.get('/download_report?format=md')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Coding Review & Audit Report", response.data)

    def test_download_report_json_route(self):
        response = self.client.get('/download_report?format=json')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"metrics", response.data)

    def test_notes_route(self):
        response = self.client.get('/notes')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Review Notes Manager", response.data)

    def test_add_secure_note_route(self):
        response = self.client.post('/add_secure_note', data={
            'title': 'Test Audit Note',
            'content': 'Audit completed cleanly without errors.'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test Audit Note", response.data)

    def test_about_route(self):
        response = self.client.get('/about')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Audit Methodology", response.data)

if __name__ == '__main__':
    unittest.main()
