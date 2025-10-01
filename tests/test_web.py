import pytest
import sys
import os
from flask import Flask, request, redirect, url_for
from datetime import datetime, timedelta
import json
from unittest.mock import patch, MagicMock
from flask_login import LoginManager, login_user

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import User, Log, Issue, AuditLog, db

def test_login_success(client, app_ctx):
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code in [200, 302]
    if response.status_code == 302:
        assert ('/' in response.headers['Location'] or 'change_password' in response.headers['Location'])

def test_login_failure(client, app_ctx):
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'wrongpass'
    })
    assert response.status_code == 200
    assert b'Invalid username or password' in response.data

def test_login_rate_limit(client, app_ctx):
    for _ in range(6):
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpass'
        })
    assert response.status_code == 429
    assert b'Account temporarily locked' in response.data

def test_protected_routes(client, app_ctx):
    # Test unauthenticated access
    response = client.get('/status')
    assert response.status_code == 302
    assert 'login' in response.headers['Location']
    
    # Test authenticated access
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    response = client.get('/status')
    assert response.status_code in [200, 302]

def test_password_change(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/change_password', data={
        'current_password': 'testpass',
        'new_password': 'NewPass123!@#',
        'confirm_password': 'NewPass123!@#'
    })
    assert response.status_code in [200, 302]
    user = User.query.filter_by(username='testuser').first()
    assert user.check_password('NewPass123!@#')

def test_logout(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.get('/logout')
    assert response.status_code == 302
    assert '/' in response.headers['Location']

def test_password_change_validation(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/change_password', data={
        'current_password': 'testpass',
        'new_password': 'weak',
        'confirm_password': 'weak'
    })
    assert response.status_code == 200
    assert b'Invalid form submission' in response.data

def test_admin_access(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.get('/admin')
    assert response.status_code == 403
    # Check for either custom error message or default Flask 403 response
    assert b'Forbidden' in response.data or b'Admin access required' in response.data

def test_issue_creation(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    response = client.post('/issues', data={
        'category': 'Security',
        'description': 'Test issue',
        'severity': 'High'
    })
    assert response.status_code in [200, 302]
    issue = Issue.query.filter_by(description='Test issue').first()
    assert issue is not None
    assert issue.category == 'Security'
    assert issue.severity == 'High'

def test_audit_logging(client, app_ctx):
    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    
    client.post('/issues', data={
        'category': 'Security',
        'description': 'Test issue',
        'severity': 'High'
    })
    audit = AuditLog.query.filter_by(action='issue_creation').first()
    assert audit is not None
    assert audit.user_id == User.query.filter_by(username='testuser').first().id