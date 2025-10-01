import pytest
import sys
import os
from datetime import datetime
from flask import Flask

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Log, Issue, AuditLog

def test_user_creation(client):
    user = User(
        username='test_db_user',
        email='test_db@test.com',
        role='user'
    )
    user.set_password('testpass')
    db.session.add(user)
    db.session.commit()

    saved_user = User.query.filter_by(username='test_db_user').first()
    assert saved_user.username == 'test_db_user'
    assert saved_user.email == 'test_db@test.com'
    assert saved_user.role == 'user'
    assert saved_user.check_password('testpass')

def test_log_creation(client):
    log = Log(
        level='INFO',
        message='Test log message',
        event_type='test',
        ip_address='127.0.0.1'
    )
    db.session.add(log)
    db.session.commit()

    saved_log = Log.query.first()
    assert saved_log.level == 'INFO'
    assert saved_log.message == 'Test log message'
    assert saved_log.event_type == 'test'
    assert saved_log.ip_address == '127.0.0.1'

def test_issue_creation(client):
    issue = Issue(
        category='Security',
        description='Test issue',
        severity='High',
        status='open'
    )
    db.session.add(issue)
    db.session.commit()

    saved_issue = Issue.query.first()
    assert saved_issue.category == 'Security'
    assert saved_issue.description == 'Test issue'
    assert saved_issue.severity == 'High'
    assert saved_issue.status == 'open'

def test_audit_log_creation(client):
    audit = AuditLog(
        action='test_action',
        details='Test audit details',
        ip_address='127.0.0.1'
    )
    db.session.add(audit)
    db.session.commit()

    saved_audit = AuditLog.query.first()
    assert saved_audit.action == 'test_action'
    assert saved_audit.details == 'Test audit details'
    assert saved_audit.ip_address == '127.0.0.1'

def test_user_relationships(client):
    # Login and related code...

    # Create user and related records
    user = User(username='test_rel_user', email='test_relationships@test.com')
    user.set_password('testpass')
    db.session.add(user)
    db.session.commit()

    log = Log(level='INFO', message='Test', user_id=user.id)
    issue = Issue(category='Test', description='Test', severity='Low', assigned_to=user.id)
    audit = AuditLog(action='test', user_id=user.id)

    db.session.add_all([log, issue, audit])
    db.session.commit()

    # Verify relationships
    saved_user = User.query.filter_by(username='test_rel_user').first()
    assert Log.query.filter_by(user_id=saved_user.id).first() is not None
    assert Issue.query.filter_by(assigned_to=saved_user.id).first() is not None
    assert AuditLog.query.filter_by(user_id=saved_user.id).first() is not None

def test_cascade_delete(client):
    # Create user and related records
    user = User(username='test_cascade_user', email='test_cascade@test.com')
    user.set_password('testpass')
    db.session.add(user)
    db.session.commit()

    log = Log(level='INFO', message='Test', user_id=user.id)
    issue = Issue(category='Test', description='Test', severity='Low', assigned_to=user.id)
    audit = AuditLog(action='test', user_id=user.id)

    db.session.add_all([log, issue, audit])
    db.session.commit()

    # Delete user and verify cascade
    db.session.delete(user)
    db.session.commit()

    assert Log.query.filter_by(user_id=user.id).first() is None
    assert Issue.query.filter_by(assigned_to=user.id).first() is None
    assert AuditLog.query.filter_by(user_id=user.id).first() is None