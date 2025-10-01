from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_login import UserMixin
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with secure password hashing and role-based access."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    api_key = db.Column(db.String(64), unique=True)
    api_key_created_at = db.Column(db.DateTime)
    api_key_expires_at = db.Column(db.DateTime)
    password_change_required = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_password_change = db.Column(db.DateTime)
    password_expires = db.Column(db.DateTime)
    
    logs = db.relationship('Log', backref='user', cascade='all, delete')
    issues = db.relationship('Issue', backref='assignee', cascade='all, delete')
    audit_logs = db.relationship('AuditLog', backref='user', cascade='all, delete')

    def set_password(self, password):
        """Hash and set the user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches the hash."""
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        """Check if user has admin role."""
        return self.role == 'admin'
        
    def generate_api_key(self, expiry_days=30):
        """
        Generate a new API key for the user.
        :param expiry_days: Number of days until the API key expires
        :return: The generated API key
        """
        self.api_key = secrets.token_urlsafe(32)
        self.api_key_created_at = datetime.utcnow()
        self.api_key_expires_at = self.api_key_created_at + timedelta(days=expiry_days)
        return self.api_key

    def is_api_key_valid(self):
        """Check if the API key is valid and not expired."""
        if not self.api_key or not self.api_key_expires_at:
            return False
        return datetime.utcnow() <= self.api_key_expires_at

class Log(db.Model):
    """Log model for system events and user actions."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    level = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    event_type = db.Column(db.String(50))

class Issue(db.Model):
    """Security issue tracking model."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='open')
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    resolved_at = db.Column(db.DateTime)
    resolution = db.Column(db.Text)
    
    @property
    def resolved(self):
        """Check if the issue is resolved based on status."""
        return self.status.lower() in ['resolved', 'closed', 'fixed']
    
    def resolve(self, resolution_text=None):
        """Mark the issue as resolved."""
        self.status = 'resolved'
        self.resolved_at = datetime.utcnow()
        if resolution_text:
            self.resolution = resolution_text

class AuditLog(db.Model):
    """Audit log for tracking security-relevant changes."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))

class ScanHistory(db.Model):
    """Model for storing vulnerability scan history and results."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(50), nullable=False, default='vulnerability')
    scan_path = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='completed')  # completed, failed, timeout
    vulnerabilities_found = db.Column(db.Integer, default=0)
    scan_duration = db.Column(db.Float)  # Duration in seconds
    osv_version = db.Column(db.String(20))
    raw_results = db.Column(db.Text)  # JSON string of full results
    error_message = db.Column(db.Text)
    
    # Relationship to user
    user = db.relationship('User', backref=db.backref('scan_history', lazy=True))
    
    def to_dict(self):
        """Convert scan history to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'scan_type': self.scan_type,
            'scan_path': self.scan_path,
            'user_id': self.user_id,
            'status': self.status,
            'vulnerabilities_found': self.vulnerabilities_found,
            'scan_duration': self.scan_duration,
            'osv_version': self.osv_version,
            'error_message': self.error_message
        }