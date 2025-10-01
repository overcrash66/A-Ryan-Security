from datetime import datetime, timedelta
from models import User, db, AuditLog
from flask import current_app

# Optional email support
try:
    from flask_mail import Message
    HAS_EMAIL = True
except ImportError:
    HAS_EMAIL = False

def check_expiring_api_keys():
    """Check for API keys that will expire soon and notify users."""
    # Find API keys expiring in the next 7 days
    expiry_threshold = datetime.utcnow() + timedelta(days=7)
    
    expiring_keys = User.query.filter(
        User.api_key.isnot(None),
        User.api_key_expires_at <= expiry_threshold,
        User.api_key_expires_at > datetime.utcnow()
    ).all()
    
    for user in expiring_keys:
        days_left = (user.api_key_expires_at - datetime.utcnow()).days
        
        # Log the expiring key
        current_app.logger.info(f"API key for user {user.username} expires in {days_left} days")
        
        # Send email notification if mail is configured and available
        if HAS_EMAIL and hasattr(current_app, 'mail'):
            try:
                msg = Message(
                    "API Key Expiration Notice",
                    recipients=[user.email],
                    body=f"Your API key will expire in {days_left} days. Please generate a new key."
                )
                current_app.mail.send(msg)
            except Exception as e:
                current_app.logger.error(f"Failed to send API key expiration email: {e}")
        
        # Always log the notification in AuditLog
        audit_log = AuditLog(
            user_id=user.id,
            action='api_key_expiring',
            resource_type='api_key',
            details=f'API key expires in {days_left} days',
        )
        db.session.add(audit_log)

def cleanup_expired_api_keys():
    """Remove expired API keys."""
    expired_users = User.query.filter(
        User.api_key.isnot(None),
        User.api_key_expires_at <= datetime.utcnow()
    ).all()
    
    for user in expired_users:
        user.api_key = None
        user.api_key_created_at = None
        user.api_key_expires_at = None
    
    try:
        db.session.commit()
        current_app.logger.info(f"Cleaned up {len(expired_users)} expired API keys")
    except Exception as e:
        current_app.logger.error(f"Failed to cleanup expired API keys: {e}")
        db.session.rollback()