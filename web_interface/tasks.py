import logging
from datetime import datetime
from models import db, User, AuditLog
from security_modules.antivirus import extra_antivirus_layer

# We will inject app context from the scheduler runner

def check_password_expiration(app):
    """Check for expired passwords and flag users."""
    with app.app_context():
        try:
            expired_users = User.query.filter(
                User.password_expires <= datetime.utcnow()
            ).all()
            
            for user in expired_users:
                user.password_change_required = True
                logging.warning(f'Password expired for user: {user.username}')
                
                # Create audit log
                audit = AuditLog(
                    user_id=user.id,
                    action='password_expired',
                    details='Password expired and change required'
                )
                db.session.add(audit)
            
            db.session.commit()
        except Exception as e:
            logging.error(f"Error in check_password_expiration: {e}")
            db.session.rollback()

def run_extra_antivirus_job():
    """Wrapper for antivirus job to be friendly to scheduler"""
    # Assuming extra_antivirus_layer handles its own context or doesn't need DB?
    # services.py: extra_antivirus_layer()
    # antivirus.py: extra_antivirus_layer()
    # It scans files. Does it use DB?
    # It returns a dict. It doesn't seem to invoke DB models directly.
    # But it might be called by other things.
    # The original code was: scheduler.add_job(func=extra_antivirus_layer, ...)
    try:
        extra_antivirus_layer()
    except Exception as e:
        logging.error(f"Error in antivirus job: {e}")
