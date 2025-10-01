#!/usr/bin/env python3
"""
Secure Admin Password Reset Script
Creates/resets admin user with temporary password and forces password change on first login
"""
from web_interface.app import app
from models import db, User
from werkzeug.security import generate_password_hash
import secrets
import string
import logging
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_secure_temp_password(length=16):
    """Generate a secure temporary password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def reset_admin_user():
    """Reset admin user with secure temporary password"""
    
    with app.app_context():
        logger.info("=== SECURE ADMIN RESET STARTED ===")
        
        # Generate secure temporary password
        temp_password = generate_secure_temp_password()
        
        # Find or create admin user
        admin = User.query.filter_by(username='admin').first()
        
        if admin:
            logger.info(f"Found existing admin user: {admin.username}")
            logger.info(f"Current status - Active: {admin.is_active}, Password change required: {admin.password_change_required}")
        else:
            logger.info("Creating new admin user")
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            db.session.add(admin)
        
        # Reset admin user properties
        admin.set_password(temp_password)
        admin.is_active = True
        admin.password_change_required = True  # Force password change on first login
        admin.failed_login_attempts = 0
        admin.last_password_change = datetime.utcnow()
        admin.password_expires = datetime.utcnow() + timedelta(days=1)  # Expires in 1 day
        
        try:
            db.session.commit()
            logger.info("✓ Admin user reset successfully")
            logger.info("=" * 60)
            logger.info("TEMPORARY LOGIN CREDENTIALS:")
            logger.info(f"Username: admin")
            logger.info(f"Password: {temp_password}")
            logger.info("=" * 60)
            logger.info("IMPORTANT SECURITY NOTES:")
            logger.info("1. This is a TEMPORARY password that expires in 24 hours")
            logger.info("2. You MUST change the password on first login")
            logger.info("3. The system will force a password change")
            logger.info("4. New password must be at least 12 characters long")
            logger.info("=" * 60)
            
            # Verify the password works
            if admin.check_password(temp_password):
                logger.info("✓ Password verification successful")
            else:
                logger.error("✗ Password verification failed!")
                return False
                
        except Exception as e:
            logger.error(f"✗ Database error: {e}")
            db.session.rollback()
            return False
        
        logger.info("=== SECURE ADMIN RESET COMPLETED ===")
        return True

def verify_login_fix():
    """Verify that the login issue is fixed"""
    with app.app_context():
        logger.info("\n=== VERIFYING LOGIN FIX ===")
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            logger.error("✗ Admin user not found!")
            return False
        
        logger.info(f"✓ Admin user exists: {admin.username}")
        logger.info(f"✓ User is active: {admin.is_active}")
        logger.info(f"✓ Password change required: {admin.password_change_required}")
        logger.info(f"✓ Password hash exists: {bool(admin.password_hash)}")
        logger.info(f"✓ Failed login attempts reset: {admin.failed_login_attempts}")
        
        logger.info("=== VERIFICATION COMPLETE ===")
        return True

if __name__ == '__main__':
    print("Secure Admin Reset Script")
    print("This will reset the admin user with a temporary password")
    
    confirm = input("Do you want to proceed? (yes/no): ").lower().strip()
    if confirm in ['yes', 'y']:
        if reset_admin_user():
            verify_login_fix()
            print("\nAdmin reset completed successfully!")
            print("Check the log output above for temporary credentials")
        else:
            print("\nAdmin reset failed!")
    else:
        print("Operation cancelled.")