from web_interface.app import app
from models import db, User
from werkzeug.security import generate_password_hash

def reset_admin():
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                role='admin'
            )
            db.session.add(admin)
        
        # Use a compliant password that meets 12+ character requirement
        compliant_password = 'AdminPassword123!'
        admin.password_hash = generate_password_hash(compliant_password)
        admin.is_active = True
        admin.password_change_required = False
        admin.failed_login_attempts = 0
        db.session.commit()
        print(f'Admin user created/updated with password: {compliant_password}')
        print('Password meets all complexity requirements:')
        print('- 16 characters long')
        print('- Contains uppercase, lowercase, digits, and special characters')

if __name__ == '__main__':
    reset_admin()
