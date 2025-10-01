from web_interface.app import app
from models import db, User
from datetime import datetime, timedelta

def init_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create a test user if none exists
        if not User.query.filter_by(username='admin').first():
            test_user = User(
                username='admin',
                email='admin@example.com',
                role='admin',
                is_active=True,
                last_login=datetime.utcnow(),
                password_change_required=False,
                password_expires=datetime.utcnow() + timedelta(days=90)
            )
            test_user.set_password('AdminPassword123!')  # Set a default password
            db.session.add(test_user)
            db.session.commit()
            print("Test user 'admin' created successfully")

if __name__ == '__main__':
    init_database()
