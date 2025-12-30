
import os
import sys
from dotenv import load_dotenv
from main import create_app
from models import db, User

load_dotenv()

app = create_app()
with app.app_context():
    admin_pass_env = os.getenv('ADMIN_PASSWORD')
    print(f"ADMIN_PASSWORD env var: {admin_pass_env}")
    
    user = User.query.filter_by(username='admin').first()
    if user:
        print(f"Admin user found: {user.username}")
        print(f"Email: {user.email}")
        print(f"Role: {user.role}")
        
        # Test default password
        default_pass = 'AdminPassword123!'
        if user.check_password(default_pass):
            print("Default password 'AdminPassword123!' works.")
        else:
            print("Default password 'AdminPassword123!' DOES NOT work.")

            if admin_pass_env:
                 if user.check_password(admin_pass_env):
                     print("Environment password works.")
                 else:
                     print("Environment password also DOES NOT work.")
    else:
        print("Admin user NOT found in database.")
