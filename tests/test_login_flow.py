
import unittest
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web_interface import create_app, db
from models import User

class TestLoginFlow(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF to test real scenario
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_admin_login(self):
        # 1. Get login page to get CSRF token
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        csrf_token = ''
        if 'name="csrf_token"' in response.get_data(as_text=True):
             print("CSRF Token field found in HTML.")
             # Print the line with the token
             for line in response.get_data(as_text=True).split('\n'):
                 if 'name="csrf_token"' in line:
                     print(f"Token Line: {line.strip()}")
                     import re
                     # Try to match value
                     match = re.search(r'value="([^"]*)"', line)
                     if match:
                         csrf_token = match.group(1)
                         print(f"CSRF Token extracted: {csrf_token[:10]}...")
                     break
        else:
             print("CSRF Token NOT found in form")

        # 2. Try login with token
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPassword123!',
            'csrf_token': csrf_token
        }, follow_redirects=True)
        
        print(f"Login Response Status: {response.status_code}")
        data = response.get_data(as_text=True)
        
        if 'Change Password' in data:
             print("RESULT: Redirected to Change Password page (Success)")
        elif 'Dashboard' in data or 'System Status' in data:
             print("RESULT: Redirected to Dashboard (Success)")
        elif 'Invalid username or password' in data:
             print("RESULT: Invalid username or password (Failed)")
        elif 'The CSRF token is missing' in data or 'The CSRF token is invalid' in data:
             print("RESULT: CSRF Error (Failed)")
        else:
             print(f"RESULT: Unknown State. Page content snippet: {data[:500]}")

if __name__ == '__main__':
    unittest.main()
