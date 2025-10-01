#!/usr/bin/env python3
"""
Test login functionality with proper session and CSRF handling
"""
import requests
import re

def test_login():
    """Test login functionality"""
    base_url = "http://127.0.0.1:5000"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print("=== TESTING LOGIN FUNCTIONALITY ===")
    
    try:
        # First, get the login page to extract CSRF token
        print("1. Getting login page...")
        login_page = session.get(f"{base_url}/login")
        print(f"   Status: {login_page.status_code}")
        
        if login_page.status_code != 200:
            print(f"   ERROR: Could not access login page")
            return False
        
        # Parse the HTML to extract CSRF token using regex
        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page.text)
        
        if not csrf_match:
            print("   ERROR: CSRF token not found in login form")
            return False
        
        csrf_value = csrf_match.group(1)
        print(f"   CSRF token found: {csrf_value[:20]}...")
        
        # Prepare login data
        login_data = {
            'username': 'admin',
            'password': 'jt3#WoVyn1Wz$nfy',
            'csrf_token': csrf_value
        }
        
        # Prepare headers to match browser behavior
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{base_url}/login'
        }
        
        print("2. Attempting login...")
        login_response = session.post(f"{base_url}/login", data=login_data, headers=headers, allow_redirects=False)
        print(f"   Status: {login_response.status_code}")
        print(f"   Headers: {dict(login_response.headers)}")
        
        if login_response.status_code == 302:
            redirect_location = login_response.headers.get('Location', '')
            print(f"   Redirect to: {redirect_location}")
            
            if 'change_password' in redirect_location:
                print("   SUCCESS: Login successful, redirected to change password")
                return True
            elif redirect_location == '/':
                print("   SUCCESS: Login successful, redirected to dashboard")
                return True
            else:
                print(f"   WARNING: Unexpected redirect location: {redirect_location}")
                return False
        else:
            print(f"   ERROR: Login failed with status {login_response.status_code}")
            print(f"   Response: {login_response.text[:500]}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ERROR: Could not connect to server. Is the application running?")
        return False
    except Exception as e:
        print(f"   ERROR: {e}")
        return False

if __name__ == '__main__':
    success = test_login()
    if success:
        print("\nLOGIN TEST PASSED")
        print("The user can now successfully log in with:")
        print("Username: admin")
        print("Password: jt3#WoVyn1Wz$nfy")
    else:
        print("\nLOGIN TEST FAILED")