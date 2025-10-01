#!/usr/bin/env python3
"""
Complete authentication flow test script
Tests login, password change, and system access
"""
import requests
import re
import json
import time
from urllib.parse import urljoin

class AuthFlowTester:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get_csrf_token(self, page_content):
        """Extract CSRF token from page content"""
        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', page_content)
        if csrf_match:
            return csrf_match.group(1)
        return None
    
    def test_login(self, username, password):
        """Test login functionality"""
        print(f"\n=== TESTING LOGIN: {username} ===")
        
        try:
            # Get login page
            print("1. Getting login page...")
            login_page = self.session.get(f"{self.base_url}/login")
            
            if login_page.status_code != 200:
                print(f"   FAIL Failed to get login page: {login_page.status_code}")
                return False
            
            # Extract CSRF token
            csrf_token = self.get_csrf_token(login_page.text)
            if not csrf_token:
                print("   FAIL CSRF token not found")
                return False
            
            print(f"   OK CSRF token extracted: {csrf_token[:20]}...")
            
            # Attempt login
            login_data = {
                'username': username,
                'password': password,
                'csrf_token': csrf_token
            }
            
            print("2. Attempting login...")
            login_response = self.session.post(
                f"{self.base_url}/login", 
                data=login_data,
                allow_redirects=False
            )
            
            print(f"   Status: {login_response.status_code}")
            
            if login_response.status_code == 302:
                redirect_location = login_response.headers.get('Location', '')
                print(f"   Redirect to: {redirect_location}")
                
                if 'change_password' in redirect_location:
                    print("   OK Login successful - redirected to change password")
                    return 'change_password_required'
                elif redirect_location in ['/', '/index']:
                    print("   OK Login successful - redirected to dashboard")
                    return 'success'
                else:
                    print(f"   ? Unexpected redirect: {redirect_location}")
                    return 'unexpected_redirect'
            else:
                print(f"   FAIL Login failed: {login_response.status_code}")
                if 'Invalid username or password' in login_response.text:
                    print("   FAIL Invalid credentials")
                elif 'locked' in login_response.text.lower():
                    print("   FAIL Account locked")
                return False
                
        except Exception as e:
            print(f"   FAIL Login test error: {e}")
            return False
    
    def test_change_password(self, current_password, new_password):
        """Test password change functionality"""
        print(f"\n=== TESTING PASSWORD CHANGE ===")
        
        try:
            # Get change password page
            print("1. Getting change password page...")
            change_page = self.session.get(f"{self.base_url}/change_password")
            
            if change_page.status_code != 200:
                print(f"   FAIL Failed to get change password page: {change_page.status_code}")
                return False
            
            # Extract CSRF token
            csrf_token = self.get_csrf_token(change_page.text)
            if not csrf_token:
                print("   FAIL CSRF token not found")
                return False
            
            print(f"   OK CSRF token extracted: {csrf_token[:20]}...")
            
            # Attempt password change
            change_data = {
                'current_password': current_password,
                'new_password': new_password,
                'confirm_password': new_password,
                'csrf_token': csrf_token
            }
            
            print("2. Attempting password change...")
            print(f"   Current password length: {len(current_password)}")
            print(f"   New password length: {len(new_password)}")
            
            change_response = self.session.post(
                f"{self.base_url}/change_password",
                data=change_data,
                allow_redirects=False
            )
            
            print(f"   Status: {change_response.status_code}")
            
            if change_response.status_code == 302:
                redirect_location = change_response.headers.get('Location', '')
                print(f"   Redirect to: {redirect_location}")
                print("   OK Password change successful")
                return True
            elif change_response.status_code == 400:
                print("   FAIL Password change failed - validation error")
                # Extract error messages
                if 'too short' in change_response.text.lower():
                    print("   FAIL Password too short")
                elif 'complexity' in change_response.text.lower():
                    print("   FAIL Password complexity requirements not met")
                elif 'incorrect' in change_response.text.lower():
                    print("   FAIL Current password incorrect")
                elif 'match' in change_response.text.lower():
                    print("   FAIL Passwords do not match")
                return False
            else:
                print(f"   FAIL Password change failed: {change_response.status_code}")
                return False
                
        except Exception as e:
            print(f"   FAIL Password change test error: {e}")
            return False
    
    def test_dashboard_access(self):
        """Test access to protected dashboard"""
        print(f"\n=== TESTING DASHBOARD ACCESS ===")
        
        try:
            dashboard_response = self.session.get(f"{self.base_url}/")
            
            if dashboard_response.status_code == 200:
                if 'logout' in dashboard_response.text.lower():
                    print("   OK Dashboard access successful")
                    return True
                else:
                    print("   ? Dashboard loaded but user might not be logged in")
                    return False
            elif dashboard_response.status_code == 302:
                redirect_location = dashboard_response.headers.get('Location', '')
                if 'login' in redirect_location:
                    print("   FAIL Redirected to login - not authenticated")
                    return False
                else:
                    print(f"   ? Unexpected redirect: {redirect_location}")
                    return False
            else:
                print(f"   FAIL Dashboard access failed: {dashboard_response.status_code}")
                return False
                
        except Exception as e:
            print(f"   FAIL Dashboard access test error: {e}")
            return False
    
    def run_complete_test(self):
        """Run the complete authentication flow test"""
        print("=" * 60)
        print("COMPLETE AUTHENTICATION FLOW TEST")
        print("=" * 60)
        
        # Test 1: Login with current password
        current_password = "AdminPassword123!"
        login_result = self.test_login("admin", current_password)
        
        if not login_result:
            print("\n❌ CRITICAL: Login failed completely")
            return False
        
        # Test 2: Test dashboard access
        dashboard_result = self.test_dashboard_access()
        
        # Test 3: Test password change functionality
        new_password = "NewSecurePassword123!"
        change_result = self.test_change_password(current_password, new_password)
        
        if change_result:
            print("\n=== TESTING LOGIN WITH NEW PASSWORD ===")
            # Test login with new password
            new_login_result = self.test_login("admin", new_password)
            
            if new_login_result:
                print("   OK Login with new password successful")
                
                # Reset password back to original for consistency
                print("\n=== RESETTING PASSWORD BACK ===")
                reset_result = self.test_change_password(new_password, current_password)
                if reset_result:
                    print("   OK Password reset back to original")
        
        # Summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        print(f"Login Test:           {'OK PASS' if login_result else 'FAIL FAIL'}")
        print(f"Dashboard Access:     {'OK PASS' if dashboard_result else 'FAIL FAIL'}")
        print(f"Password Change:      {'OK PASS' if change_result else 'FAIL FAIL'}")
        
        overall_success = login_result and dashboard_result and change_result
        print(f"\nOVERALL RESULT:       {'OK ALL TESTS PASSED' if overall_success else 'FAIL SOME TESTS FAILED'}")
        
        if overall_success:
            print("\nSUCCESS: AUTHENTICATION SYSTEM IS WORKING CORRECTLY!")
            print(f"You can now log in with:")
            print(f"Username: admin")
            print(f"Password: {current_password}")
        else:
            print("\nWARNING:  AUTHENTICATION ISSUES DETECTED")
            print("Check the detailed output above for specific problems")
        
        return overall_success

def main():
    print("Starting authentication flow test...")
    print("Testing Flask application on http://127.0.0.1:5000")
    
    # Give the server a moment to fully start
    import time
    time.sleep(2)
    
    tester = AuthFlowTester()
    success = tester.run_complete_test()
    
    return success

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)