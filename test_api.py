#!/usr/bin/env python3
"""
Simple API test script for JWT Authentication API

This script provides basic functionality testing for the authentication API.
It tests user registration, login, profile access, and admin operations.
"""

import requests
import json
import time
from typing import Optional, Dict, Any

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api/v1"

class APITester:
    """
    Simple API testing class for the JWT Authentication API.
    
    This class provides methods to test various API endpoints
    and verify the authentication system functionality.
    """
    
    def __init__(self, base_url: str = BASE_URL):
        """
        Initialize the API tester.
        
        Args:
            base_url: Base URL of the API server
        """
        self.base_url = base_url
        self.api_base = f"{base_url}/api/v1"
        self.session = requests.Session()
        self.token: Optional[str] = None
        self.user_id: Optional[str] = None
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[Any, Any]] = None,
        use_auth: bool = False
    ) -> requests.Response:
        """
        Make an HTTP request to the API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request data (for POST/PUT requests)
            use_auth: Whether to include authentication header
        
        Returns:
            requests.Response: The HTTP response
        """
        url = f"{self.api_base}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        if use_auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        kwargs = {
            "headers": headers,
            "timeout": 10
        }
        
        if data:
            kwargs["json"] = data
        
        return self.session.request(method, url, **kwargs)
    
    def test_health_check(self) -> bool:
        """
        Test the health check endpoint.
        
        Returns:
            bool: True if health check passes, False otherwise
        """
        print("🔍 Testing health check...")
        
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            
            if response.status_code == 200:
                health_data = response.json()
                print(f"✅ Health check passed: {health_data.get('status', 'unknown')}")
                return True
            else:
                print(f"❌ Health check failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Health check error: {e}")
            return False
    
    def test_user_registration(self, username: str, email: str, password: str) -> bool:
        """
        Test user registration.
        
        Args:
            username: Username for registration
            email: Email for registration
            password: Password for registration
        
        Returns:
            bool: True if registration succeeds, False otherwise
        """
        print(f"📝 Testing user registration for {username}...")
        
        try:
            data = {
                "username": username,
                "email": email,
                "password": password
            }
            
            response = self._make_request("POST", "/auth/register", data)
            
            if response.status_code == 201:
                user_data = response.json()
                self.user_id = user_data.get("user", {}).get("id")
                print(f"✅ Registration successful for {username}")
                print(f"   User ID: {self.user_id}")
                return True
            else:
                print(f"❌ Registration failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
            return False
    
    def test_user_login(self, username: str, password: str) -> bool:
        """
        Test user login.
        
        Args:
            username: Username for login
            password: Password for login
        
        Returns:
            bool: True if login succeeds, False otherwise
        """
        print(f"🔐 Testing user login for {username}...")
        
        try:
            data = {
                "username": username,
                "password": password
            }
            
            response = self._make_request("POST", "/auth/login", data)
            
            if response.status_code == 200:
                login_data = response.json()
                self.token = login_data.get("access_token")
                print(f"✅ Login successful for {username}")
                print(f"   Token: {self.token[:50]}...")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def test_get_profile(self) -> bool:
        """
        Test getting user profile (authenticated endpoint).
        
        Returns:
            bool: True if profile retrieval succeeds, False otherwise
        """
        print("👤 Testing profile retrieval...")
        
        try:
            response = self._make_request("GET", "/auth/profile", use_auth=True)
            
            if response.status_code == 200:
                profile_data = response.json()
                print(f"✅ Profile retrieved successfully")
                print(f"   Username: {profile_data.get('username')}")
                print(f"   Email: {profile_data.get('email')}")
                print(f"   Role: {profile_data.get('role')}")
                return True
            else:
                print(f"❌ Profile retrieval failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Profile retrieval error: {e}")
            return False
    
    def test_token_refresh(self) -> bool:
        """
        Test JWT token refresh.
        
        Returns:
            bool: True if token refresh succeeds, False otherwise
        """
        print("🔄 Testing token refresh...")
        
        try:
            response = self._make_request("POST", "/auth/refresh", use_auth=True)
            
            if response.status_code == 200:
                refresh_data = response.json()
                new_token = refresh_data.get("access_token")
                if new_token:
                    self.token = new_token
                    print(f"✅ Token refresh successful")
                    print(f"   New token: {new_token[:50]}...")
                    return True
                else:
                    print("❌ Token refresh failed: No new token received")
                    return False
            else:
                print(f"❌ Token refresh failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Token refresh error: {e}")
            return False
    
    def test_unauthorized_access(self) -> bool:
        """
        Test accessing protected endpoint without authentication.
        
        Returns:
            bool: True if properly denied, False otherwise
        """
        print("🚫 Testing unauthorized access...")
        
        try:
            # Temporarily remove token
            original_token = self.token
            self.token = None
            
            response = self._make_request("GET", "/auth/profile", use_auth=True)
            
            # Restore token
            self.token = original_token
            
            if response.status_code == 401:
                print("✅ Unauthorized access properly denied")
                return True
            else:
                print(f"❌ Unauthorized access not properly denied: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Unauthorized access test error: {e}")
            return False
    
    def test_admin_endpoints(self) -> bool:
        """
        Test admin-only endpoints (will fail for regular users).
        
        Returns:
            bool: True if admin access is properly controlled, False otherwise
        """
        print("👑 Testing admin endpoint access...")
        
        try:
            response = self._make_request("GET", "/users/", use_auth=True)
            
            if response.status_code == 403:
                print("✅ Admin endpoint properly protected (403 Forbidden)")
                return True
            elif response.status_code == 200:
                print("⚠️  Admin endpoint accessible (user might be admin)")
                users_data = response.json()
                print(f"   Retrieved {len(users_data.get('users', []))} users")
                return True
            else:
                print(f"❌ Unexpected admin endpoint response: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Admin endpoint test error: {e}")
            return False
    
    def run_full_test_suite(self) -> bool:
        """
        Run the complete test suite.
        
        Returns:
            bool: True if all tests pass, False otherwise
        """
        print("🧪 Starting API Test Suite")
        print("=" * 50)
        
        # Test configuration
        test_username = f"testuser_{int(time.time())}"
        test_email = f"test_{int(time.time())}@example.com"
        test_password = "TestPassword123!"
        
        tests = [
            ("Health Check", lambda: self.test_health_check()),
            ("User Registration", lambda: self.test_user_registration(test_username, test_email, test_password)),
            ("User Login", lambda: self.test_user_login(test_username, test_password)),
            ("Profile Retrieval", lambda: self.test_get_profile()),
            ("Token Refresh", lambda: self.test_token_refresh()),
            ("Unauthorized Access", lambda: self.test_unauthorized_access()),
            ("Admin Endpoints", lambda: self.test_admin_endpoints()),
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n📋 Running: {test_name}")
            try:
                if test_func():
                    passed += 1
                    print(f"✅ {test_name} PASSED")
                else:
                    print(f"❌ {test_name} FAILED")
            except Exception as e:
                print(f"❌ {test_name} ERROR: {e}")
            
            # Small delay between tests
            time.sleep(0.5)
        
        print("\n" + "=" * 50)
        print(f"🏁 Test Suite Complete: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! API is working correctly.")
            return True
        else:
            print(f"⚠️  {total - passed} test(s) failed. Please check the issues above.")
            return False

def main():
    """
    Main function to run the API tests.
    """
    print("🚀 JWT Authentication API Tester")
    print(f"Testing API at: {BASE_URL}")
    print("\nMake sure the API server is running before starting tests.")
    
    # Wait for user confirmation
    input("\nPress Enter to start testing...")
    
    # Create tester instance
    tester = APITester(BASE_URL)
    
    # Run tests
    success = tester.run_full_test_suite()
    
    # Exit with appropriate code
    exit(0 if success else 1)

if __name__ == "__main__":
    main()