import streamlit as st
import requests
import json
from datetime import datetime
import pandas as pd

# Configure Streamlit page
st.set_page_config(
    page_title="JWT Authentication System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API Configuration
API_BASE_URL = "http://localhost:8000"
API_AUTH_URL = f"{API_BASE_URL}/api/v1/auth"
API_USERS_URL = f"{API_BASE_URL}/api/v1/users"

# Initialize session state
if 'token' not in st.session_state:
    st.session_state.token = None
if 'user_info' not in st.session_state:
    st.session_state.user_info = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False

def make_request(method, url, data=None, headers=None):
    """Make HTTP request with error handling"""
    try:
        if headers is None:
            headers = {}
        
        if st.session_state.token:
            headers['Authorization'] = f'Bearer {st.session_state.token}'
        
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        elif method.upper() == 'POST':
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == 'PUT':
            headers['Content-Type'] = 'application/json'
            response = requests.put(url, json=data, headers=headers)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers)
        
        return response
    except requests.exceptions.RequestException as e:
        st.error(f"Connection error: {str(e)}")
        return None

def login_user(username, password):
    """Login user and store token"""
    data = {"username": username, "password": password}
    response = make_request('POST', f"{API_AUTH_URL}/login", data)
    
    if response and response.status_code == 200:
        result = response.json()
        st.session_state.token = result['access_token']
        
        # Get user profile
        profile_response = make_request('GET', f"{API_AUTH_URL}/profile")
        if profile_response and profile_response.status_code == 200:
            st.session_state.user_info = profile_response.json()
            st.session_state.is_admin = st.session_state.user_info.get('role') == 'admin'
            return {'success': True, 'response': response}
        else:
            return {'success': False, 'response': profile_response, 'error': 'Failed to get user profile'}
    
    return {'success': False, 'response': response}

def register_user(username, email, password):
    """Register new user"""
    data = {
        "username": username,
        "email": email,
        "password": password
    }
    response = make_request('POST', f"{API_AUTH_URL}/register", data)
    return response

def logout_user():
    """Logout user and clear session"""
    st.session_state.token = None
    st.session_state.user_info = None
    st.session_state.is_admin = False
    st.rerun()

def check_api_health():
    """Check if API is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def main():
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .main-header {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .status-card {
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #ddd;
        margin: 1rem 0;
    }
    .success-card {
        background-color: #d4edda;
        border-color: #c3e6cb;
    }
    .error-card {
        background-color: #f8d7da;
        border-color: #f5c6cb;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔐 JWT Authentication System</h1>
        <p>Secure User Management with FastAPI & Streamlit</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check API health
    if not check_api_health():
        st.error("⚠️ API Server is not running! Please start the FastAPI server first.")
        st.info("Run: `python run.py` in your project directory")
        return
    
    # Sidebar navigation
    with st.sidebar:
        st.title("Navigation")
        
        if st.session_state.token:
            st.success(f"Welcome, {st.session_state.user_info.get('username', 'User')}!")
            st.info(f"Role: {st.session_state.user_info.get('role', 'user').title()}")
            
            if st.button("🚪 Logout", use_container_width=True):
                logout_user()
            
            st.divider()
            
            # Navigation options
            page = st.selectbox(
                "Select Page",
                ["👤 Profile", "🔑 Change Password"] + 
                (["👥 User Management", "📊 Statistics"] if st.session_state.is_admin else [])
            )
        else:
            page = st.selectbox("Select Page", ["🔑 Login", "📝 Register"])
    
    # Main content area
    if not st.session_state.token:
        if page == "🔑 Login":
            show_login_page()
        elif page == "📝 Register":
            show_register_page()
    else:
        if page == "👤 Profile":
            show_profile_page()
        elif page == "🔑 Change Password":
            show_change_password_page()
        elif page == "👥 User Management" and st.session_state.is_admin:
            show_user_management_page()
        elif page == "📊 Statistics" and st.session_state.is_admin:
            show_statistics_page()

def show_login_page():
    st.header("🔑 User Login")
    
    with st.form("login_form"):
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            username = st.text_input("Username or Email", placeholder="Enter your username or email")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            submitted = st.form_submit_button("🔓 Login", use_container_width=True)
            
            if submitted:
                if username and password:
                    with st.spinner("Logging in..."):
                        login_result = login_user(username, password)
                        if login_result['success']:
                            st.success("✅ Login successful!")
                            st.rerun()
                        else:
                            response = login_result.get('response')
                            if response:
                                try:
                                    error_data = response.json()
                                    if isinstance(error_data, dict):
                                        if 'detail' in error_data:
                                            if isinstance(error_data['detail'], list):
                                                error_msgs = []
                                                for error in error_data['detail']:
                                                    if isinstance(error, dict) and 'msg' in error:
                                                        error_msgs.append(error['msg'])
                                                    else:
                                                        error_msgs.append(str(error))
                                                error_msg = "; ".join(error_msgs)
                                            else:
                                                error_msg = str(error_data['detail'])
                                        elif 'message' in error_data:
                                            error_msg = error_data['message']
                                        else:
                                            error_msg = f"Login failed (Status: {response.status_code})"
                                    else:
                                        error_msg = f"Login failed (Status: {response.status_code})"
                                    
                                    st.error(f"❌ {error_msg}")
                                    
                                    # Show additional debug info in expander for non-401 errors
                                    if response.status_code != 401:
                                        with st.expander("🔍 Technical Details", expanded=False):
                                            st.write(f"**Status Code:** {response.status_code}")
                                            st.write(f"**Response Headers:** {dict(response.headers)}")
                                            st.json(error_data)
                                            
                                except Exception as e:
                                    st.error(f"❌ Login failed (Status: {response.status_code})")
                                    with st.expander("🔍 Technical Details", expanded=False):
                                        st.write(f"**Status Code:** {response.status_code}")
                                        st.write(f"**Raw Response:** {response.text}")
                                        st.write(f"**Parse Error:** {str(e)}")
                            else:
                                error_msg = login_result.get('error', 'Login failed. Could not connect to server.')
                                st.error(f"❌ {error_msg}")
                else:
                    st.warning("⚠️ Please fill in all fields.")

def show_register_page():
    st.header("📝 User Registration")
    
    with st.form("register_form"):
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            username = st.text_input("Username", placeholder="Choose a username")
            email = st.text_input("Email", placeholder="Enter your email address")
            password = st.text_input("Password", type="password", placeholder="Create a strong password")
            confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
            
            st.info("Password must be at least 8 characters with uppercase, lowercase, number, and special character.")
            
            submitted = st.form_submit_button("📝 Register", use_container_width=True)
            
            if submitted:
                if username and email and password and confirm_password:
                    if password != confirm_password:
                        st.error("❌ Passwords do not match.")
                    else:
                        with st.spinner("Creating account..."):
                            response = register_user(username, email, password)
                            if response and response.status_code == 201:
                                st.success("✅ Account created successfully! Please login.")
                            elif response:
                                try:
                                    error_data = response.json()
                                    if isinstance(error_data, dict):
                                        # Handle different error response formats
                                        if 'detail' in error_data:
                                            if isinstance(error_data['detail'], list):
                                                # Validation errors
                                                error_msgs = []
                                                for error in error_data['detail']:
                                                    if isinstance(error, dict) and 'msg' in error:
                                                        error_msgs.append(error['msg'])
                                                    else:
                                                        error_msgs.append(str(error))
                                                error_msg = "; ".join(error_msgs)
                                            else:
                                                error_msg = str(error_data['detail'])
                                        elif 'message' in error_data:
                                            error_msg = error_data['message']
                                        else:
                                            error_msg = f"Registration failed (Status: {response.status_code})"
                                    else:
                                        error_msg = f"Registration failed (Status: {response.status_code})"
                                    
                                    st.error(f"❌ {error_msg}")
                                    
                                    # Show additional debug info in expander
                                    with st.expander("🔍 Technical Details", expanded=False):
                                        st.write(f"**Status Code:** {response.status_code}")
                                        st.write(f"**Response Headers:** {dict(response.headers)}")
                                        st.json(error_data)
                                        
                                except Exception as e:
                                    st.error(f"❌ Registration failed (Status: {response.status_code})")
                                    with st.expander("🔍 Technical Details", expanded=False):
                                        st.write(f"**Status Code:** {response.status_code}")
                                        st.write(f"**Raw Response:** {response.text}")
                                        st.write(f"**Parse Error:** {str(e)}")
                            else:
                                st.error("❌ Registration failed. Could not connect to server.")
                else:
                    st.warning("⚠️ Please fill in all fields.")

def show_profile_page():
    st.header("👤 User Profile")
    
    if st.session_state.user_info:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Profile Information")
            
            info_data = {
                "Username": st.session_state.user_info.get('username'),
                "Email": st.session_state.user_info.get('email'),
                "Role": st.session_state.user_info.get('role', 'user').title(),
                "Status": "Active" if st.session_state.user_info.get('is_active') else "Inactive",
                "Member Since": st.session_state.user_info.get('created_at', 'Unknown')
            }
            
            for key, value in info_data.items():
                st.text(f"**{key}:** {value}")
        
        with col2:
            st.subheader("Quick Actions")
            
            if st.button("🔄 Refresh Profile", use_container_width=True):
                response = make_request('GET', f"{API_AUTH_URL}/profile")
                if response and response.status_code == 200:
                    st.session_state.user_info = response.json()
                    st.success("Profile refreshed!")
                    st.rerun()
            
            if st.button("🔑 Change Password", use_container_width=True):
                st.info("Use the 'Change Password' page from the sidebar.")

def show_change_password_page():
    st.header("🔑 Change Password")
    
    with st.form("change_password_form"):
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_new_password = st.text_input("Confirm New Password", type="password")
            
            submitted = st.form_submit_button("🔄 Change Password", use_container_width=True)
            
            if submitted:
                if current_password and new_password and confirm_new_password:
                    if new_password != confirm_new_password:
                        st.error("❌ New passwords do not match.")
                    else:
                        data = {
                            "current_password": current_password,
                            "new_password": new_password
                        }
                        response = make_request('PUT', f"{API_AUTH_URL}/change-password", data)
                        if response and response.status_code == 200:
                            st.success("✅ Password changed successfully!")
                        elif response:
                            error_msg = response.json().get('detail', 'Password change failed')
                            st.error(f"❌ {error_msg}")
                        else:
                            st.error("❌ Password change failed.")
                else:
                    st.warning("⚠️ Please fill in all fields.")

def show_user_management_page():
    st.header("👥 User Management")
    
    # Get all users
    response = make_request('GET', API_USERS_URL)
    if response and response.status_code == 200:
        users_data = response.json()
        users = users_data.get('users', [])
        
        if users:
            # Convert to DataFrame for better display
            df = pd.DataFrame(users)
            
            # Display users table
            st.subheader("All Users")
            
            # Format the dataframe
            display_df = df[['username', 'email', 'role', 'is_active', 'created_at']].copy()
            display_df['created_at'] = pd.to_datetime(display_df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
            display_df['is_active'] = display_df['is_active'].map({True: '✅ Active', False: '❌ Inactive'})
            
            st.dataframe(display_df, use_container_width=True)
            
            # User actions
            st.subheader("User Actions")
            
            col1, col2 = st.columns(2)
            
            with col1:
                selected_user = st.selectbox(
                    "Select User",
                    options=[f"{user['username']} ({user['email']})" for user in users],
                    key="user_select"
                )
                
                if selected_user:
                    user_info = next(user for user in users if f"{user['username']} ({user['email']})" == selected_user)
                    
                    st.write(f"**Selected:** {user_info['username']}")
                    st.write(f"**Role:** {user_info['role']}")
                    st.write(f"**Status:** {'Active' if user_info['is_active'] else 'Inactive'}")
            
            with col2:
                if st.button("🔄 Refresh Users", use_container_width=True):
                    st.rerun()
        else:
            st.info("No users found.")
    else:
        st.error("Failed to load users.")

def show_statistics_page():
    st.header("📊 User Statistics")
    
    # Get statistics
    response = make_request('GET', f"{API_USERS_URL}/stats/summary")
    if response and response.status_code == 200:
        stats = response.json()
        
        # Display metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Users", stats.get('total_users', 0))
        
        with col2:
            st.metric("Active Users", stats.get('active_users', 0))
        
        with col3:
            st.metric("Admin Users", stats.get('admin_users', 0))
        
        with col4:
            st.metric("Regular Users", stats.get('regular_users', 0))
        
        # Additional statistics
        st.subheader("Detailed Statistics")
        
        stats_data = {
            "Metric": ["Total Users", "Active Users", "Inactive Users", "Admin Users", "Regular Users"],
            "Count": [
                stats.get('total_users', 0),
                stats.get('active_users', 0),
                stats.get('total_users', 0) - stats.get('active_users', 0),
                stats.get('admin_users', 0),
                stats.get('regular_users', 0)
            ]
        }
        
        df = pd.DataFrame(stats_data)
        st.bar_chart(df.set_index('Metric'))
        
    else:
        st.error("Failed to load statistics.")

if __name__ == "__main__":
    main()