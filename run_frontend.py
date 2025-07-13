#!/usr/bin/env python3
"""
Startup script for the Streamlit Frontend

This script starts the Streamlit frontend application that connects
to the JWT Authentication API.
"""

import os
import sys
import subprocess
import time
import requests
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_api_server():
    """
    Check if the FastAPI server is running.
    
    Returns:
        bool: True if API server is accessible, False otherwise
    """
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def start_streamlit():
    """
    Start the Streamlit application.
    """
    print("🚀 Starting Streamlit Frontend...")
    print("📋 JWT Authentication System Frontend")
    print("🌐 Frontend will be available at: http://localhost:8501")
    print("🔗 Make sure the API server is running at: http://localhost:8000")
    print("\n" + "="*60)
    
    # Check if API server is running
    if not check_api_server():
        print("⚠️  WARNING: API server is not running!")
        print("   Please start the API server first by running: python run.py")
        print("   The frontend will still start, but API calls will fail.")
        print("\n" + "="*60)
    else:
        print("✅ API server is running and accessible")
        print("\n" + "="*60)
    
    try:
        # Start Streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "streamlit_app.py",
            "--server.port=8501",
            "--server.address=localhost",
            "--browser.gatherUsageStats=false"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error starting Streamlit: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n🛑 Frontend stopped by user")
        sys.exit(0)

def main():
    """
    Main function to start the frontend application.
    """
    print("🔍 Checking environment...")
    
    # Check if streamlit_app.py exists
    if not os.path.exists("streamlit_app.py"):
        print("❌ streamlit_app.py not found!")
        print("   Please make sure you're in the correct directory.")
        sys.exit(1)
    
    print("✅ Frontend application found")
    
    # Start Streamlit
    start_streamlit()

if __name__ == "__main__":
    main()