#!/usr/bin/env python3
"""
Startup script for the JWT Authentication API

This script provides an easy way to start the FastAPI application
with proper configuration and error handling.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    import uvicorn
    from app.core.config import settings, validate_settings
    from app.core.database import test_database_connection
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Please make sure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def check_environment():
    """
    Check if the environment is properly configured.
    
    Returns:
        bool: True if environment is ready, False otherwise
    """
    logger.info("🔍 Checking environment configuration...")
    
    # Check if .env file exists
    env_file = project_root / ".env"
    if not env_file.exists():
        logger.error("❌ .env file not found!")
        logger.error("Please create a .env file with your configuration.")
        logger.error("See .env.example for reference.")
        return False
    
    logger.info("✅ .env file found")
    
    try:
        # Validate settings configuration
        validate_settings()
        
        # Check critical settings
        if not settings.database_url:
            logger.error("❌ DATABASE_URL not configured")
            return False
        
        if not settings.jwt_secret_key:
            logger.error("❌ JWT_SECRET_KEY not configured")
            return False
        
        if not settings.supabase_url:
            logger.error("❌ SUPABASE_URL not configured")
            return False
        
        logger.info("✅ Configuration validated")
        return True
        
    except Exception as e:
        logger.error(f"❌ Configuration error: {e}")
        return False

def check_database():
    """
    Check database connectivity.
    
    Returns:
        bool: True if database is accessible, False otherwise
    """
    logger.info("🔍 Checking database connection...")
    
    try:
        if test_database_connection():
            logger.info("✅ Database connection successful")
            return True
        else:
            logger.error("❌ Database connection failed")
            logger.error("Please check your database configuration and ensure Supabase is accessible.")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
        logger.error("Please check your database configuration.")
        return False

def main():
    """
    Main function to start the application.
    """
    logger.info("🚀 Starting JWT Authentication API...")
    
    # Check environment
    if not check_environment():
        logger.error("❌ Environment check failed. Please fix the issues above.")
        sys.exit(1)
    
    # Check database
    if not check_database():
        logger.error("❌ Database check failed. Please fix the issues above.")
        sys.exit(1)
    
    # Determine host and port
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    # Log startup information
    logger.info(f"📋 Application: {settings.api_title} v{settings.api_version}")
    logger.info(f"🌍 Environment: {settings.environment}")
    logger.info(f"🔧 Debug mode: {settings.debug}")
    logger.info(f"🌐 Server: http://{host}:{port}")
    
    if settings.environment != "production":
        logger.info(f"📚 API Docs: http://{host}:{port}/docs")
        logger.info(f"📖 ReDoc: http://{host}:{port}/redoc")
    
    logger.info(f"❤️  Health Check: http://{host}:{port}/health")
    
    # Start the server
    try:
        logger.info("🎯 Starting server...")
        
        uvicorn.run(
            "app.main:app",
            host=host,
            port=port,
            reload=settings.debug,
            log_level="info" if settings.debug else "warning",
            access_log=settings.debug,
            reload_dirs=[str(project_root / "app")] if settings.debug else None
        )
        
    except KeyboardInterrupt:
        logger.info("\n🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()