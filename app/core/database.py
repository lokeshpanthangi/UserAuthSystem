# Database configuration and connection management
# This module sets up SQLAlchemy engine, session management, and database utilities

from sqlalchemy import create_engine, MetaData, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator
import logging

from .config import settings

# Configure logging for database operations
logger = logging.getLogger(__name__)

# SQLAlchemy engine configuration
# Create database engine with connection pooling and optimization settings
engine = create_engine(
    settings.database_url,
    # Connection pool settings for better performance
    pool_size=10,  # Number of connections to maintain in the pool
    max_overflow=20,  # Maximum number of connections that can overflow the pool
    pool_pre_ping=True,  # Validate connections before use
    pool_recycle=3600,  # Recycle connections every hour
    # Echo SQL queries in development mode for debugging
    echo=settings.debug and settings.is_development,
)

# Session factory for creating database sessions
# autocommit=False: Transactions must be explicitly committed
# autoflush=False: Changes are not automatically flushed to database
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Base class for all SQLAlchemy models
# All database models will inherit from this base class
Base = declarative_base()

# Metadata object for database schema operations
metadata = MetaData()

def get_database_session() -> Generator[Session, None, None]:
    """
    Dependency function to get database session for FastAPI endpoints.
    
    This function creates a new database session for each request,
    ensures proper cleanup, and handles database errors gracefully.
    
    Yields:
        Session: SQLAlchemy database session
    
    Usage in FastAPI endpoints:
        @app.get("/users/")
        def get_users(db: Session = Depends(get_database_session)):
            return db.query(User).all()
    """
    # Create a new database session
    db = SessionLocal()
    try:
        # Yield the session to the endpoint
        yield db
    except Exception as e:
        # Rollback transaction on error
        logger.error(f"Database error occurred: {str(e)}")
        db.rollback()
        raise
    finally:
        # Always close the session to prevent connection leaks
        db.close()

def create_database_tables():
    """
    Create all database tables defined in models.
    
    This function should be called during application startup
    to ensure all required tables exist in the database.
    
    Note: In production, use Alembic migrations instead of this function.
    """
    try:
        # Import all models to ensure they are registered with Base
        from app.models import user  # noqa: F401
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables created successfully")
    except Exception as e:
        logger.error(f"❌ Failed to create database tables: {str(e)}")
        raise

def check_database_connection() -> bool:
    """
    Check if database connection is working properly.
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        # Test database connection
        with engine.connect() as connection:
            connection.execute("SELECT 1")
        logger.info("✅ Database connection successful")
        return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {str(e)}")
        return False

def get_database_info() -> dict:
    """
    Get database connection information for debugging.
    
    Returns:
        dict: Database connection details (excluding sensitive information)
    """
    return {
        "database_url": settings.database_url.split("@")[-1] if "@" in settings.database_url else "[hidden]",
        "pool_size": engine.pool.size(),
        "checked_in_connections": engine.pool.checkedin(),
        "checked_out_connections": engine.pool.checkedout(),
        "overflow_connections": engine.pool.overflow(),
        "echo_enabled": engine.echo,
    }

class DatabaseManager:
    """
    Database manager class for handling database operations.
    
    This class provides utility methods for database management,
    including health checks, connection management, and cleanup.
    """
    
    def __init__(self):
        self.engine = engine
        self.session_factory = SessionLocal
    
    def health_check(self) -> dict:
        """
        Perform a comprehensive database health check.
        
        Returns:
            dict: Health check results
        """
        try:
            # Test basic connection
            with self.engine.connect() as conn:
                result = conn.execute("SELECT version()")
                db_version = result.fetchone()[0]
            
            # Get connection pool status
            pool_status = {
                "size": self.engine.pool.size(),
                "checked_in": self.engine.pool.checkedin(),
                "checked_out": self.engine.pool.checkedout(),
                "overflow": self.engine.pool.overflow(),
            }
            
            return {
                "status": "healthy",
                "database_version": db_version,
                "connection_pool": pool_status,
                "timestamp": "now()"
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": "now()"
            }
    
    def close_all_connections(self):
        """
        Close all database connections.
        
        This method should be called during application shutdown
        to ensure proper cleanup of database resources.
        """
        try:
            self.engine.dispose()
            logger.info("✅ All database connections closed")
        except Exception as e:
            logger.error(f"❌ Error closing database connections: {str(e)}")

# Create a global database manager instance
db_manager = DatabaseManager()

def test_database_connection() -> bool:
    """
    Test database connectivity.
    
    This function attempts to connect to the database and execute
    a simple query to verify connectivity.
    
    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        # Create a test session
        db = SessionLocal()
        
        try:
            # Execute a simple query to test connection
            result = db.execute(text("SELECT 1"))
            result.fetchone()
            
            logger.info("Database connection test successful")
            return True
            
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"Database connection test failed: {str(e)}")
        return False

# Export commonly used objects
__all__ = [
    "engine",
    "SessionLocal",
    "Base",
    "get_database_session",
    "create_database_tables",
    "check_database_connection",
    "get_database_info",
    "test_database_connection",
    "db_manager",
]