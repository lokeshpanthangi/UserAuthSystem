# Models package for database models
# This package contains all SQLAlchemy models for the application

# Import all models here to ensure they are registered with SQLAlchemy
from .user import User

# Export all models
__all__ = ["User"]