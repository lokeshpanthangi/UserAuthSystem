# Dependencies package for FastAPI dependency injection
# This package contains all dependency functions for authentication and authorization

# Import all dependencies here for easy access
from .auth import (
    get_current_user,
    get_current_active_user,
    get_current_admin_user,
    require_admin_role,
    optional_current_user
)

# Export all dependencies
__all__ = [
    "get_current_user",
    "get_current_active_user",
    "get_current_admin_user",
    "require_admin_role",
    "optional_current_user"
]