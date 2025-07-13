# Routers package for API endpoints
# This package contains all FastAPI routers for different API modules

# Import all routers here for easy access
from .auth import router as auth_router
from .users import router as users_router

# Export all routers
__all__ = ["auth_router", "users_router"]