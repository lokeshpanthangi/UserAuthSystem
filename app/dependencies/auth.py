# Authentication dependencies for FastAPI dependency injection
# This module provides dependency functions for user authentication and authorization

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.core.database import get_database_session
from app.core.security import verify_token, TokenData
from app.models.user import User, UserRole
from app.schemas.user import ErrorResponse

# Configure logging
logger = logging.getLogger(__name__)

# HTTP Bearer token security scheme
# This will automatically extract the Authorization header
security = HTTPBearer(
    scheme_name="JWT Bearer Token",
    description="Enter your JWT token",
    auto_error=False  # Don't automatically raise error, handle manually
)

class AuthenticationError(HTTPException):
    """
    Custom exception for authentication errors.
    
    Provides consistent error responses for authentication failures.
    """
    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

class AuthorizationError(HTTPException):
    """
    Custom exception for authorization errors.
    
    Used when user doesn't have sufficient permissions.
    """
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_database_session)
) -> User:
    """
    Dependency to get the current authenticated user.
    
    This function extracts and validates the JWT token from the Authorization header,
    then retrieves the corresponding user from the database.
    
    Args:
        credentials: HTTP Bearer token credentials
        db: Database session
    
    Returns:
        User: Current authenticated user
    
    Raises:
        AuthenticationError: If token is invalid or user not found
    
    Usage:
        @app.get("/protected")
        def protected_route(current_user: User = Depends(get_current_user)):
            return {"user_id": current_user.id}
    """
    # Check if credentials are provided
    if not credentials:
        logger.warning("No authorization credentials provided")
        raise AuthenticationError("Authorization header missing")
    
    # Extract token from credentials
    token = credentials.credentials
    if not token:
        logger.warning("Empty token in authorization header")
        raise AuthenticationError("Token missing in authorization header")
    
    # Verify and decode the token
    token_data: Optional[TokenData] = verify_token(token)
    if not token_data:
        logger.warning(f"Invalid token provided")
        raise AuthenticationError("Invalid or expired token")
    
    # Check if token contains required user information
    if not token_data.user_id:
        logger.warning("Token missing user_id")
        raise AuthenticationError("Invalid token payload")
    
    # Retrieve user from database
    try:
        user = db.query(User).filter(User.id == token_data.user_id).first()
        if not user:
            logger.warning(f"User not found for token user_id: {token_data.user_id}")
            raise AuthenticationError("User not found")
        
        # Log successful authentication (without sensitive data)
        logger.info(f"User authenticated successfully: {user.username}")
        return user
    
    except Exception as e:
        logger.error(f"Database error during user lookup: {str(e)}")
        raise AuthenticationError("Authentication failed")

def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to get the current active user.
    
    This function ensures the authenticated user account is active.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        User: Current active user
    
    Raises:
        AuthenticationError: If user account is inactive
    
    Usage:
        @app.get("/active-only")
        def active_only_route(current_user: User = Depends(get_current_active_user)):
            return {"message": "Access granted to active user"}
    """
    if not current_user.is_active:
        logger.warning(f"Inactive user attempted access: {current_user.username}")
        raise AuthenticationError("Account is inactive")
    
    return current_user

def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to get the current admin user.
    
    This function ensures the authenticated user has admin privileges.
    
    Args:
        current_user: Current active user
    
    Returns:
        User: Current admin user
    
    Raises:
        AuthorizationError: If user is not an admin
    
    Usage:
        @app.get("/admin-only")
        def admin_only_route(admin_user: User = Depends(get_current_admin_user)):
            return {"message": "Admin access granted"}
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(
            f"Non-admin user attempted admin access: {current_user.username} (role: {current_user.role})"
        )
        raise AuthorizationError("Admin privileges required")
    
    logger.info(f"Admin access granted to: {current_user.username}")
    return current_user

def require_admin_role(
    current_user: User = Depends(get_current_active_user)
) -> None:
    """
    Dependency to require admin role without returning user.
    
    This is useful when you need to enforce admin access but don't need
    the user object in your endpoint function.
    
    Args:
        current_user: Current active user
    
    Raises:
        AuthorizationError: If user is not an admin
    
    Usage:
        @app.delete("/admin/dangerous-action")
        def dangerous_action(_: None = Depends(require_admin_role)):
            return {"message": "Dangerous action performed"}
    """
    if current_user.role != UserRole.ADMIN:
        logger.warning(
            f"Non-admin user attempted admin action: {current_user.username}"
        )
        raise AuthorizationError("Admin privileges required for this action")

def optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_database_session)
) -> Optional[User]:
    """
    Dependency to optionally get the current user.
    
    This function returns the current user if valid credentials are provided,
    or None if no credentials are provided. It does not raise an error
    for missing credentials.
    
    Args:
        credentials: HTTP Bearer token credentials (optional)
        db: Database session
    
    Returns:
        Optional[User]: Current user if authenticated, None otherwise
    
    Usage:
        @app.get("/public-or-private")
        def flexible_route(current_user: Optional[User] = Depends(optional_current_user)):
            if current_user:
                return {"message": f"Hello, {current_user.username}!"}
            else:
                return {"message": "Hello, anonymous user!"}
    """
    # Return None if no credentials provided
    if not credentials or not credentials.credentials:
        return None
    
    try:
        # Try to get current user using the regular dependency
        # We need to manually call the function since we can't use Depends here
        token = credentials.credentials
        token_data = verify_token(token)
        
        if not token_data or not token_data.user_id:
            return None
        
        user = db.query(User).filter(User.id == token_data.user_id).first()
        return user if user and user.is_active else None
    
    except Exception as e:
        # Log the error but don't raise it (optional authentication)
        logger.debug(f"Optional authentication failed: {str(e)}")
        return None

def verify_user_access(current_user: User, target_user_id: str) -> bool:
    """
    Verify if current user can access target user's data.
    
    Users can access their own data, admins can access any user's data.
    
    Args:
        current_user: Current authenticated user
        target_user_id: ID of the user being accessed
    
    Returns:
        bool: True if access is allowed, False otherwise
    """
    # Users can always access their own data
    if str(current_user.id) == target_user_id:
        return True
    
    # Admins can access any user's data
    if current_user.role == UserRole.ADMIN:
        return True
    
    return False

def require_user_access(
    target_user_id: str,
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to require access to a specific user's data.
    
    Args:
        target_user_id: ID of the user being accessed
        current_user: Current authenticated user
    
    Returns:
        User: Current user (if access is allowed)
    
    Raises:
        AuthorizationError: If user cannot access the target user's data
    
    Usage:
        @app.get("/users/{user_id}/profile")
        def get_user_profile(
            user_id: str,
            _: User = Depends(lambda: require_user_access(user_id))
        ):
            # Access granted, proceed with operation
            pass
    """
    if not verify_user_access(current_user, target_user_id):
        logger.warning(
            f"User {current_user.username} attempted unauthorized access to user {target_user_id}"
        )
        raise AuthorizationError("You can only access your own data")
    
    return current_user

# Export all dependencies
__all__ = [
    "get_current_user",
    "get_current_active_user",
    "get_current_admin_user",
    "require_admin_role",
    "optional_current_user",
    "verify_user_access",
    "require_user_access",
    "AuthenticationError",
    "AuthorizationError"
]