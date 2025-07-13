# Authentication router for user registration, login, and profile management
# This module handles all authentication-related API endpoints

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
import logging

from app.core.database import get_database_session
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    PasswordValidator
)
from app.core.config import settings
from app.models.user import User, UserRole
from app.schemas.user import (
    UserCreate,
    UserLogin,
    UserResponse,
    UserProfile,
    TokenResponse,
    MessageResponse,
    ErrorResponse,
    PasswordChangeRequest
)
from app.dependencies.auth import get_current_active_user

# Configure logging
logger = logging.getLogger(__name__)

# Create router instance
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    }
)

@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account with username, email, and password",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "User already exists or invalid data"},
        422: {"description": "Validation error"}
    }
)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_database_session)
):
    """
    Register a new user account.
    
    This endpoint creates a new user with the provided credentials.
    Passwords are automatically hashed using bcrypt before storage.
    
    Args:
        user_data: User registration data (username, email, password)
        db: Database session
    
    Returns:
        MessageResponse: Success message with user ID
    
    Raises:
        HTTPException: If user already exists or validation fails
    """
    logger.info(f"Registration attempt for username: {user_data.username}")
    
    try:
        # Check if user already exists (username or email)
        existing_user = db.query(User).filter(
            (User.username == user_data.username) | 
            (User.email == user_data.email)
        ).first()
        
        if existing_user:
            if existing_user.username == user_data.username:
                logger.warning(f"Registration failed: Username '{user_data.username}' already exists")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already registered"
                )
            else:
                logger.warning(f"Registration failed: Email '{user_data.email}' already exists")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
        
        # Hash the password
        hashed_password = hash_password(user_data.password)
        
        # Create new user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            role=UserRole.USER,  # Default role
            is_active=True
        )
        
        # Add user to database
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        logger.info(f"User registered successfully: {new_user.username} (ID: {new_user.id})")
        
        return MessageResponse(
            message="User registered successfully",
            success=True,
            data={"user_id": str(new_user.id)}
        )
    
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Database integrity error during registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this username or email already exists"
        )
    
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to server error"
        )

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User login",
    description="Authenticate user and return JWT access token",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        422: {"description": "Validation error"}
    }
)
async def login_user(
    login_data: UserLogin,
    db: Session = Depends(get_database_session)
):
    """
    Authenticate user and return access token.
    
    This endpoint accepts username or email with password,
    validates credentials, and returns a JWT token.
    
    Args:
        login_data: Login credentials (username/email and password)
        db: Database session
    
    Returns:
        TokenResponse: JWT token and user information
    
    Raises:
        HTTPException: If credentials are invalid
    """
    logger.info(f"Login attempt for: {login_data.username_or_email}")
    
    try:
        # Find user by username or email
        user = db.query(User).filter(
            (User.username == login_data.username_or_email) |
            (User.email == login_data.username_or_email)
        ).first()
        
        # Check if user exists
        if not user:
            logger.warning(f"Login failed: User not found for '{login_data.username_or_email}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if account is active
        if not user.is_active:
            logger.warning(f"Login failed: Inactive account for user '{user.username}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verify password
        if not verify_password(login_data.password, user.hashed_password):
            logger.warning(f"Login failed: Invalid password for user '{user.username}'")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username/email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        access_token = create_access_token(
            data=user.get_token_payload(),
            expires_delta=access_token_expires
        )
        
        logger.info(f"Login successful for user: {user.username}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.jwt_access_token_expire_minutes * 60,  # Convert to seconds
            user=UserProfile.from_orm(user)
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed due to server error"
        )

@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get current user profile",
    description="Get the profile information of the currently authenticated user",
    responses={
        200: {"description": "User profile retrieved successfully"},
        401: {"description": "Authentication required"}
    }
)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's profile information.
    
    This endpoint returns the profile of the currently authenticated user.
    Requires a valid JWT token in the Authorization header.
    
    Args:
        current_user: Current authenticated user (from dependency)
    
    Returns:
        UserProfile: Current user's profile information
    """
    logger.info(f"Profile request for user: {current_user.username}")
    
    return UserProfile.from_orm(current_user)

@router.put(
    "/change-password",
    response_model=MessageResponse,
    summary="Change user password",
    description="Change the password for the currently authenticated user",
    responses={
        200: {"description": "Password changed successfully"},
        401: {"description": "Authentication required"},
        400: {"description": "Invalid current password"}
    }
)
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_database_session)
):
    """
    Change user's password.
    
    This endpoint allows users to change their password by providing
    their current password and a new password.
    
    Args:
        password_data: Current and new password data
        current_user: Current authenticated user
        db: Database session
    
    Returns:
        MessageResponse: Success message
    
    Raises:
        HTTPException: If current password is invalid
    """
    logger.info(f"Password change request for user: {current_user.username}")
    
    try:
        # Verify current password
        if not verify_password(password_data.current_password, current_user.hashed_password):
            logger.warning(f"Password change failed: Invalid current password for user '{current_user.username}'")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Check if new password is different from current
        if verify_password(password_data.new_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from current password"
            )
        
        # Hash new password
        new_hashed_password = hash_password(password_data.new_password)
        
        # Update password in database
        current_user.hashed_password = new_hashed_password
        db.commit()
        
        logger.info(f"Password changed successfully for user: {current_user.username}")
        
        return MessageResponse(
            message="Password changed successfully",
            success=True
        )
    
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during password change: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed due to server error"
        )

@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Refresh the current access token (extend session)",
    responses={
        200: {"description": "Token refreshed successfully"},
        401: {"description": "Authentication required"}
    }
)
async def refresh_token(
    current_user: User = Depends(get_current_active_user)
):
    """
    Refresh the current access token.
    
    This endpoint generates a new access token for the current user,
    effectively extending their session.
    
    Args:
        current_user: Current authenticated user
    
    Returns:
        TokenResponse: New JWT token and user information
    """
    logger.info(f"Token refresh request for user: {current_user.username}")
    
    try:
        # Create new access token
        access_token_expires = timedelta(minutes=settings.jwt_access_token_expire_minutes)
        access_token = create_access_token(
            data=current_user.get_token_payload(),
            expires_delta=access_token_expires
        )
        
        logger.info(f"Token refreshed successfully for user: {current_user.username}")
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.jwt_access_token_expire_minutes * 60,
            user=UserProfile.from_orm(current_user)
        )
    
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed due to server error"
        )

# Health check endpoint for authentication service
@router.get(
    "/health",
    response_model=dict,
    summary="Authentication service health check",
    description="Check if authentication service is working properly",
    tags=["Health"]
)
async def auth_health_check():
    """
    Health check for authentication service.
    
    Returns:
        dict: Service health status
    """
    return {
        "service": "authentication",
        "status": "healthy",
        "timestamp": "now()",
        "features": {
            "registration": True,
            "login": True,
            "password_change": True,
            "token_refresh": True
        }
    }