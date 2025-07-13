# Users router for user management (admin-only endpoints)
# This module handles admin-only user management operations

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional, List
import logging
from math import ceil

from app.core.database import get_database_session
from app.models.user import User, UserRole
from app.schemas.user import (
    UserResponse,
    UserUpdate,
    UserRoleUpdate,
    UserListResponse,
    MessageResponse,
    ErrorResponse
)
from app.dependencies.auth import (
    get_current_admin_user,
    require_admin_role,
    verify_user_access,
    get_current_active_user
)

# Configure logging
logger = logging.getLogger(__name__)

# Create router instance
router = APIRouter(
    prefix="/users",
    tags=["User Management"],
    responses={
        401: {"model": ErrorResponse, "description": "Authentication required"},
        403: {"model": ErrorResponse, "description": "Admin privileges required"},
        404: {"model": ErrorResponse, "description": "User not found"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    }
)

@router.get(
    "/",
    response_model=UserListResponse,
    summary="Get all users (Admin only)",
    description="Retrieve a paginated list of all users in the system",
    responses={
        200: {"description": "Users retrieved successfully"},
        403: {"description": "Admin privileges required"}
    }
)
async def get_all_users(
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    per_page: int = Query(10, ge=1, le=100, description="Number of users per page"),
    role: Optional[UserRole] = Query(None, description="Filter by user role"),
    is_active: Optional[bool] = Query(None, description="Filter by account status"),
    search: Optional[str] = Query(None, description="Search by username or email"),
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Get paginated list of all users (admin only).
    
    This endpoint allows administrators to view all users in the system
    with optional filtering and pagination.
    
    Args:
        page: Page number (1-based)
        per_page: Number of users per page (1-100)
        role: Filter by user role
        is_active: Filter by account status
        search: Search term for username or email
        admin_user: Current admin user (from dependency)
        db: Database session
    
    Returns:
        UserListResponse: Paginated list of users
    """
    logger.info(f"Admin {admin_user.username} requesting user list (page {page}, per_page {per_page})")
    
    try:
        # Build query with filters
        query = db.query(User)
        
        # Apply role filter
        if role is not None:
            query = query.filter(User.role == role)
        
        # Apply active status filter
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (User.username.ilike(search_term)) |
                (User.email.ilike(search_term))
            )
        
        # Get total count for pagination
        total_users = query.count()
        
        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = ceil(total_users / per_page)
        
        # Get users for current page
        users = query.offset(offset).limit(per_page).all()
        
        # Convert to response models
        user_responses = [UserResponse.from_orm(user) for user in users]
        
        logger.info(f"Retrieved {len(users)} users for admin {admin_user.username}")
        
        return UserListResponse(
            users=user_responses,
            total=total_users,
            page=page,
            per_page=per_page,
            total_pages=total_pages
        )
    
    except Exception as e:
        logger.error(f"Error retrieving users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )

@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID",
    description="Retrieve a specific user by their ID (admin only or own profile)",
    responses={
        200: {"description": "User retrieved successfully"},
        404: {"description": "User not found"},
        403: {"description": "Access denied"}
    }
)
async def get_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_database_session)
):
    """
    Get user by ID.
    
    Users can access their own profile, admins can access any user's profile.
    
    Args:
        user_id: ID of the user to retrieve
        current_user: Current authenticated user
        db: Database session
    
    Returns:
        UserResponse: User information
    
    Raises:
        HTTPException: If user not found or access denied
    """
    logger.info(f"User {current_user.username} requesting user {user_id}")
    
    try:
        # Check access permissions
        if not verify_user_access(current_user, user_id):
            logger.warning(f"Access denied: {current_user.username} cannot access user {user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only access your own profile unless you are an admin"
            )
        
        # Find user by ID
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            logger.warning(f"User not found: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        logger.info(f"User {user.username} retrieved by {current_user.username}")
        return UserResponse.from_orm(user)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )

@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user (Admin only)",
    description="Update user information (admin only)",
    responses={
        200: {"description": "User updated successfully"},
        404: {"description": "User not found"},
        403: {"description": "Admin privileges required"},
        400: {"description": "Invalid update data"}
    }
)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Update user information (admin only).
    
    This endpoint allows administrators to update user information
    including username, email, and account status.
    
    Args:
        user_id: ID of the user to update
        user_update: Updated user data
        admin_user: Current admin user
        db: Database session
    
    Returns:
        UserResponse: Updated user information
    
    Raises:
        HTTPException: If user not found or update fails
    """
    logger.info(f"Admin {admin_user.username} updating user {user_id}")
    
    try:
        # Find user to update
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            logger.warning(f"User not found for update: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Check for duplicate username/email if being updated
        update_data = user_update.dict(exclude_unset=True)
        
        if "username" in update_data:
            existing_user = db.query(User).filter(
                User.username == update_data["username"],
                User.id != user_id
            ).first()
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already exists"
                )
        
        if "email" in update_data:
            existing_user = db.query(User).filter(
                User.email == update_data["email"],
                User.id != user_id
            ).first()
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already exists"
                )
        
        # Update user fields
        user.update_from_dict(update_data)
        
        # Commit changes
        db.commit()
        db.refresh(user)
        
        logger.info(f"User {user.username} updated successfully by admin {admin_user.username}")
        return UserResponse.from_orm(user)
    
    except HTTPException:
        raise
    except IntegrityError as e:
        db.rollback()
        logger.error(f"Database integrity error during user update: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists"
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )

@router.put(
    "/{user_id}/role",
    response_model=UserResponse,
    summary="Update user role (Admin only)",
    description="Update a user's role (admin only)",
    responses={
        200: {"description": "User role updated successfully"},
        404: {"description": "User not found"},
        403: {"description": "Admin privileges required"},
        400: {"description": "Cannot modify own role"}
    }
)
async def update_user_role(
    user_id: str,
    role_update: UserRoleUpdate,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Update user role (admin only).
    
    This endpoint allows administrators to change user roles.
    Admins cannot change their own role for security reasons.
    
    Args:
        user_id: ID of the user to update
        role_update: New role data
        admin_user: Current admin user
        db: Database session
    
    Returns:
        UserResponse: Updated user information
    
    Raises:
        HTTPException: If user not found or invalid operation
    """
    logger.info(f"Admin {admin_user.username} updating role for user {user_id} to {role_update.role}")
    
    try:
        # Find user to update
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            logger.warning(f"User not found for role update: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent admin from changing their own role
        if str(user.id) == str(admin_user.id):
            logger.warning(f"Admin {admin_user.username} attempted to change own role")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot change your own role"
            )
        
        # Update role
        old_role = user.role
        user.role = role_update.role
        
        # Commit changes
        db.commit()
        db.refresh(user)
        
        logger.info(
            f"User {user.username} role updated from {old_role} to {role_update.role} "
            f"by admin {admin_user.username}"
        )
        
        return UserResponse.from_orm(user)
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating user role {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user role"
        )

@router.delete(
    "/{user_id}",
    response_model=MessageResponse,
    summary="Delete user (Admin only)",
    description="Delete a user account (admin only)",
    responses={
        200: {"description": "User deleted successfully"},
        404: {"description": "User not found"},
        403: {"description": "Admin privileges required"},
        400: {"description": "Cannot delete own account"}
    }
)
async def delete_user(
    user_id: str,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Delete user account (admin only).
    
    This endpoint allows administrators to delete user accounts.
    Admins cannot delete their own account for security reasons.
    
    Args:
        user_id: ID of the user to delete
        admin_user: Current admin user
        db: Database session
    
    Returns:
        MessageResponse: Deletion confirmation
    
    Raises:
        HTTPException: If user not found or invalid operation
    """
    logger.info(f"Admin {admin_user.username} attempting to delete user {user_id}")
    
    try:
        # Find user to delete
        user = db.query(User).filter(User.id == user_id).first()
        
        if not user:
            logger.warning(f"User not found for deletion: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prevent admin from deleting their own account
        if str(user.id) == str(admin_user.id):
            logger.warning(f"Admin {admin_user.username} attempted to delete own account")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot delete your own account"
            )
        
        # Store user info for logging before deletion
        deleted_username = user.username
        deleted_email = user.email
        
        # Delete user
        db.delete(user)
        db.commit()
        
        logger.info(
            f"User {deleted_username} ({deleted_email}) deleted successfully "
            f"by admin {admin_user.username}"
        )
        
        return MessageResponse(
            message=f"User '{deleted_username}' deleted successfully",
            success=True,
            data={"deleted_user_id": user_id}
        )
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )

@router.get(
    "/stats/summary",
    response_model=dict,
    summary="Get user statistics (Admin only)",
    description="Get summary statistics about users in the system",
    responses={
        200: {"description": "Statistics retrieved successfully"},
        403: {"description": "Admin privileges required"}
    }
)
async def get_user_statistics(
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_database_session)
):
    """
    Get user statistics (admin only).
    
    This endpoint provides summary statistics about users in the system.
    
    Args:
        admin_user: Current admin user
        db: Database session
    
    Returns:
        dict: User statistics
    """
    logger.info(f"Admin {admin_user.username} requesting user statistics")
    
    try:
        # Get total user count
        total_users = db.query(User).count()
        
        # Get active user count
        active_users = db.query(User).filter(User.is_active == True).count()
        
        # Get inactive user count
        inactive_users = total_users - active_users
        
        # Get user count by role
        admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
        regular_user_count = db.query(User).filter(User.role == UserRole.USER).count()
        
        # Get recent registrations (last 30 days)
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_registrations = db.query(User).filter(
            User.created_at >= thirty_days_ago
        ).count()
        
        statistics = {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "users_by_role": {
                "admin": admin_count,
                "user": regular_user_count
            },
            "recent_registrations_30_days": recent_registrations,
            "activity_rate": round((active_users / total_users * 100), 2) if total_users > 0 else 0,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"User statistics generated for admin {admin_user.username}")
        return statistics
    
    except Exception as e:
        logger.error(f"Error generating user statistics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate user statistics"
        )

# Health check endpoint for user management service
@router.get(
    "/health",
    response_model=dict,
    summary="User management service health check",
    description="Check if user management service is working properly",
    tags=["Health"]
)
async def users_health_check():
    """
    Health check for user management service.
    
    Returns:
        dict: Service health status
    """
    return {
        "service": "user_management",
        "status": "healthy",
        "timestamp": "now()",
        "features": {
            "list_users": True,
            "get_user": True,
            "update_user": True,
            "update_role": True,
            "delete_user": True,
            "statistics": True
        }
    }