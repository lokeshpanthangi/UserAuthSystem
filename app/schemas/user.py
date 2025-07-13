# Pydantic schemas for user-related API requests and responses
# This module defines all data models for user authentication and management

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import re

from app.core.config import settings

class UserRole(str, Enum):
    """
    User role enumeration for API schemas.
    
    This enum matches the database UserRole enum.
    """
    USER = "user"
    ADMIN = "admin"

class UserCreate(BaseModel):
    """
    Schema for user registration request.
    
    This model validates user input during registration,
    including password strength requirements.
    """
    username: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description="Unique username for login"
    )
    email: EmailStr = Field(
        ...,
        description="Valid email address"
    )
    password: str = Field(
        ...,
        min_length=settings.password_min_length,
        description="Password meeting security requirements"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """
        Validate username format and requirements.
        
        Args:
            v (str): Username to validate
        
        Returns:
            str: Validated username
        
        Raises:
            ValueError: If username doesn't meet requirements
        """
        # Remove leading/trailing whitespace
        v = v.strip()
        
        # Check for empty username
        if not v:
            raise ValueError('Username cannot be empty')
        
        # Check for valid characters (alphanumeric and underscore)
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        
        # Check if username starts with a letter
        if not v[0].isalpha():
            raise ValueError('Username must start with a letter')
        
        # Check for reserved usernames
        reserved_usernames = ['admin', 'root', 'system', 'api', 'null', 'undefined']
        if v.lower() in reserved_usernames:
            raise ValueError('This username is reserved and cannot be used')
        
        return v
    
    @validator('password')
    def validate_password(cls, v):
        """
        Validate password strength requirements.
        
        Args:
            v (str): Password to validate
        
        Returns:
            str: Validated password
        
        Raises:
            ValueError: If password doesn't meet requirements
        """
        # Import here to avoid circular imports
        from app.core.security import PasswordValidator
        
        validation_result = PasswordValidator.validate_password_strength(v)
        
        if not validation_result['is_valid']:
            raise ValueError('; '.join(validation_result['errors']))
        
        return v
    
    class Config:
        # Example values for API documentation
        schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "password": "SecurePass123!"
            }
        }

class UserLogin(BaseModel):
    """
    Schema for user login request.
    
    Accepts either username or email for login.
    """
    username_or_email: str = Field(
        ...,
        description="Username or email address for login"
    )
    password: str = Field(
        ...,
        description="User password"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "username_or_email": "johndoe",
                "password": "SecurePass123!"
            }
        }

class UserResponse(BaseModel):
    """
    Schema for user data in API responses.
    
    This model excludes sensitive information like passwords.
    """
    id: str = Field(..., description="User unique identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    role: UserRole = Field(..., description="User role")
    is_active: bool = Field(..., description="Account status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    
    class Config:
        # Allow ORM models to be converted to Pydantic models
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        schema_extra = {
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "username": "johndoe",
                "email": "john.doe@example.com",
                "role": "user",
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z"
            }
        }

class UserProfile(BaseModel):
    """
    Schema for user profile information.
    
    Similar to UserResponse but may include additional profile fields.
    """
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

class UserUpdate(BaseModel):
    """
    Schema for updating user information.
    
    All fields are optional to allow partial updates.
    """
    username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=50,
        description="New username"
    )
    email: Optional[EmailStr] = Field(
        None,
        description="New email address"
    )
    is_active: Optional[bool] = Field(
        None,
        description="Account status"
    )
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username if provided."""
        if v is not None:
            # Use the same validation as UserCreate
            return UserCreate.validate_username(v)
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "username": "newusername",
                "email": "newemail@example.com",
                "is_active": True
            }
        }

class UserRoleUpdate(BaseModel):
    """
    Schema for updating user role (admin only).
    """
    role: UserRole = Field(..., description="New user role")
    
    class Config:
        schema_extra = {
            "example": {
                "role": "admin"
            }
        }

class TokenResponse(BaseModel):
    """
    Schema for authentication token response.
    
    Returned after successful login.
    """
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: UserProfile = Field(..., description="User profile information")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        schema_extra = {
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "johndoe",
                    "email": "john.doe@example.com",
                    "role": "user",
                    "is_active": True,
                    "created_at": "2024-01-15T10:30:00Z"
                }
            }
        }

class TokenData(BaseModel):
    """
    Schema for JWT token payload data.
    
    Used internally for token validation.
    """
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None

class ErrorResponse(BaseModel):
    """
    Schema for error responses.
    
    Standardized error format for all API endpoints.
    """
    error: str = Field(..., description="Error type or code")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[dict] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        schema_extra = {
            "example": {
                "error": "VALIDATION_ERROR",
                "message": "Invalid input data",
                "details": {
                    "field": "email",
                    "issue": "Invalid email format"
                },
                "timestamp": "2024-01-15T10:30:00Z"
            }
        }

class MessageResponse(BaseModel):
    """
    Schema for simple message responses.
    
    Used for success messages and confirmations.
    """
    message: str = Field(..., description="Response message")
    success: bool = Field(default=True, description="Operation success status")
    data: Optional[dict] = Field(None, description="Additional response data")
    
    class Config:
        schema_extra = {
            "example": {
                "message": "User created successfully",
                "success": True,
                "data": {
                    "user_id": "123e4567-e89b-12d3-a456-426614174000"
                }
            }
        }

class UserListResponse(BaseModel):
    """
    Schema for paginated user list response.
    
    Used for admin endpoints that return multiple users.
    """
    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Number of users per page")
    total_pages: int = Field(..., description="Total number of pages")
    
    class Config:
        schema_extra = {
            "example": {
                "users": [
                    {
                        "id": "123e4567-e89b-12d3-a456-426614174000",
                        "username": "johndoe",
                        "email": "john.doe@example.com",
                        "role": "user",
                        "is_active": True,
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-15T10:30:00Z"
                    }
                ],
                "total": 50,
                "page": 1,
                "per_page": 10,
                "total_pages": 5
            }
        }

class PasswordChangeRequest(BaseModel):
    """
    Schema for password change request.
    
    Requires current password for security.
    """
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=settings.password_min_length,
        description="New password meeting security requirements"
    )
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength."""
        from app.core.security import PasswordValidator
        
        validation_result = PasswordValidator.validate_password_strength(v)
        
        if not validation_result['is_valid']:
            raise ValueError('; '.join(validation_result['errors']))
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecurePass456!"
            }
        }

# Export all schemas
__all__ = [
    "UserRole",
    "UserCreate",
    "UserLogin",
    "UserResponse",
    "UserProfile",
    "UserUpdate",
    "UserRoleUpdate",
    "TokenResponse",
    "TokenData",
    "ErrorResponse",
    "MessageResponse",
    "UserListResponse",
    "PasswordChangeRequest"
]