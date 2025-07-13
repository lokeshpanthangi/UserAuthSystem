# User model for authentication and user management
# This module defines the User SQLAlchemy model with all required fields

from sqlalchemy import Column, String, Boolean, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
import enum
from datetime import datetime
from typing import Optional

from app.core.database import Base

class UserRole(str, enum.Enum):
    """
    Enumeration for user roles.
    
    This enum defines the available user roles in the system.
    """
    USER = "user"      # Regular user with basic permissions
    ADMIN = "admin"    # Administrator with full permissions

class User(Base):
    """
    User model for storing user authentication and profile information.
    
    This model represents users in the authentication system with
    secure password storage, role-based access control, and audit fields.
    
    Attributes:
        id (UUID): Unique identifier for the user
        username (str): Unique username for login
        email (str): Unique email address
        hashed_password (str): Bcrypt hashed password
        role (UserRole): User role (user or admin)
        is_active (bool): Account status flag
        created_at (datetime): Account creation timestamp
        updated_at (datetime): Last update timestamp
    """
    
    # Table name in the database
    __tablename__ = "users"
    
    # Primary key using UUID for better security and scalability
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        comment="Unique identifier for the user"
    )
    
    # Unique username for login (case-sensitive)
    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique username for login"
    )
    
    # Unique email address (case-insensitive)
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique email address"
    )
    
    # Bcrypt hashed password (never store plain text passwords)
    hashed_password = Column(
        String(255),
        nullable=False,
        comment="Bcrypt hashed password"
    )
    
    # User role with default value 'user'
    role = Column(
        Enum(UserRole),
        nullable=False,
        default=UserRole.USER,
        index=True,
        comment="User role (user or admin)"
    )
    
    # Account status flag
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Account status flag"
    )
    
    # Timestamp when account was created
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Account creation timestamp"
    )
    
    # Timestamp when account was last updated
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Last update timestamp"
    )
    
    def __repr__(self) -> str:
        """
        String representation of the User object.
        
        Returns:
            str: User representation (excludes sensitive data)
        """
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}', role='{self.role.value}')>"
    
    def __str__(self) -> str:
        """
        Human-readable string representation.
        
        Returns:
            str: User string representation
        """
        return f"User: {self.username} ({self.email})"
    
    @property
    def is_admin(self) -> bool:
        """
        Check if user has admin role.
        
        Returns:
            bool: True if user is admin, False otherwise
        """
        return self.role == UserRole.ADMIN
    
    @property
    def is_user(self) -> bool:
        """
        Check if user has regular user role.
        
        Returns:
            bool: True if user has user role, False otherwise
        """
        return self.role == UserRole.USER
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user object to dictionary.
        
        Args:
            include_sensitive (bool): Whether to include sensitive data
        
        Returns:
            dict: User data as dictionary
        """
        user_dict = {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        
        # Include sensitive data only if explicitly requested
        if include_sensitive:
            user_dict["hashed_password"] = self.hashed_password
        
        return user_dict
    
    def update_from_dict(self, data: dict) -> None:
        """
        Update user fields from dictionary.
        
        Args:
            data (dict): Dictionary containing fields to update
        
        Note:
            This method does not update sensitive fields like password or id.
            Use specific methods for password updates.
        """
        # List of fields that can be safely updated
        updatable_fields = ["username", "email", "role", "is_active"]
        
        for field in updatable_fields:
            if field in data and hasattr(self, field):
                # Handle role enum conversion
                if field == "role" and isinstance(data[field], str):
                    try:
                        setattr(self, field, UserRole(data[field]))
                    except ValueError:
                        # Invalid role value, skip update
                        continue
                else:
                    setattr(self, field, data[field])
    
    @classmethod
    def create_user_dict(cls, username: str, email: str, hashed_password: str, 
                        role: UserRole = UserRole.USER, is_active: bool = True) -> dict:
        """
        Create a dictionary for user creation.
        
        Args:
            username (str): Username
            email (str): Email address
            hashed_password (str): Hashed password
            role (UserRole): User role
            is_active (bool): Account status
        
        Returns:
            dict: Dictionary for creating new user
        """
        return {
            "username": username,
            "email": email,
            "hashed_password": hashed_password,
            "role": role,
            "is_active": is_active,
        }
    
    def can_access_admin_features(self) -> bool:
        """
        Check if user can access admin features.
        
        Returns:
            bool: True if user can access admin features
        """
        return self.is_active and self.is_admin
    
    def get_public_profile(self) -> dict:
        """
        Get public profile information (safe for API responses).
        
        Returns:
            dict: Public profile data
        """
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def get_token_payload(self) -> dict:
        """
        Get data for JWT token payload.
        
        Returns:
            dict: Data to include in JWT token
        """
        return {
            "user_id": str(self.id),
            "username": self.username,
            "role": self.role.value,
            "is_active": self.is_active,
        }

# Table constraints and indexes are defined in the database schema
# See database_schema.sql for additional constraints and indexes

# Export the User model and UserRole enum
__all__ = ["User", "UserRole"]