# Security utilities for authentication, JWT tokens, and password management
# This module provides all security-related functions for the application

from datetime import datetime, timedelta
from typing import Optional, Union, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
import secrets
import string
import re
from pydantic import BaseModel

from .config import settings

# Password hashing context using bcrypt
# bcrypt is a secure hashing algorithm designed for password storage
pwd_context = CryptContext(
    schemes=["bcrypt"],  # Use bcrypt hashing scheme
    deprecated="auto",   # Automatically handle deprecated schemes
    bcrypt__rounds=12,   # Number of rounds for bcrypt (higher = more secure but slower)
)

class TokenData(BaseModel):
    """
    Model for JWT token data payload.
    
    This model defines the structure of data stored in JWT tokens.
    """
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None

class PasswordValidator:
    """
    Password validation utility class.
    
    Provides methods to validate password strength and security requirements.
    """
    
    @staticmethod
    def validate_password_strength(password: str) -> dict:
        """
        Validate password strength against security requirements.
        
        Args:
            password (str): Password to validate
        
        Returns:
            dict: Validation result with status and details
        """
        errors = []
        
        # Check minimum length
        if len(password) < settings.password_min_length:
            errors.append(f"Password must be at least {settings.password_min_length} characters long")
        
        # Check for uppercase letter
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        # Check for lowercase letter
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        # Check for digit
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")
        
        # Check for special character
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        ]
        if password.lower() in weak_passwords:
            errors.append("Password is too common and easily guessable")
        
        return {
            "is_valid": len(errors) == 0,
            "errors": errors,
            "strength_score": max(0, 100 - (len(errors) * 20))  # Simple scoring system
        }

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password (str): Plain text password to hash
    
    Returns:
        str: Hashed password
    
    Example:
        hashed = hash_password("mypassword123")
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password (str): Plain text password to verify
        hashed_password (str): Stored hashed password
    
    Returns:
        bool: True if password matches, False otherwise
    
    Example:
        is_valid = verify_password("mypassword123", stored_hash)
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Return False if verification fails for any reason
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data (dict): Data to encode in the token (user_id, username, role, etc.)
        expires_delta (Optional[timedelta]): Custom expiration time
    
    Returns:
        str: Encoded JWT token
    
    Example:
        token = create_access_token(
            data={"user_id": "123", "username": "john", "role": "user"}
        )
    """
    # Create a copy of the data to avoid modifying the original
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.jwt_access_token_expire_minutes
        )
    
    # Add expiration time to token payload
    to_encode.update({"exp": expire})
    
    # Add issued at time
    to_encode.update({"iat": datetime.utcnow()})
    
    # Add token type
    to_encode.update({"type": "access_token"})
    
    # Encode and return the JWT token
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.jwt_secret_key, 
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt

def verify_token(token: str) -> Optional[TokenData]:
    """
    Verify and decode a JWT token.
    
    Args:
        token (str): JWT token to verify
    
    Returns:
        Optional[TokenData]: Decoded token data if valid, None otherwise
    
    Example:
        token_data = verify_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
        if token_data:
            print(f"User ID: {token_data.user_id}")
    """
    try:
        # Decode the JWT token
        payload = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=[settings.jwt_algorithm]
        )
        
        # Extract user information from payload
        user_id: str = payload.get("user_id")
        username: str = payload.get("username")
        role: str = payload.get("role")
        exp_timestamp: int = payload.get("exp")
        
        # Validate required fields
        if user_id is None or username is None:
            return None
        
        # Convert expiration timestamp to datetime
        exp_datetime = datetime.fromtimestamp(exp_timestamp) if exp_timestamp else None
        
        # Create and return token data
        return TokenData(
            user_id=user_id,
            username=username,
            role=role,
            exp=exp_datetime
        )
    
    except JWTError:
        # Token is invalid or expired
        return None
    except Exception:
        # Any other error during token verification
        return None

def generate_secure_random_string(length: int = 32) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length (int): Length of the random string
    
    Returns:
        str: Secure random string
    
    Example:
        secret_key = generate_secure_random_string(64)
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def extract_token_from_header(authorization_header: str) -> Optional[str]:
    """
    Extract JWT token from Authorization header.
    
    Args:
        authorization_header (str): Authorization header value
    
    Returns:
        Optional[str]: Extracted token if valid format, None otherwise
    
    Example:
        token = extract_token_from_header("Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
    """
    if not authorization_header:
        return None
    
    # Check if header starts with "Bearer "
    if not authorization_header.startswith("Bearer "):
        return None
    
    # Extract token part (remove "Bearer " prefix)
    token = authorization_header[7:]  # len("Bearer ") = 7
    
    return token if token else None

def is_token_expired(token_data: TokenData) -> bool:
    """
    Check if a token is expired.
    
    Args:
        token_data (TokenData): Token data with expiration time
    
    Returns:
        bool: True if token is expired, False otherwise
    """
    if not token_data.exp:
        return True  # No expiration time means invalid token
    
    return datetime.utcnow() > token_data.exp

def get_password_hash_info(hashed_password: str) -> dict:
    """
    Get information about a hashed password.
    
    Args:
        hashed_password (str): Bcrypt hashed password
    
    Returns:
        dict: Information about the hash
    """
    try:
        # Extract bcrypt hash information
        if hashed_password.startswith("$2b$"):
            parts = hashed_password.split("$")
            if len(parts) >= 4:
                return {
                    "algorithm": "bcrypt",
                    "rounds": int(parts[2]),
                    "salt_length": len(parts[3]) if len(parts) > 3 else 0,
                    "is_valid_format": True
                }
        
        return {"is_valid_format": False}
    
    except Exception:
        return {"is_valid_format": False, "error": "Failed to parse hash"}

# Security constants
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin"
}

# Export commonly used functions
__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "verify_token",
    "TokenData",
    "PasswordValidator",
    "generate_secure_random_string",
    "extract_token_from_header",
    "is_token_expired",
    "get_password_hash_info",
    "SECURITY_HEADERS"
]