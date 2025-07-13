# Configuration module for managing environment variables and application settings
# This module uses Pydantic Settings for type validation and environment variable loading

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os
from pathlib import Path

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Uses Pydantic for validation and type conversion.
    """
    
    # Supabase Configuration
    # URL for connecting to Supabase project
    supabase_url: str = Field(..., description="Supabase project URL")
    
    # Anonymous key for client-side operations (public key)
    supabase_anon_key: str = Field(..., description="Supabase anonymous key")
    
    # Service role key for server-side operations (private key)
    supabase_service_key: str = Field(..., description="Supabase service role key")
    
    # Database Configuration
    # PostgreSQL connection string for SQLAlchemy
    database_url: str = Field(..., description="Database connection URL")
    
    # JWT Configuration
    # Secret key for signing JWT tokens (must be kept secure)
    jwt_secret_key: str = Field(..., description="JWT secret key for token signing")
    
    # Algorithm used for JWT token signing (HS256 is recommended)
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    
    # Token expiration time in minutes
    jwt_access_token_expire_minutes: int = Field(
        default=30, 
        description="JWT token expiration time in minutes"
    )
    
    # Application Configuration
    # Environment mode (development, staging, production)
    environment: str = Field(default="development", description="Application environment")
    
    # API metadata
    api_title: str = Field(default="Secure Authentication API", description="API title")
    api_version: str = Field(default="1.0.0", description="API version")
    
    # Debug mode flag
    debug: bool = Field(default=True, description="Debug mode flag")
    
    # CORS Configuration
    # Allowed origins for CORS (comma-separated list)
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000",
        description="Allowed CORS origins"
    )
    
    # Security Configuration
    # Password minimum length
    password_min_length: int = Field(default=8, description="Minimum password length")
    
    # Rate limiting configuration
    rate_limit_requests: int = Field(default=100, description="Rate limit requests per minute")
    
    class Config:
        # Load environment variables from .env file
        env_file = os.path.join(PROJECT_ROOT, ".env")
        env_file_encoding = "utf-8"
        case_sensitive = False
        
        # Map environment variable names to field names
        fields = {
            "supabase_url": {"env": "SUPABASE_URL"},
            "supabase_anon_key": {"env": "SUPABASE_ANON_KEY"},
            "supabase_service_key": {"env": "SUPABASE_SERVICE_KEY"},
            "database_url": {"env": "DATABASE_URL"},
            "jwt_secret_key": {"env": "JWT_SECRET_KEY"},
            "jwt_algorithm": {"env": "JWT_ALGORITHM"},
            "jwt_access_token_expire_minutes": {"env": "JWT_ACCESS_TOKEN_EXPIRE_MINUTES"},
            "environment": {"env": "ENVIRONMENT"},
            "api_title": {"env": "API_TITLE"},
            "api_version": {"env": "API_VERSION"},
            "debug": {"env": "DEBUG"},
            "cors_origins": {"env": "CORS_ORIGINS"},
            "password_min_length": {"env": "PASSWORD_MIN_LENGTH"},
            "rate_limit_requests": {"env": "RATE_LIMIT_REQUESTS"},
        }
    
    @property
    def cors_origins_list(self) -> list[str]:
        """
        Convert comma-separated CORS origins string to list.
        """
        return [origin.strip() for origin in self.cors_origins.split(",")]
    
    @property
    def is_development(self) -> bool:
        """
        Check if application is running in development mode.
        """
        return self.environment.lower() == "development"
    
    @property
    def is_production(self) -> bool:
        """
        Check if application is running in production mode.
        """
        return self.environment.lower() == "production"

# Create a global settings instance
# This will be imported and used throughout the application
settings = Settings()

# Validate critical settings on startup
def validate_settings():
    """
    Validate critical application settings.
    Raises ValueError if any critical setting is missing or invalid.
    """
    if not settings.jwt_secret_key or settings.jwt_secret_key == "your-super-secret-jwt-key-change-this-in-production":
        raise ValueError(
            "JWT_SECRET_KEY must be set to a secure random string. "
            "Never use the default value in production!"
        )
    
    if settings.is_production and settings.debug:
        raise ValueError("Debug mode should be disabled in production environment")
    
    if not settings.database_url:
        raise ValueError("DATABASE_URL must be configured")
    
    print(f"✅ Settings validated successfully for {settings.environment} environment")

# Export commonly used settings
__all__ = ["settings", "validate_settings", "Settings"]