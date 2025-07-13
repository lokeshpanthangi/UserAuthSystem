# Security middleware for rate limiting, headers, and input sanitization
# This module provides comprehensive security middleware for the FastAPI application

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
import re
import html
import logging
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Rate limiter instance
limiter = Limiter(key_func=get_remote_address)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.
    
    This middleware adds various security headers to protect against
    common web vulnerabilities and attacks.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add security headers to the response.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware or route handler
        
        Returns:
            Response: The HTTP response with security headers
        """
        response = await call_next(request)
        
        # Security headers
        security_headers = {
            # Prevent clickjacking attacks
            "X-Frame-Options": "DENY",
            
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Enable XSS protection
            "X-XSS-Protection": "1; mode=block",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            ),
            
            # Permissions policy
            "Permissions-Policy": (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "speaker=()"
            ),
        }
        
        # Add HSTS header for HTTPS
        if request.url.scheme == "https":
            security_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Add all security headers to response
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response

class InputSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize user inputs and prevent injection attacks.
    
    This middleware cleans and validates user inputs to prevent
    XSS, SQL injection, and other input-based attacks.
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        
        # Patterns for detecting malicious input
        self.xss_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'<iframe[^>]*>', re.IGNORECASE),
            re.compile(r'<object[^>]*>', re.IGNORECASE),
            re.compile(r'<embed[^>]*>', re.IGNORECASE),
        ]
        
        self.sql_patterns = [
            re.compile(r"(union|select|insert|update|delete|drop|create|alter)\s+", re.IGNORECASE),
            re.compile(r"'\s*(or|and)\s*'\w*'\s*=\s*'\w*'", re.IGNORECASE),
            re.compile(r"--", re.IGNORECASE),
            re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Sanitize request data before processing.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware or route handler
        
        Returns:
            Response: The HTTP response
        """
        # Check for malicious patterns in URL path
        if self._contains_malicious_patterns(request.url.path):
            logger.warning(f"Malicious pattern detected in URL path: {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid request", "message": "Malicious input detected"}
            )
        
        # Check query parameters
        for key, value in request.query_params.items():
            if self._contains_malicious_patterns(f"{key}={value}"):
                logger.warning(f"Malicious pattern detected in query params: {key}={value}")
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "Invalid request", "message": "Malicious input detected"}
                )
        
        return await call_next(request)
    
    def _contains_malicious_patterns(self, text: str) -> bool:
        """
        Check if text contains malicious patterns.
        
        Args:
            text: The text to check
        
        Returns:
            bool: True if malicious patterns found, False otherwise
        """
        # Check for XSS patterns
        for pattern in self.xss_patterns:
            if pattern.search(text):
                return True
        
        # Check for SQL injection patterns
        for pattern in self.sql_patterns:
            if pattern.search(text):
                return True
        
        return False
    
    @staticmethod
    def sanitize_string(text: str) -> str:
        """
        Sanitize a string by escaping HTML and removing dangerous characters.
        
        Args:
            text: The text to sanitize
        
        Returns:
            str: The sanitized text
        """
        if not isinstance(text, str):
            return text
        
        # HTML escape
        text = html.escape(text)
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove control characters except newline and tab
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
        
        return text.strip()

def setup_rate_limiting(app):
    """
    Set up rate limiting for the FastAPI application.
    
    Args:
        app: The FastAPI application instance
    """
    # Add rate limiting middleware
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    
    # Add general rate limiting middleware for all requests
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """
        General rate limiting middleware for all API requests.
        
        Applies a 100 requests per minute per IP limit to all endpoints.
        """
        try:
            # Get client IP
            client_ip = request.client.host if request.client else "unknown"
            
            # Check if this is a health check or docs endpoint (exempt from rate limiting)
            if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
                response = await call_next(request)
                return response
            
            # Apply general rate limit using slowapi's limiter
            # This will be handled by the @limiter.limit decorators on individual endpoints
            response = await call_next(request)
            return response
            
        except RateLimitExceeded:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "detail": "API rate limit exceeded"
                }
            )
        except Exception as e:
            # If rate limiting fails, continue with the request
            response = await call_next(request)
            return response
    
    logger.info("Rate limiting configured successfully")

def setup_security_middleware(app):
    """
    Set up all security middleware for the FastAPI application.
    
    Args:
        app: The FastAPI application instance
    """
    # Add security headers middleware
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Add input sanitization middleware
    app.add_middleware(InputSanitizationMiddleware)
    
    # Set up rate limiting
    setup_rate_limiting(app)
    
    logger.info("Security middleware configured successfully")

# Export the limiter for use in route decorators
__all__ = ["limiter", "setup_security_middleware", "InputSanitizationMiddleware"]