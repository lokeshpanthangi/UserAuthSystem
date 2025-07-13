# Main FastAPI application
# This is the entry point of the application that configures and starts the FastAPI server

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import time
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import create_database_tables, db_manager
from app.core.middleware import setup_rate_limiting, setup_security_middleware
from app.routers import auth_router, users_router
from app.schemas.user import ErrorResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Application settings are imported directly

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Handles startup and shutdown events for the FastAPI application.
    This includes database initialization and cleanup.
    """
    # Startup
    logger.info("Starting up FastAPI application...")
    
    try:
        # Create database tables if they don't exist
        logger.info("Creating database tables...")
        create_database_tables()
        logger.info("Database tables created successfully")
        
        # Test database connection
        health_result = db_manager.health_check()
        if health_result.get("status") == "healthy":
            logger.info("Database connection established successfully")
        else:
            logger.warning("Database connection test failed")
        
        logger.info("Application startup completed")
        
    except Exception as e:
        logger.error(f"Error during application startup: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down FastAPI application...")
    
    try:
        # Close database connections
        db_manager.close_all_connections()
        logger.info("Database connections closed")
        
        logger.info("Application shutdown completed")
        
    except Exception as e:
        logger.error(f"Error during application shutdown: {str(e)}")

# Create FastAPI application instance
app = FastAPI(
    title=settings.api_title,
    description="A secure JWT-based authentication system built with FastAPI, SQLAlchemy, and Supabase PostgreSQL. "
                "Features user registration, login, role-based access control, and comprehensive security measures.",
    version=settings.api_version,
    debug=settings.debug,
    lifespan=lifespan,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    openapi_url="/openapi.json" if settings.environment != "production" else None,
)

# Setup rate limiting
setup_rate_limiting(app)

# Setup security middleware
setup_security_middleware(app)

# Add security middleware
if settings.environment == "production":
    # Add trusted host middleware for production
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1"]  # Configure as needed
    )

# Add CORS middleware with more restrictive settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",  # Streamlit frontend
        "http://127.0.0.1:8501",
        "http://localhost:3000",  # Common React dev server
        "http://127.0.0.1:3000"
    ] + settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With"
    ],
    expose_headers=["X-Total-Count", "X-Page-Count"]
)

# Custom middleware for request logging and timing
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Middleware to log all HTTP requests and measure response time.
    
    This middleware logs incoming requests and their processing time,
    which is useful for monitoring and debugging.
    
    Args:
        request: The incoming HTTP request
        call_next: The next middleware or route handler
    
    Returns:
        Response: The HTTP response
    """
    start_time = time.time()
    
    # Log request details
    logger.info(
        f"Request: {request.method} {request.url.path} "
        f"from {request.client.host if request.client else 'unknown'}"
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate processing time
    process_time = time.time() - start_time
    
    # Add processing time to response headers
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log response details
    logger.info(
        f"Response: {response.status_code} for {request.method} {request.url.path} "
        f"(processed in {process_time:.4f}s)"
    )
    
    return response

# Custom exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Handle HTTP exceptions and return consistent error responses.
    
    Args:
        request: The HTTP request that caused the exception
        exc: The HTTP exception
    
    Returns:
        JSONResponse: Standardized error response
    """
    logger.warning(
        f"HTTP {exc.status_code} error on {request.method} {request.url.path}: {exc.detail}"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="HTTP Error",
            message=str(exc.detail),
            status_code=exc.status_code,
            path=str(request.url.path)
        ).dict()
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle request validation errors and return detailed error information.
    
    Args:
        request: The HTTP request that caused the validation error
        exc: The validation exception
    
    Returns:
        JSONResponse: Detailed validation error response
    """
    logger.warning(
        f"Validation error on {request.method} {request.url.path}: {exc.errors()}"
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            error="Validation Error",
            message="Request validation failed",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            path=str(request.url.path),
            details=exc.errors()
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """
    Handle unexpected exceptions and return generic error response.
    
    Args:
        request: The HTTP request that caused the exception
        exc: The unexpected exception
    
    Returns:
        JSONResponse: Generic error response
    """
    logger.error(
        f"Unexpected error on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True
    )
    
    # Don't expose internal error details in production
    error_detail = str(exc) if settings.DEBUG else "Internal server error"
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal Server Error",
            message=error_detail,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            path=str(request.url.path)
        ).dict()
    )

# Include routers
app.include_router(
    auth_router,
    prefix="/api/v1",
    tags=["Authentication"]
)

app.include_router(
    users_router,
    prefix="/api/v1",
    tags=["User Management"]
)

# Root endpoint
@app.get(
    "/",
    summary="API Root",
    description="Welcome endpoint for the JWT Authentication API",
    tags=["Root"]
)
async def root():
    """
    Root endpoint that provides basic API information.
    
    Returns:
        dict: API welcome message and basic information
    """
    return {
        "message": "Welcome to the JWT Authentication API",
        "title": settings.api_title,
        "version": settings.api_version,
        "environment": settings.environment,
        "docs_url": "/docs" if settings.environment != "production" else "Documentation disabled in production",
        "endpoints": {
            "authentication": "/api/v1/auth",
            "user_management": "/api/v1/users",
            "health_check": "/health"
        },
        "features": [
            "User Registration",
            "User Login",
            "JWT Token Authentication",
            "Role-based Access Control",
            "Password Security",
            "User Management (Admin)",
            "API Documentation"
        ]
    }

# Health check endpoint
@app.get(
    "/health",
    summary="Application Health Check",
    description="Check the health status of the application and its dependencies",
    tags=["Health"]
)
async def health_check():
    """
    Application health check endpoint.
    
    This endpoint checks the health of the application and its dependencies,
    including database connectivity.
    
    Returns:
        dict: Health status information
    """
    try:
        # Check database health
        db_health_result = db_manager.health_check()
        db_healthy = db_health_result.get("status") == "healthy"
        
        # Overall health status
        overall_status = "healthy" if db_healthy else "unhealthy"
        
        health_info = {
            "status": overall_status,
            "timestamp": time.time(),
            "version": settings.api_version,
            "environment": settings.environment,
            "services": {
                "database": "healthy" if db_healthy else "unhealthy",
                "authentication": "healthy",
                "user_management": "healthy"
            },
            "uptime": "Available via process monitoring"
        }
        
        # Always return 200 OK for API availability, but report service status
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=health_info
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "timestamp": time.time(),
                "error": "Health check failed",
                "message": str(e) if settings.debug else "Service unavailable"
            }
        )

# Startup event logging
@app.on_event("startup")
async def startup_event():
    """
    Log application startup information.
    
    This function is called when the application starts up and logs
    important configuration information.
    """
    logger.info(f"🚀 {settings.api_title} v{settings.api_version} starting up...")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Database URL: {settings.database_url[:50]}...")
    logger.info(f"CORS origins: {settings.cors_origins}")
    
    if settings.environment != "production":
        logger.info("📚 API Documentation available at: /docs")
        logger.info("📖 ReDoc documentation available at: /redoc")
    
    logger.info("✅ Application startup completed successfully")

# Shutdown event logging
@app.on_event("shutdown")
async def shutdown_event():
    """
    Log application shutdown information.
    
    This function is called when the application shuts down.
    """
    logger.info(f"🛑 {settings.api_title} shutting down...")
    logger.info("✅ Application shutdown completed")

if __name__ == "__main__":
    # This block is executed when running the script directly
    # For development purposes only
    import uvicorn
    
    logger.info("Starting development server...")
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )