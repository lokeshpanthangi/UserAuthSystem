@echo off
REM Batch script to start the JWT Authentication API on Windows
REM This script activates the virtual environment and starts the server

echo ========================================
echo JWT Authentication API Startup Script
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Python found: 
python --version
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\activate.bat" (
    echo Virtual environment not found. Creating one...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
    echo.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)
echo Virtual environment activated
echo.

REM Check if requirements are installed
echo Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo Dependencies installed successfully
) else (
    echo Dependencies already installed
)
echo.

REM Check if .env file exists
if not exist ".env" (
    echo WARNING: .env file not found!
    echo Please create a .env file with your configuration
    echo See README.md for instructions
    pause
    exit /b 1
)

REM Start the application
echo Starting JWT Authentication API...
echo.
echo The API will be available at:
echo - Main API: http://localhost:8000
echo - Documentation: http://localhost:8000/docs
echo - Health Check: http://localhost:8000/health
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

python run.py

REM Pause on exit to see any error messages
if errorlevel 1 (
    echo.
    echo ========================================
    echo Server stopped with errors
    pause
)