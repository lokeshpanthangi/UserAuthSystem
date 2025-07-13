@echo off
echo ========================================
echo   JWT Authentication System Frontend
echo ========================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

:: Check if we're in the right directory
if not exist "streamlit_app.py" (
    echo Error: streamlit_app.py not found!
    echo Please make sure you're in the correct project directory
    pause
    exit /b 1
)

:: Check if virtual environment exists, if not create it
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo Error: Failed to activate virtual environment
    pause
    exit /b 1
)

:: Install/update dependencies
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Warning: Some dependencies might not have installed correctly
)

:: Check if API server is running
echo.
echo Checking API server status...
python -c "import requests; requests.get('http://localhost:8000/health', timeout=5)" >nul 2>&1
if errorlevel 1 (
    echo.
    echo ========================================
    echo   WARNING: API Server Not Running!
    echo ========================================
    echo.
    echo The API server is not running at http://localhost:8000
    echo Please start the API server first by running: start.bat
    echo.
    echo The frontend will still start, but you won't be able to
    echo use the authentication features until the API is running.
    echo.
    pause
) else (
    echo API server is running and accessible!
)

echo.
echo ========================================
echo   Starting Streamlit Frontend...
echo ========================================
echo.
echo Frontend URL: http://localhost:8501
echo API URL: http://localhost:8000
echo.
echo Press Ctrl+C to stop the frontend
echo.

:: Start Streamlit
python run_frontend.py

echo.
echo Frontend stopped.
pause