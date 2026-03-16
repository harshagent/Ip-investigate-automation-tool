@echo off
echo Setting up IP Investigate Tool on Windows...

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Please install Python 3.7+ from https://www.python.org/
    pause
    exit /b 1
)

REM Install virtual environment if not exists
if not exist venv (
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
pip install -r requirements.txt

REM Set environment variables (replace with your actual keys)
set VT_API_KEY=88f9247c42b4f29d3997429c1ef5c7817e8068becfcb4e171855e0150da49b04
set ABUSE_API_KEY=794d7459b26d13fcc134a2d1a0f5ce9d27d4a34b2b95b78257b1589e31cf6249accc59bfe3128ebf

echo Setup complete!
echo To run the app, use: python app.py
echo Make sure to set your API keys in the environment variables.

pause
