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
set ABUSE_API_KEY=0270e4ecd73216ecf81f5c974b2bec2efcbf2ef83310af4309a3985b73aaf0809830b8c3ebb3a80c

echo Setup complete!
echo To run the app, use: python app.py
echo Make sure to set your API keys in the environment variables.

pause
