@echo off
REM This script sets up a Python virtual environment, installs required packages, and runs the network sniffer.
REM Make sure to run this script in a command prompt with administrative privileges.
REM untested on windows environment
REM Check if Python is installed
REM cd \path\to\network_sniffer
REM setup.bat
REM Step 1: create virtual environment
IF NOT EXIST "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Step 2: activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Step 3: install required packages
echo Installing required packages...
pip install --upgrade pip
pip install -r requirements.txt
echo Setup complete.

REM Step 4: Run Sniffer
echo Starting network sniffer...
python network_sniffer.py

REM Step 5: Deactivate virtual environment after use
echo Deactivating virtual environment...
call venv\Scripts\deactivate.bat
echo Virtual environment deactivated.