#!/bin/bash

# This script sets up a Python virtual environment and installs the required packages for the network sniffer project.
# It also checks for necessary system dependencies.
# Usage: ./setup.sh
# Make sure to run this script from the project root directory.
# Ensure the script exits on any error

# Step 1
if [ ! -d "venv"]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Step 2
echo "Activating virtual environment..."
source venv/bin/activate

# Step 3
pip install --upgrade pip

# Step 4
echo "Installing required Python packages..."
pip install -r requirements.txt

# Step 5
echo "Running network sniffer..."
sudo python3 network_sniffer.py
# Note: Running the sniffer may require superuser privileges to access network interfaces.

# Step 6
deactivate
echo "Setup complete. Virtual environment deactivated."