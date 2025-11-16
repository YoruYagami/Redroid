#!/usr/bin/env python3
"""
Global configuration and shared variables for Redroid
"""

import os
import sys
import warnings
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Suppress warnings
warnings.filterwarnings("ignore")

# Version
VERSION = "1.0.0-linux"

# Global variables
emulator_type = None
emulator_installation_path = None
adb_command = None
device_serial = None
target_app = None
switch_device_requested = False
