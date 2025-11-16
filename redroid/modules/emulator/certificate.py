#!/usr/bin/env python3
"""
Certificate management
"""

import os
from colorama import Fore, Style
import redroid.config as config
from redroid.core.utils import try_download_certificate

def install_burpsuite_certificate(port):
    """Install the Burp Suite certificate onto the device using the provided IP and port."""
    ip = input(Fore.CYAN + "📝 Enter the IP (e.g., 127.0.0.1): " + Style.RESET_ALL).strip()
    if not ip:
        print(Fore.RED + "❌ Invalid IP." + Style.RESET_ALL)
        return
    print(Fore.CYAN + f"🔍 Attempting to download the certificate from {ip}:{port}..." + Style.RESET_ALL)
    if try_download_certificate(ip, port):
        print(Fore.GREEN + "✅ Certificate installation completed." + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Certificate installation failed." + Style.RESET_ALL)


