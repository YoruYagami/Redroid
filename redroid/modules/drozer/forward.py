#!/usr/bin/env python3
"""
Drozer Port Forwarding
"""

from colorama import Fore, Style
import redroid.config as config
from redroid.core.adb import run_adb_command

def start_drozer_forwarding():
    # global adb_command, config.device_serial
    if config.adb_command is None or not config.device_serial:
        print(Fore.RED + "❌ ADB command unavailable or no device selected. Cannot forward Drozer port." + Style.RESET_ALL)
        return
    result = run_adb_command("forward tcp:31415 tcp:31415")
    if result and result.returncode == 0:
        print(Fore.GREEN + "✅ ADB forward set up: 31415 -> 31415" + Style.RESET_ALL)
    else:
        print(Fore.RED + "❌ Failed to set up port forwarding. Check adb logs for details." + Style.RESET_ALL)


