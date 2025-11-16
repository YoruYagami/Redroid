#!/usr/bin/env python3
"""
Device detection and management functions
"""

import os
import psutil
from colorama import Fore, Style
import redroid.config as config


def detect_emulator():
    """Detect whether Nox, Genymotion, or Android Studio emulator is running.
       When running on Android, this function is bypassed.
    """
    if 'ANDROID_ARGUMENT' in os.environ:
        print(Fore.YELLOW + "⚠️ Running on Android device; emulator detection is disabled." + Style.RESET_ALL)
        config.emulator_type = None
        config.emulator_installation_path = None
        return None, None

    for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            name = process.info.get('name')
            cmdline = process.info.get('cmdline', [])
            exe_path = process.info.get('exe', '')
            if not exe_path:
                continue
            # Linux naming conventions
            if name and 'nox' in name.lower():
                config.emulator_type = 'Nox'
                config.emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and 'player' in name.lower() and any('genymotion' in arg.lower() for arg in cmdline):
                config.emulator_type = 'Genymotion'
                config.emulator_installation_path = os.path.dirname(exe_path)
                break
            elif name and ("emulator" in name.lower() or "qemu-system" in name.lower()):
                config.emulator_type = 'AndroidStudio'
                config.emulator_installation_path = os.path.dirname(exe_path)
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return config.emulator_type, config.emulator_installation_path


def switch_device():
    """Switch to a different connected device."""
    from redroid.core.adb import get_connected_devices

    if config.adb_command is None:
        print(Fore.RED + "❌ ADB command not available." + Style.RESET_ALL)
        return False

    devices = get_connected_devices(config.adb_command)
    if len(devices) <= 1:
        print(Fore.YELLOW + "⚠️ Only one or no devices connected. Cannot switch." + Style.RESET_ALL)
        return False

    print(Fore.CYAN + "\n🔄 Available devices:" + Style.RESET_ALL)
    for idx, dev in enumerate(devices, 1):
        current_indicator = " (current)" if dev == config.device_serial else ""
        print(f"{idx}. {dev}{current_indicator}")

    try:
        choice = input(Fore.CYAN + "Select device number to switch to: " + Style.RESET_ALL).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            new_device = devices[int(choice) - 1]
            if new_device != config.device_serial:
                config.device_serial = new_device
                print(Fore.GREEN + f"✅ Switched to device: {config.device_serial}" + Style.RESET_ALL)
                return True
            else:
                print(Fore.YELLOW + "⚠️ Already connected to this device." + Style.RESET_ALL)
                return False
        else:
            print(Fore.RED + "❌ Invalid choice." + Style.RESET_ALL)
            return False
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n⚠️ Device switch cancelled." + Style.RESET_ALL)
        return False
