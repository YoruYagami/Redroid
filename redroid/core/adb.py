#!/usr/bin/env python3
"""
ADB command functions
"""

import os
import subprocess
from colorama import Fore, Style
import redroid.config as config


def connect_nox_adb_ports(adb_cmd):
    """
    Automatically attempt to connect the local ADB to Nox
    on localhost ports [62001, 62025, 62026].
    """
    ip = '127.0.0.1'
    ports = [62001, 62025, 62026]
    for port in ports:
        cmd = f'{adb_cmd} connect {ip}:{port}'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(Fore.GREEN + f"✅ Attempted adb connect to {ip}:{port}. Output:" + Style.RESET_ALL)
                print(Fore.GREEN + result.stdout.strip() + Style.RESET_ALL)
            else:
                print(Fore.YELLOW + f"⚠️ Could not connect to {ip}:{port}. Error:" + Style.RESET_ALL)
                print(Fore.YELLOW + result.stderr.strip() + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"❌ Exception connecting to Nox at {ip}:{port}: {str(e)}" + Style.RESET_ALL)


def get_adb_command(emulator_type, emulator_installation_path):
    """Return the adb command path based on the emulator type.
       On Android, return None. On Linux, assume adb is in PATH.
    """
    if os.environ.get('ANDROID_ARGUMENT'):
        return None

    # On Linux, just use 'adb' from PATH
    return 'adb'


def get_connected_devices(adb_command):
    """Retrieve a list of connected devices via adb. Returns an empty list on Android."""
    if adb_command is None:
        return []
    try:
        result = subprocess.run(f'{adb_command} devices', shell=True, capture_output=True, text=True, check=True)
        devices = []
        for line in result.stdout.strip().split('\n')[1:]:
            if line.strip():
                device_serial = line.split()[0]
                devices.append(device_serial)
        return devices
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"❌ Error executing adb: {e}" + Style.RESET_ALL)
        return []


def run_adb_command(command):
    """Run an ADB command on the selected device."""
    if config.adb_command is None or not config.device_serial:
        print(Fore.RED + "❌ ADB command not available or no device selected." + Style.RESET_ALL)
        return None

    full_command = f'{config.adb_command} -s {config.device_serial} {command}'
    try:
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True)
        return result
    except Exception as e:
        print(Fore.RED + f"❌ Error running adb command: {e}" + Style.RESET_ALL)
        return None
